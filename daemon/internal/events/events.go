// Package events broadcasts daemon events and appends them to a jsonl journal.
package events

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"
)

const maxDetail = 1024

// Event matches $defs/event of the RPC schema.
type Event struct {
	Time    time.Time `json:"time"`
	Profile string    `json:"profile"` // "" is serialized as null
	State   string    `json:"state"`
	Kind    string    `json:"kind"`
	Detail  string    `json:"detail"`
}

func (e Event) MarshalJSON() ([]byte, error) {
	var p *string
	if e.Profile != "" {
		p = &e.Profile
	}
	return json.Marshal(struct {
		Time    time.Time `json:"time"`
		Profile *string   `json:"profile"`
		State   string    `json:"state"`
		Kind    string    `json:"kind"`
		Detail  string    `json:"detail"`
	}{e.Time, p, e.State, e.Kind, e.Detail})
}

func (e *Event) UnmarshalJSON(b []byte) error {
	var v struct {
		Time    time.Time `json:"time"`
		Profile *string   `json:"profile"`
		State   string    `json:"state"`
		Kind    string    `json:"kind"`
		Detail  string    `json:"detail"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*e = Event{Time: v.Time, State: v.State, Kind: v.Kind, Detail: v.Detail}
	if v.Profile != nil {
		e.Profile = *v.Profile
	}
	return nil
}

type Bus struct {
	path string
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

// NewBus: journalPath "" disables the journal.
func NewBus(journalPath string) *Bus {
	return &Bus{path: journalPath, subs: map[chan Event]struct{}{}}
}

// Publish never blocks: a slow subscriber loses the event.
func (b *Bus) Publish(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	if len(e.Detail) > maxDetail {
		d := e.Detail[:maxDetail]
		for !utf8.ValidString(d) {
			d = d[:len(d)-1]
		}
		e.Detail = d
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.path != "" {
		if line, err := json.Marshal(e); err == nil {
			if f, err := os.OpenFile(b.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err == nil {
				f.Write(append(line, '\n'))
				f.Close()
			}
		}
	}
	for c := range b.subs {
		select {
		case c <- e:
		default:
		}
	}
}

func (b *Bus) Subscribe() (<-chan Event, func()) {
	c := make(chan Event, 64)
	b.mu.Lock()
	b.subs[c] = struct{}{}
	b.mu.Unlock()
	return c, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[c]; ok {
			delete(b.subs, c)
			close(c)
		}
	}
}

const maxLine = 1 << 20

// Purge drops journal entries older than maxAge; unparsable lines are kept.
func (b *Bus) Purge(maxAge time.Duration, now time.Time) (removed int, err error) {
	if b.path == "" {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	f, err := os.Open(b.path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	tmp, err := os.CreateTemp(filepath.Dir(b.path), ".journal-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name()) // no-op after successful rename
	defer tmp.Close()
	w := bufio.NewWriter(tmp)
	cut := now.Add(-maxAge)
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, maxLine)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Time.Before(cut) {
			removed++
			continue
		}
		w.Write(sc.Bytes())
		w.WriteByte('\n')
	}
	if err := sc.Err(); err != nil { // never rewrite from a partial read
		return 0, err
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}
	if err := tmp.Chmod(0o640); err != nil {
		return 0, err
	}
	if err := tmp.Sync(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp.Name(), b.path); err != nil {
		return 0, err
	}
	return removed, nil
}

// Read returns the last `limit` entries with Time >= since, oldest first.
func (b *Bus) Read(since time.Time, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 1000
	}
	if b.path == "" {
		return nil, nil
	}
	b.mu.Lock()
	f, err := os.Open(b.path)
	b.mu.Unlock()
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, maxLine)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && !e.Time.Before(since) {
			out = append(out, e)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, sc.Err()
}

// RunPurge purges now, then every `every`, until ctx is done.
func (b *Bus) RunPurge(ctx context.Context, maxAge, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := b.Purge(maxAge, time.Now()); err != nil {
			slog.Warn("events purge", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
