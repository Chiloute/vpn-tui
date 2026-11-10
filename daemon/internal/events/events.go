// Package events broadcasts daemon events and appends them to a jsonl journal.
package events

import (
	"encoding/json"
	"os"
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
