package events

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPurgeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	b := NewBus(path)
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	b.Publish(Event{Time: now.Add(-8 * day), Kind: "old"})
	b.Publish(Event{Time: now.Add(-6 * day), Kind: "new"})
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("garbage\n")
	f.Close()
	os.Chmod(path, 0o640)

	got, _ := b.Read(now.Add(-10*day), 0)
	if len(got) != 2 {
		t.Fatalf("read %d", len(got))
	}
	if got, _ = b.Read(now.Add(-10*day), 1); len(got) != 1 || got[0].Kind != "new" {
		t.Fatalf("limit %v", got)
	}
	if got, _ = b.Read(now.Add(-7*day), 0); len(got) != 1 {
		t.Fatalf("since %v", got)
	}
	n, err := b.Purge(7*day, now)
	if err != nil || n != 1 {
		t.Fatalf("purge %d %v", n, err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "old") || !strings.Contains(string(data), "garbage") || !strings.Contains(string(data), "new") {
		t.Fatalf("content %s", data)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode())
	}
	if n, err := NewBus("").Purge(day, now); n != 0 || err != nil {
		t.Fatal("noop")
	}
}

func TestPurgeConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	b := NewBus(path)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			b.Publish(Event{Kind: "x"})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			b.Purge(time.Hour, time.Now())
		}
	}()
	wg.Wait()
	got, err := b.Read(time.Time{}, 10000)
	if err != nil || len(got) != 300 {
		t.Fatalf("got %d %v", len(got), err)
	}
}

func TestRunPurgeStops(t *testing.T) {
	b := NewBus(filepath.Join(t.TempDir(), "j.jsonl"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.RunPurge(ctx, time.Hour, 10*time.Millisecond); close(done) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("not stopped")
	}
}
