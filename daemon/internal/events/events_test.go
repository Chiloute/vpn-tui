package events

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Chiloute/vpn-tui/proto"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const base = "https://github.com/Chiloute/vpn-tui/proto/rpc.schema.json"

func TestBus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "j.jsonl")
	b := NewBus(path)
	slow, unsubSlow := b.Subscribe() // never drained
	fast, unsub := b.Subscribe()
	for i := 0; i < 200; i++ { // would deadlock if Publish blocked
		b.Publish(Event{Profile: "p", State: "armed", Kind: "up"})
	}
	b.Publish(Event{State: "disarmed", Kind: "down", Detail: "é"})
	if len(slow) != 64 || len(fast) != 64 {
		t.Fatalf("buffers %d %d", len(slow), len(fast))
	}
	unsub()
	unsub() // idempotent
	if _, ok := <-drain(fast); ok {
		t.Fatal("channel should be closed")
	}
	unsubSlow()
	b.Publish(Event{State: "locked", Kind: "lock"})

	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(proto.Schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(base, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(base + "#/$defs/event")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode())
	}
	f, _ := os.Open(path)
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var v any
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(v); err != nil {
			t.Fatalf("%s: %v", sc.Text(), err)
		}
		n++
	}
	if n != 202 {
		t.Fatalf("lines %d", n)
	}
}

func drain(c <-chan Event) <-chan Event {
	for len(c) > 0 {
		<-c
	}
	return c
}
