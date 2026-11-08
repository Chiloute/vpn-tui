package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/proto"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func start(t *testing.T, member func(uint32) (bool, error), idle time.Duration) (string, chan error) {
	t.Helper()
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	s.Member, s.IdleTimeout, s.ReadTimeout = member, idle, 5*time.Second
	return serve2(t, s)
}

func serve(t *testing.T, s *Server) string {
	p, _ := serve2(t, s)
	return p
}

func serve2(t *testing.T, s *Server) (string, chan error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	return path, done
}

func allow(uint32) (bool, error) { return true, nil }

// call sends raw (plus newline) and returns the decoded first reply.
func call(t *testing.T, path, raw string) (map[string]any, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go c.Write([]byte(raw + "\n"))
	r := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatal(err)
	}
	return m, r
}

func code(m map[string]any) int {
	e, _ := m["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return int(c)
}

func TestStatus(t *testing.T) {
	u, _ := user.Current()
	g, _ := user.LookupGroupId(u.Gid)
	path, _ := start(t, GroupMember(g.Name), time.Minute)
	m, _ := call(t, path, `{"jsonrpc":"2.0","id":1,"method":"status"}`)

	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(proto.Schema))
	c := jsonschema.NewCompiler()
	c.AddResource(schemaBase, doc)
	for _, def := range []string{"response", "result_status"} {
		sch, err := c.Compile(schemaBase + "#/$defs/" + def)
		if err != nil {
			t.Fatal(err)
		}
		var v any = m
		if def == "result_status" {
			v = m["result"]
		}
		if err := sch.Validate(v); err != nil {
			t.Errorf("%s: %v", def, err)
		}
	}
}

func TestForbidden(t *testing.T) {
	path, _ := start(t, func(uint32) (bool, error) { return false, nil }, time.Minute)
	m, r := call(t, path, `{"jsonrpc":"2.0","id":1,"method":"status"}`)
	if code(m) != CodeForbidden {
		t.Fatalf("got %v", m)
	}
	if _, err := r.ReadBytes('\n'); err == nil {
		t.Fatal("connection not closed")
	}
}

func TestErrors(t *testing.T) {
	path, _ := start(t, allow, time.Minute)
	for _, c := range []struct {
		name, msg string
		want      int
	}{
		{"too large", `{"jsonrpc":"2.0","id":1,"method":"status","x":"` + strings.Repeat("a", 70000) + `"}`, CodeTooLarge},
		{"bad json", `{nope`, CodeParse},
		{"unknown field", `{"jsonrpc":"2.0","id":1,"method":"status","x":1}`, CodeInvalidReq},
		{"bad params", `{"jsonrpc":"2.0","id":1,"method":"status","params":{"a":1}}`, CodeInvalidPar},
		{"not implemented", `{"jsonrpc":"2.0","id":1,"method":"down"}`, CodeNotImplemen},
	} {
		if m, _ := call(t, path, c.msg); code(m) != c.want {
			t.Errorf("%s: got %v want %d", c.name, m, c.want)
		}
	}
}

func TestIdleShutdown(t *testing.T) {
	_, done := start(t, allow, 100*time.Millisecond)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no idle shutdown")
	}
}
