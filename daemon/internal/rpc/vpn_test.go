package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/Chiloute/vpn-tui/proto"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type fakeTun struct{ dead chan struct{} }

func (f fakeTun) Down() error             { close(f.dead); return nil }
func (f fakeTun) Dead() <-chan struct{}   { return f.dead }
func (f fakeTun) Stats() (uint64, uint64) { return 7, 9 }

type fakeDriver struct{ fail atomic.Bool }

func (*fakeDriver) Endpoints(context.Context, *profile.Profile) ([]state.Endpoint, error) {
	return []state.Endpoint{{IP: netip.MustParseAddr("192.0.2.1"), Port: 51820, Proto: "udp"}}, nil
}

func (f *fakeDriver) Up(context.Context, *profile.Profile, state.Secrets, []state.Endpoint) (state.Tunnel, state.Info, error) {
	if f.fail.Load() {
		return nil, state.Info{}, errors.New("handshake impossible")
	}
	return fakeTun{make(chan struct{})}, state.Info{Iface: "vpntui0", LHOST: netip.MustParseAddr("10.9.0.2"),
		Learned: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}}, nil
}

type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func TestVPNMethods(t *testing.T) {
	logs := &lockedBuf{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	root, run := t.TempDir(), t.TempDir()
	st := &profile.Store{Root: root}
	st.Init()
	if _, err := st.Import("wireguard", "wg", "wg1", rd(t, "../wg/testdata/client.conf")); err != nil {
		t.Fatal(err)
	}
	fd := &fakeDriver{}
	mgr := &state.Manager{Drivers: map[string]state.Driver{"wireguard": fd}, FW: state.NoopFirewall{},
		Bus: events.NewBus(filepath.Join(run, "events.jsonl")), StatePath: filepath.Join(run, "state.json")}
	s, _ := New()
	s.Member, s.IdleTimeout, s.ReadTimeout, s.Store, s.Mgr = allow, time.Minute, 5*time.Second, st, mgr
	s.Busy = mgr.Active
	path := serve(t, s)

	// subscriber
	sub, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	sub.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"events_subscribe"}` + "\n"))
	r := bufio.NewReader(sub)
	next := func() map[string]any {
		t.Helper()
		sub.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := r.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		json.Unmarshal(line, &m)
		return m
	}
	if m := next(); m["result"] == nil {
		t.Fatalf("ack: %v", m)
	}

	status := func() map[string]any {
		m := req(t, path, "status", map[string]any{})
		validate(t, m, "result_status")
		return m["result"].(map[string]any)
	}
	if r := status(); r["state"] != "disarmed" || r["profile"] != nil || r["lhost"] != nil {
		t.Fatalf("%v", r)
	}

	// errors
	if m := req(t, path, "up", map[string]any{"id": "wg1"}); code(m) != CodeInvalidPar {
		t.Errorf("sans secrets: %v", m)
	}
	if m := req(t, path, "up", map[string]any{"id": "nope", "secrets": map[string]any{"private_key": key("X")}}); code(m) != CodeNotFound {
		t.Errorf("inconnu: %v", m)
	}
	if m := req(t, path, "up", map[string]any{"id": 1}); code(m) != CodeInvalidPar {
		t.Errorf("params invalides: %v", m)
	}
	if m, _ := call(t, path, `{"jsonrpc":"2.0","id":1,"method":"up"}`); code(m) != CodeInvalidPar {
		t.Errorf("params absents: %v", m)
	}
	if m := req(t, path, "scope_learn_accept", map[string]any{"id": "wg1", "cidrs": []string{"10.1.0.1/24"}}); code(m) != CodeInvalidPar {
		t.Errorf("cidr non canonique: %v", m)
	}

	// up / events / status armed
	pw := key("MARKERSECRET")
	if m := req(t, path, "up", map[string]any{"id": "wg1", "secrets": map[string]any{"private_key": pw}}); code(m) != 0 {
		t.Fatalf("up: %v", m)
	}
	for _, kind := range []string{"up", "scope_learned"} {
		m := next()
		if err := evSchema(t).Validate(m); err != nil {
			t.Fatal(err)
		}
		if m["method"] != "event" || m["params"].(map[string]any)["kind"] != kind {
			t.Fatalf("want %s, got %v", kind, m)
		}
	}
	if r := status(); r["state"] != "armed" || r["lhost"] != "10.9.0.2" || r["interface"] != "vpntui0" || r["profile"] != "wg1" || r["rx_bytes"] != 7.0 {
		t.Fatalf("%v", r)
	}
	if m := req(t, path, "up", map[string]any{"id": "wg1", "secrets": map[string]any{"private_key": pw}}); code(m) != CodeBusy {
		t.Errorf("déjà actif: %v", m)
	}

	// scope_learn_accept
	m := req(t, path, "scope_learn_accept", map[string]any{"id": "wg1", "cidrs": []string{"10.1.0.0/24"}})
	validate(t, m, "profile")
	if sc := m["result"].(map[string]any)["scope"].(map[string]any); len(sc["cidrs"].([]any)) != 1 || len(sc["learned"].([]any)) != 1 {
		t.Fatalf("%v", sc)
	}
	if r := status(); len(r["scope"].([]any)) != 1 {
		t.Fatalf("scope: %v", r)
	}

	// down
	if m := req(t, path, "down", map[string]any{}); code(m) != 0 {
		t.Fatalf("down: %v", m)
	}
	if e := next(); e["params"].(map[string]any)["kind"] != "down" {
		t.Fatalf("%v", e)
	}
	if r := status(); r["state"] != "disarmed" {
		t.Fatalf("%v", r)
	}

	// failed connection: clear error, locked (kill switch on), schema-conformant status
	fd.fail.Store(true)
	m = req(t, path, "up", map[string]any{"id": "wg1", "secrets": map[string]any{"private_key": pw}})
	if e, _ := m["error"].(map[string]any); e == nil || !strings.Contains(e["message"].(string), "échec de la connexion") {
		t.Fatalf("%v", m)
	}
	if r := status(); r["state"] != "locked" {
		t.Fatalf("%v", r)
	}

	// no secret anywhere
	files := logs.String() + rd(t, filepath.Join(run, "state.json")) + rd(t, filepath.Join(run, "events.jsonl"))
	if strings.Contains(files, "MARKERSECRET") {
		t.Fatal("secret divulgué dans les logs / state.json / events.jsonl")
	}

	// subscriber ends cleanly when the client closes
	sub.Close()
}

// key builds a schema-valid WireGuard key containing marker.
func key(marker string) string {
	return strings.Repeat("A", 43-len(marker)) + marker + "="
}

func evSchema(t *testing.T) *jsonschema.Schema {
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(proto.Schema))
	c := jsonschema.NewCompiler()
	c.AddResource(schemaBase, doc)
	sch, err := c.Compile(schemaBase + "#/$defs/event_notification")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}
