package rpc

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
)

type mortalTun struct {
	dead chan struct{}
	once sync.Once
}

func (m *mortalTun) Down() error             { m.once.Do(func() { close(m.dead) }); return nil }
func (m *mortalTun) Dead() <-chan struct{}   { return m.dead }
func (m *mortalTun) Stats() (uint64, uint64) { return 0, 0 }

type mortalDriver struct {
	mu   sync.Mutex
	last *mortalTun
	fail bool
}

func (*mortalDriver) Endpoints(context.Context, *profile.Profile) ([]state.Endpoint, error) {
	return []state.Endpoint{{IP: netip.MustParseAddr("192.0.2.1"), Port: 51820, Proto: "udp"}}, nil
}

func (d *mortalDriver) Up(context.Context, *profile.Profile, state.Secrets, []state.Endpoint) (state.Tunnel, state.Info, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return nil, state.Info{}, context.DeadlineExceeded
	}
	d.last = &mortalTun{dead: make(chan struct{})}
	return d.last, state.Info{Iface: "vpntui0"}, nil
}

func TestPanicOffLogsReconnecting(t *testing.T) {
	root, run := t.TempDir(), t.TempDir()
	st := &profile.Store{Root: root}
	st.Init()
	if _, err := st.Import("wireguard", "wg", "wg1", rd(t, "../wg/testdata/client.conf")); err != nil {
		t.Fatal(err)
	}
	d := &mortalDriver{}
	mgr := &state.Manager{Drivers: map[string]state.Driver{"wireguard": d}, FW: state.NoopFirewall{},
		Bus: events.NewBus(filepath.Join(run, "events.jsonl")), StatePath: filepath.Join(run, "state.json")}
	mgr.Reconnect.MaxAttempts = 3
	mgr.Sleep = func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }
	s, _ := New()
	s.Member, s.IdleTimeout, s.ReadTimeout, s.Store, s.Mgr = allow, time.Minute, 5*time.Second, st, mgr
	path := serve(t, s)

	if m := req(t, path, "up", map[string]any{"id": "wg1", "secrets": map[string]any{"private_key": key("K")}}); code(m) != 0 {
		t.Fatalf("up: %v", m)
	}
	d.mu.Lock()
	d.fail = true
	d.last.Down() // simulates a drop
	d.mu.Unlock()
	var r map[string]any
	for i := 0; i < 200; i++ {
		m := req(t, path, "status", map[string]any{})
		validate(t, m, "result_status")
		if r = m["result"].(map[string]any); r["state"] == "reconnecting" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if rc := r["reconnect"].(map[string]any); r["state"] != "reconnecting" || rc["attempt"] != 1.0 || rc["max"] != 3.0 {
		t.Fatalf("%v", r)
	}

	m := req(t, path, "logs", map[string]any{"since": "2000-01-01T00:00:00Z"})
	validate(t, m, "result_logs")
	if evs := m["result"].(map[string]any)["events"].([]any); len(evs) < 3 {
		t.Fatalf("journal: %v", evs)
	}
	m = req(t, path, "logs", map[string]any{"since": "2999-01-01T00:00:00Z"})
	validate(t, m, "result_logs")
	if evs := m["result"].(map[string]any)["events"].([]any); len(evs) != 0 {
		t.Fatalf("%v", evs)
	}

	m = req(t, path, "panic_off", map[string]any{})
	validate(t, m, "result_panic_off")
	if code(m) != 0 {
		t.Fatalf("%v", m)
	}
	if r := req(t, path, "status", map[string]any{})["result"].(map[string]any); r["state"] != "disarmed" {
		t.Fatalf("%v", r)
	}
}
