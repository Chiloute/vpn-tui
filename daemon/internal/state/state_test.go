package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
)

const marker = "S3CR3T-MARKER"

type log struct {
	mu sync.Mutex
	c  []string
}

func (l *log) add(s string) { l.mu.Lock(); l.c = append(l.c, s); l.mu.Unlock() }
func (l *log) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.c...)
}

type fakeFW struct {
	l      *log
	failOn string
}

func ips(s Spec) string {
	var o []string
	for _, e := range s.Endpoints {
		o = append(o, e.IP.String())
	}
	return s.Profile.ID + ":" + strings.Join(o, "+")
}
func (f *fakeFW) call(n, a string) error {
	f.l.add(n + "(" + a + ")")
	if f.failOn == n {
		return errors.New("fw " + n)
	}
	return nil
}
func (f *fakeFW) Lock(s Spec) error { return f.call("Lock", ips(s)) }
func (f *fakeFW) Arm(s Spec) error  { return f.call("Arm", ips(s)+"@"+s.Iface) }
func (f *fakeFW) Disarm() error     { return f.call("Disarm", "") }

type fakeTun struct {
	id   string
	l    *log
	dead chan struct{}
	err  error
}

func (t *fakeTun) Down() error {
	t.l.add(t.id + ".Down")
	if t.err != nil {
		return t.err
	}
	close(t.dead)
	return nil
}
func (t *fakeTun) Dead() <-chan struct{}   { return t.dead }
func (t *fakeTun) Stats() (uint64, uint64) { return 1, 2 }

type fakeDrv struct {
	l       *log
	ip      string
	fail    bool
	learned []netip.Prefix
	last    *fakeTun
}

func (d *fakeDrv) Endpoints(context.Context, *profile.Profile) ([]Endpoint, error) {
	return []Endpoint{{IP: netip.MustParseAddr(d.ip), Port: 1, Proto: "udp"}}, nil
}
func (d *fakeDrv) Up(_ context.Context, p *profile.Profile, s Secrets, _ []Endpoint) (Tunnel, Info, error) {
	if d.fail {
		return nil, Info{}, errors.New("up failed")
	}
	d.last = &fakeTun{id: p.ID, l: d.l, dead: make(chan struct{})}
	return d.last, Info{Iface: "tun-" + p.ID, LHOST: netip.MustParseAddr("10.0.0.2"), Learned: d.learned}, nil
}

func prof(id string, ks bool) *profile.Profile {
	return &profile.Profile{ID: id, Type: "openvpn", Killswitch: profile.Killswitch{Enabled: ks}}
}

type env struct {
	m   *Manager
	l   *log
	fw  *fakeFW
	drv map[string]*fakeDrv
	ch  <-chan events.Event
	dir string
}

func setup(t *testing.T) *env {
	l := &log{}
	dir := t.TempDir()
	e := &env{l: l, fw: &fakeFW{l: l}, dir: dir, drv: map[string]*fakeDrv{}}
	bus := events.NewBus(filepath.Join(dir, "j.jsonl"))
	e.ch, _ = bus.Subscribe()
	d := &fakeDrv{l: l, ip: "1.1.1.1"}
	e.drv["openvpn"] = d
	e.m = &Manager{Drivers: map[string]Driver{"openvpn": d}, FW: e.fw, Bus: bus, StatePath: filepath.Join(dir, "state.json")}
	return e
}

// ipFor makes endpoints differ per profile in switch tests.
type perProfileDrv struct{ *fakeDrv }

func (d perProfileDrv) Endpoints(_ context.Context, p *profile.Profile) ([]Endpoint, error) {
	ip := map[string]string{"a": "1.1.1.1", "b": "2.2.2.2"}[p.ID]
	return []Endpoint{{IP: netip.MustParseAddr(ip), Port: 1, Proto: "udp"}}, nil
}

func kinds(ch <-chan events.Event) []string {
	var k []string
	for len(ch) > 0 {
		e := <-ch
		k = append(k, e.Kind)
	}
	return k
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestUpSimple(t *testing.T) {
	e := setup(t)
	e.drv["openvpn"].learned = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16"), netip.MustParsePrefix("10.2.0.0/24")}
	sec := Secrets{Password: marker, PrivateKey: marker}
	if err := e.m.Up(context.Background(), prof("a", true), sec); err != nil {
		t.Fatal(err)
	}
	eq(t, e.l.get(), []string{"Lock(a:1.1.1.1)", "Arm(a:1.1.1.1@tun-a)"})
	st := e.m.Status()
	if st.State != Armed || !st.Killswitch || st.Iface != "tun-a" || st.LHOST != "10.0.0.2" || st.Rx != 1 || !e.m.Active() {
		t.Fatalf("%+v", st)
	}
	eq(t, kinds(e.ch), []string{"up", "scope_learned"})
	if err := e.m.Up(context.Background(), prof("a", true), sec); !errors.Is(err, ErrAlreadyActive) {
		t.Fatal(err)
	}
	p, err := Load(e.m.StatePath)
	if err != nil || p.State != Armed || p.Profile != "a" || p.Iface != "tun-a" {
		t.Fatalf("%+v %v", p, err)
	}
	if fi, _ := os.Stat(e.m.StatePath); fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	for _, f := range []string{e.m.StatePath, filepath.Join(e.dir, "j.jsonl")} {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), marker) {
			t.Fatalf("secret leaked in %s", f)
		}
	}
	if fmt.Sprintf("%v %+v", sec, sec) != "[redacted] [redacted]" {
		t.Fatal("secrets printable")
	}
}

func TestSwitch(t *testing.T) {
	e := setup(t)
	e.m.Drivers["openvpn"] = perProfileDrv{e.drv["openvpn"]}
	ctx := context.Background()
	if err := e.m.Up(ctx, prof("a", true), Secrets{}); err != nil {
		t.Fatal(err)
	}
	e.l.c = nil
	if err := e.m.Up(ctx, prof("b", true), Secrets{}); err != nil {
		t.Fatal(err)
	}
	eq(t, e.l.get(), []string{"Lock(a:1.1.1.1+2.2.2.2)", "a.Down", "Lock(b:2.2.2.2)", "Arm(b:2.2.2.2@tun-b)"})
	if st := e.m.Status(); st.Profile != "b" || st.State != Armed {
		t.Fatalf("%+v", st)
	}
	time.Sleep(20 * time.Millisecond) // A's watcher must not report a drop
	eq(t, kinds(e.ch), []string{"up", "up"})
}

func TestUpFailure(t *testing.T) {
	e := setup(t)
	e.drv["openvpn"].fail = true
	if err := e.m.Up(context.Background(), prof("a", true), Secrets{}); err == nil {
		t.Fatal("want error")
	}
	eq(t, e.l.get(), []string{"Lock(a:1.1.1.1)"})
	if st := e.m.Status(); st.State != Locked || st.Profile != "a" {
		t.Fatalf("%+v", st)
	}
	eq(t, kinds(e.ch), []string{"error"})

	// without kill switch: Disarm, never locked
	e = setup(t)
	e.drv["openvpn"].fail = true
	_ = e.m.Up(context.Background(), prof("a", false), Secrets{})
	eq(t, e.l.get(), []string{"Disarm()"})
	if e.m.Status().State != Disarmed || e.m.Active() {
		t.Fatal("want disarmed")
	}
}

func TestFirewallErrors(t *testing.T) {
	for _, on := range []string{"Lock", "Arm"} {
		e := setup(t)
		e.fw.failOn = on
		if err := e.m.Up(context.Background(), prof("a", true), Secrets{}); err == nil {
			t.Fatal("want error")
		}
		if e.m.Status().State != Locked {
			t.Fatalf("%s: %+v", on, e.m.Status())
		}
		for _, c := range e.l.get() {
			if c == "Disarm()" {
				t.Fatal("disarmed on error")
			}
		}
	}
}

func TestDrop(t *testing.T) {
	e := setup(t)
	if err := e.m.Up(context.Background(), prof("a", true), Secrets{}); err != nil {
		t.Fatal(err)
	}
	e.l.c = nil
	close(e.drv["openvpn"].last.dead)
	deadline := time.Now().Add(2 * time.Second)
	for e.m.Status().State != Locked && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	eq(t, e.l.get(), []string{"Lock(a:1.1.1.1)"})
	eq(t, kinds(e.ch), []string{"up", "drop"})
}

func TestDown(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if err := e.m.Up(ctx, prof("a", true), Secrets{}); err != nil {
		t.Fatal(err)
	}
	e.l.c = nil
	e.drv["openvpn"].last.err = errors.New("boom")
	if err := e.m.Down(); err == nil || e.m.Status().State != Locked {
		t.Fatal("down failure must stay locked")
	}
	e.drv["openvpn"].last.err = nil
	if err := e.m.Down(); err != nil {
		t.Fatal(err)
	}
	eq(t, e.l.get(), []string{"a.Down", "a.Down", "Disarm()"})
	if e.m.Status().State != Disarmed || e.m.Active() {
		t.Fatal("want disarmed")
	}
	eq(t, kinds(e.ch), []string{"up", "error", "down"})
}

func TestNoKillswitch(t *testing.T) {
	e := setup(t)
	if err := e.m.Up(context.Background(), prof("a", false), Secrets{}); err != nil {
		t.Fatal(err)
	}
	eq(t, e.l.get(), nil)
	if st := e.m.Status(); st.State != Armed || st.Killswitch {
		t.Fatalf("%+v", st)
	}
}
