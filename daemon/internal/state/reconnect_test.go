package state

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/health"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/proto"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type tun2 struct {
	dead  chan struct{}
	once  sync.Once
	block chan struct{} // when non-nil, Down never returns until closed
}

func newTun() *tun2 { return &tun2{dead: make(chan struct{})} }
func (t *tun2) Down() error {
	if t.block != nil {
		<-t.block
	}
	t.once.Do(func() { close(t.dead) })
	return nil
}
func (t *tun2) Dead() <-chan struct{}   { return t.dead }
func (t *tun2) Stats() (uint64, uint64) { return 0, 0 }

// scriptDrv fails the first `failures` Up calls; it also implements Adopter.
type scriptDrv struct {
	mu       sync.Mutex
	failures int
	ups      atomic.Int32
	tuns     []*tun2
	adoptErr error
	noEps    bool
	block    chan struct{}
}

func (d *scriptDrv) Endpoints(_ context.Context, p *profile.Profile) ([]Endpoint, error) {
	return []Endpoint{{IP: netip.MustParseAddr("1.1.1.1"), Port: 1, Proto: "udp"}}, nil
}
func (d *scriptDrv) Up(_ context.Context, p *profile.Profile, s Secrets, _ []Endpoint) (Tunnel, Info, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ups.Add(1)
	if len(d.tuns) > 0 || d.ups.Load() > 1 { // first Up is the initial one in most tests; see failAfterFirst
		if d.failures > 0 {
			d.failures--
			return nil, Info{}, errors.New("up failed")
		}
	}
	t := newTun()
	t.block = d.block
	d.tuns = append(d.tuns, t)
	return t, Info{Iface: "tun-" + p.ID, LHOST: netip.MustParseAddr("10.0.0.2")}, nil
}
func (d *scriptDrv) Adopt(_ context.Context, p *profile.Profile, iface string, pid int) (Tunnel, Info, error) {
	if d.adoptErr != nil {
		return nil, Info{}, d.adoptErr
	}
	t := newTun()
	d.mu.Lock()
	d.tuns = append(d.tuns, t)
	d.mu.Unlock()
	return t, Info{Iface: iface, PID: pid}, nil
}
func (d *scriptDrv) last() *tun2 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tuns[len(d.tuns)-1]
}

type rig struct {
	m      *Manager
	fw     *fakeFW
	l      *log
	d      *scriptDrv
	ch     <-chan events.Event
	dir    string
	delays []time.Duration
	atts   []int
	dmu    sync.Mutex
}

// validJournal checks every journaled event against $defs/event of the RPC schema.
func validJournal(t *testing.T, dir string) {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(proto.Schema))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	const base = "https://github.com/Chiloute/vpn-tui/proto/rpc.schema.json"
	if err := c.AddResource(base, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(base + "#/$defs/event")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "j.jsonl"))
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		v, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
		if err != nil {
			t.Fatal(err)
		}
		if err := sch.Validate(v); err != nil {
			t.Fatalf("invalid event %s: %v", line, err)
		}
		n++
	}
	if n == 0 {
		t.Fatal("empty journal")
	}
}

func newRig(t *testing.T, max int) *rig {
	t.Helper()
	l := &log{}
	r := &rig{l: l, fw: &fakeFW{l: l}, d: &scriptDrv{}, dir: t.TempDir()}
	bus := events.NewBus(filepath.Join(r.dir, "j.jsonl"))
	r.ch, _ = bus.Subscribe()
	r.m = &Manager{
		Drivers: map[string]Driver{"openvpn": r.d, "wireguard": r.d}, FW: r.fw, Bus: bus,
		StatePath: filepath.Join(r.dir, "state.json"), MarkerPath: filepath.Join(r.dir, "armed.json"),
		PanicTimeout: 100 * time.Millisecond,
	}
	r.m.Reconnect.MaxAttempts = max
	r.m.Reconnect.Backoff = health.Backoff{Initial: time.Second, Max: 4 * time.Second}
	r.m.Sleep = func(ctx context.Context, d time.Duration) error {
		r.dmu.Lock()
		r.delays = append(r.delays, d)
		r.atts = append(r.atts, r.m.Status().Attempt)
		r.dmu.Unlock()
		return ctx.Err()
	}
	return r
}

func wait(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout")
}

func noDisarm(t *testing.T, l *log) {
	t.Helper()
	for _, c := range l.get() {
		if c == "Disarm()" {
			t.Fatal("unexpected Disarm", l.get())
		}
	}
}

func (r *rig) up(t *testing.T, p *profile.Profile) {
	t.Helper()
	if err := r.m.Up(context.Background(), p, Secrets{Password: marker, PrivateKey: marker}); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectSuccess(t *testing.T) {
	r := newRig(t, 5)
	r.up(t, prof("a", true))
	r.d.mu.Lock()
	r.d.failures = 2
	r.d.mu.Unlock()
	close(r.d.last().dead)
	wait(t, func() bool { return r.m.Status().State == Armed && r.d.ups.Load() == 4 && len(r.ch) >= 8 }) // the up event follows the state change
	r.dmu.Lock()
	defer r.dmu.Unlock()
	if len(r.delays) != 3 || r.delays[0] != time.Second || r.delays[1] != 2*time.Second || r.delays[2] != 4*time.Second {
		t.Fatal(r.delays)
	}
	if r.atts[0] != 1 || r.atts[2] != 3 {
		t.Fatal(r.atts)
	}
	eq(t, r.l.get(), []string{"Lock(a:1.1.1.1)", "Arm(a:1.1.1.1@tun-a)", "Lock(a:1.1.1.1)", "Arm(a:1.1.1.1@tun-a)"})
	eq(t, kinds(r.ch), []string{"up", "drop", "reconnect", "error", "reconnect", "error", "reconnect", "up"})
	if _, err := os.Stat(r.m.MarkerPath); err != nil {
		t.Fatal(err)
	}
}

func TestReconnectExhausted(t *testing.T) {
	r := newRig(t, 3)
	r.up(t, prof("a", true))
	r.d.mu.Lock()
	r.d.failures = 100
	r.d.mu.Unlock()
	close(r.d.last().dead)
	wait(t, func() bool { return r.m.Status().State == Locked })
	time.Sleep(30 * time.Millisecond)
	if n := r.d.ups.Load(); n != 4 {
		t.Fatalf("ups %d", n)
	}
	if st := r.m.Status(); st.State != Locked || st.Profile != "a" {
		t.Fatalf("%+v", st)
	}
	if p, _ := Load(r.m.StatePath); p.State != Locked {
		t.Fatal("not durable")
	}
	if _, err := os.Stat(r.m.MarkerPath); err != nil {
		t.Fatal("marker must stay while locked")
	}
	noDisarm(t, r.l)
	ks := kinds(r.ch)
	if ks[len(ks)-1] != "lock" {
		t.Fatal(ks)
	}
	// secrets never leak (state, marker, journal)
	for _, f := range []string{r.m.StatePath, r.m.MarkerPath, filepath.Join(r.dir, "j.jsonl")} {
		b, err := os.ReadFile(f)
		if err != nil || strings.Contains(string(b), marker) {
			t.Fatalf("%s: %v leak", f, err)
		}
	}
	// Down from locked releases everything
	if err := r.m.Down(); err != nil {
		t.Fatal(err)
	}
	if r.m.Status().State != Disarmed {
		t.Fatal("want disarmed")
	}
	if _, err := os.Stat(r.m.MarkerPath); !os.IsNotExist(err) {
		t.Fatal("marker kept")
	}
}

// blockingSleep parks the reconnect loop until its context is cancelled.
func (r *rig) blockingSleep() chan struct{} {
	in := make(chan struct{}, 1)
	r.m.Sleep = func(ctx context.Context, d time.Duration) error {
		select {
		case in <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}
	return in
}

func TestDownDuringLoop(t *testing.T) {
	r := newRig(t, 5)
	in := r.blockingSleep()
	r.up(t, prof("a", true))
	close(r.d.last().dead)
	<-in
	if r.m.Status().State != Reconnecting {
		t.Fatal(r.m.Status())
	}
	if err := r.m.Down(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if r.m.Status().State != Disarmed || r.d.ups.Load() != 1 {
		t.Fatalf("%+v ups=%d", r.m.Status(), r.d.ups.Load())
	}
	eq(t, r.l.get(), []string{"Lock(a:1.1.1.1)", "Arm(a:1.1.1.1@tun-a)", "Lock(a:1.1.1.1)", "Disarm()"})
}

func TestSwitchDuringLoop(t *testing.T) {
	r := newRig(t, 5)
	in := r.blockingSleep()
	r.up(t, prof("a", true))
	close(r.d.last().dead)
	<-in
	r.up(t, prof("b", true))
	time.Sleep(30 * time.Millisecond)
	if st := r.m.Status(); st.State != Armed || st.Profile != "b" {
		t.Fatalf("%+v", st)
	}
	if r.d.ups.Load() != 2 {
		t.Fatal("loop kept running")
	}
	noDisarm(t, r.l)
}

func TestPanicOffBlockedTunnel(t *testing.T) {
	r := newRig(t, 5)
	r.d.block = make(chan struct{})
	defer close(r.d.block)
	r.up(t, prof("a", true))
	start := time.Now()
	if err := r.m.PanicOff(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("blocked")
	}
	if r.m.Status().State != Disarmed || r.m.Active() {
		t.Fatal("want disarmed")
	}
	if _, err := os.Stat(r.m.MarkerPath); !os.IsNotExist(err) {
		t.Fatal("marker kept")
	}
	eq(t, kinds(r.ch), []string{"up", "error", "panic_off"})

	r.fw.failOn = "Disarm"
	if err := r.m.PanicOff(); err == nil {
		t.Fatal("disarm error must be returned")
	}
}

func TestPanicOffDuringLoop(t *testing.T) {
	r := newRig(t, 5)
	in := r.blockingSleep()
	r.up(t, prof("a", true))
	close(r.d.last().dead)
	<-in
	if err := r.m.PanicOff(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if r.m.Status().State != Disarmed || r.d.ups.Load() != 1 {
		t.Fatal("loop survived")
	}
}

func TestReconnectNoKillswitch(t *testing.T) {
	r := newRig(t, 2)
	r.up(t, prof("a", false))
	close(r.d.last().dead)
	wait(t, func() bool { return r.d.ups.Load() == 2 && r.m.Status().State == Armed })
	eq(t, r.l.get(), nil)
}

func TestRestoreLock(t *testing.T) {
	r := newRig(t, 0)
	if err := r.m.RestoreLock(); err != nil || r.m.Status().State != Disarmed || len(r.l.get()) != 0 {
		t.Fatal("no marker must be a no-op")
	}
	mk := `{"profile":"a","iface":"tun-a","endpoints":[{"IP":"1.1.1.1","Port":1,"Proto":"udp"}],"armed_at":"2026-01-01T00:00:00Z"}`
	os.WriteFile(r.m.MarkerPath, []byte(mk), 0o600)
	if err := r.m.RestoreLock(); err != nil {
		t.Fatal(err)
	}
	eq(t, r.l.get(), []string{"Lock(a:1.1.1.1)"})
	if r.m.Status().State != Locked || r.m.Status().Profile != "a" {
		t.Fatalf("%+v", r.m.Status())
	}
	if err := r.m.Down(); err != nil || r.m.Status().State != Disarmed {
		t.Fatal(err)
	}
	// corrupt marker: still locks
	os.WriteFile(r.m.MarkerPath, []byte("{"), 0o600)
	if err := r.m.RestoreLock(); err == nil || r.m.Status().State != Locked {
		t.Fatal("corrupt marker must lock")
	}
}

type fakeKernel struct {
	table  bool
	ifaces map[string]bool
	pid    bool
}

func (k fakeKernel) TableExists() bool         { return k.table }
func (k fakeKernel) IfaceExists(n string) bool { return k.ifaces[n] }
func (k fakeKernel) PidAlive(int) bool         { return k.pid }

func TestReconcile(t *testing.T) {
	getOK := func(id string) (*profile.Profile, error) { return prof(id, true), nil }
	getKO := func(string) (*profile.Profile, error) { return nil, errors.New("gone") }
	both := map[string]bool{"tun-a": true, orphanIface: true}
	tunA := map[string]bool{"tun-a": true}
	cases := []struct {
		name    string
		state   string // "" = no state.json
		pid     int
		k       fakeKernel
		get     func(string) (*profile.Profile, error)
		noAdopt bool
		adoptKO bool
		fwFail  string
		delKO   bool
		want    string
		wantErr bool
		lock    bool // a Lock call is expected
		final   string
	}{
		{name: "no state clean", k: fakeKernel{}, want: "clean", final: Disarmed},
		{name: "disarmed clean", state: Disarmed, k: fakeKernel{}, want: "clean", final: Disarmed},
		{name: "no state table", k: fakeKernel{table: true}, want: "locked", lock: true, final: Locked},
		{name: "disarmed table", state: Disarmed, k: fakeKernel{table: true}, want: "locked", lock: true, final: Locked},
		{name: "table fw error", k: fakeKernel{table: true}, fwFail: "Lock", want: "locked", wantErr: true, lock: true, final: Locked},
		{name: "orphan iface", k: fakeKernel{ifaces: both}, want: "orphan_cleaned", final: Disarmed},
		{name: "orphan delete error", k: fakeKernel{ifaces: map[string]bool{orphanIface: true}}, delKO: true, want: "locked", wantErr: true, lock: true, final: Locked},
		{name: "resumed ovpn", state: Armed, pid: 42, k: fakeKernel{ifaces: tunA, pid: true}, want: "resumed", final: Armed},
		{name: "resumed wg pid0", state: Armed, k: fakeKernel{ifaces: tunA}, want: "resumed", final: Armed},
		{name: "armed table too", state: Armed, k: fakeKernel{table: true, ifaces: tunA}, want: "resumed", final: Armed},
		{name: "iface absent", state: Armed, k: fakeKernel{}, want: "locked", lock: true, final: Locked},
		{name: "pid dead", state: Armed, pid: 42, k: fakeKernel{ifaces: tunA}, want: "locked", lock: true, final: Locked},
		{name: "profile gone", state: Armed, k: fakeKernel{ifaces: tunA}, get: getKO, want: "locked", lock: true, final: Locked},
		{name: "adopt fails", state: Armed, k: fakeKernel{ifaces: tunA}, adoptKO: true, want: "locked", wantErr: true, lock: true, final: Locked},
		{name: "no adopter", state: Armed, k: fakeKernel{ifaces: tunA}, noAdopt: true, want: "locked", lock: true, final: Locked},
		{name: "reconnecting", state: Reconnecting, k: fakeKernel{ifaces: tunA}, want: "locked", lock: true, final: Locked},
		{name: "locked", state: Locked, k: fakeKernel{ifaces: tunA}, want: "locked", lock: true, final: Locked},
		{name: "arm fails", state: Armed, k: fakeKernel{ifaces: tunA}, fwFail: "Arm", want: "locked", wantErr: true, lock: true, final: Locked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, 0)
			if c.noAdopt {
				r.m.Drivers["openvpn"] = struct{ Driver }{r.d}
			}
			if c.adoptKO {
				r.d.adoptErr = errors.New("adopt")
			}
			r.fw.failOn = c.fwFail
			var deleted []string
			r.m.DeleteIface = func(n string) error {
				deleted = append(deleted, n)
				if c.delKO {
					return errors.New("del")
				}
				return nil
			}
			if c.state != "" {
				writeAtomic(r.m.StatePath, Persisted{Profile: "a", State: c.state, Iface: "tun-a", PID: c.pid})
			}
			get := c.get
			if get == nil {
				get = getOK
			}
			got, err := r.m.Reconcile(context.Background(), c.k, get)
			if got != c.want || (err != nil) != c.wantErr {
				t.Fatalf("got %q %v", got, err)
			}
			noDisarm(t, r.l)
			validJournal(t, r.dir)
			hasLock := false
			for _, x := range r.l.get() {
				hasLock = hasLock || strings.HasPrefix(x, "Lock(")
			}
			if hasLock != c.lock {
				t.Fatalf("lock=%v calls %v", hasLock, r.l.get())
			}
			if st := r.m.Status().State; st != c.final {
				t.Fatalf("state %s", st)
			}
			if c.want == "orphan_cleaned" && (len(deleted) != 1 || deleted[0] != orphanIface) {
				t.Fatal(deleted)
			}
			if c.want != "orphan_cleaned" && !c.delKO && len(deleted) != 0 {
				t.Fatal("unexpected delete")
			}
			found := false
			for e := range r.ch {
				if e.Kind == "reconcile" && e.Detail == c.want {
					found = true
				}
				if len(r.ch) == 0 {
					break
				}
			}
			if !found {
				t.Fatal("no reconcile event")
			}
		})
	}
}

func TestReconcileResumedNoSecrets(t *testing.T) {
	r := newRig(t, 5)
	writeAtomic(r.m.StatePath, Persisted{Profile: "a", State: Armed, Iface: "tun-a"})
	got, err := r.m.Reconcile(context.Background(), fakeKernel{ifaces: map[string]bool{"tun-a": true}},
		func(id string) (*profile.Profile, error) { return prof(id, true), nil })
	if got != "resumed" || err != nil {
		t.Fatal(got, err)
	}
	close(r.d.last().dead)
	wait(t, func() bool { return r.m.Status().State == Locked })
	time.Sleep(30 * time.Millisecond)
	if r.d.ups.Load() != 0 {
		t.Fatal("reconnect attempted without secrets")
	}
	var lockDetail string
	for len(r.ch) > 0 {
		if e := <-r.ch; e.Kind == "lock" {
			lockDetail = e.Detail
		}
	}
	if lockDetail != noSecretsMsg {
		t.Fatal(lockDetail)
	}
	noDisarm(t, r.l)
}

// blockUpDrv blocks Driver.Up until released, to simulate a slow Up overtaken by PanicOff.
type blockUpDrv struct {
	*scriptDrv
	in, release chan struct{}
}

func (d blockUpDrv) Up(ctx context.Context, p *profile.Profile, s Secrets, e []Endpoint) (Tunnel, Info, error) {
	d.in <- struct{}{}
	<-d.release
	return d.scriptDrv.Up(ctx, p, s, e)
}

// ctxUpDrv blocks Up until its ctx is cancelled (a server that never answers).
type ctxUpDrv struct {
	*scriptDrv
	in chan struct{}
}

func (d ctxUpDrv) Up(ctx context.Context, p *profile.Profile, s Secrets, e []Endpoint) (Tunnel, Info, error) {
	d.in <- struct{}{}
	<-ctx.Done()
	return nil, Info{}, ctx.Err()
}

func TestDownInterruptsUp(t *testing.T) {
	for _, ks := range []bool{true, false} {
		r := newRig(t, 0)
		d := ctxUpDrv{r.d, make(chan struct{}, 1)}
		r.m.Drivers["openvpn"] = d
		res := make(chan error, 1)
		go func() { res <- r.m.Up(context.Background(), prof("a", ks), Secrets{}) }()
		<-d.in
		start := time.Now()
		if err := r.m.Down(); err != nil {
			t.Fatal(err)
		}
		if time.Since(start) > time.Second {
			t.Fatal("down waited for the connect timeout")
		}
		if err := <-res; !errors.Is(err, ErrCancelled) {
			t.Fatalf("ks=%v: %v", ks, err)
		}
		if st := r.m.Status(); st.State != Disarmed || r.m.Active() {
			t.Fatalf("ks=%v: %+v", ks, st)
		}
	}
}

func TestUpQueuedBehindDownIsCancelled(t *testing.T) {
	r := newRig(t, 0)
	bd := blockUpDrv{r.d, make(chan struct{}, 1), make(chan struct{})}
	r.m.Drivers["openvpn"] = bd
	first := make(chan error, 1)
	go func() { first <- r.m.Up(context.Background(), prof("a", true), Secrets{}) }()
	<-bd.in
	second := make(chan error, 1)
	go func() { second <- r.m.Up(context.Background(), prof("b", true), Secrets{}) }()
	time.Sleep(20 * time.Millisecond) // b is now queued on mu
	go func() { time.Sleep(20 * time.Millisecond); close(bd.release) }()
	if err := r.m.Down(); err != nil {
		t.Fatal(err)
	}
	if err := <-first; !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
	if err := <-second; !errors.Is(err, ErrCancelled) {
		t.Fatal("queued up must not re-lock after down:", err)
	}
	if st := r.m.Status(); st.State != Disarmed {
		t.Fatalf("%+v", st)
	}
}

func TestPanicOffDuringSlowUp(t *testing.T) {
	r := newRig(t, 0)
	bd := blockUpDrv{r.d, make(chan struct{}, 1), make(chan struct{})}
	r.m.Drivers["openvpn"] = bd
	res := make(chan error, 1)
	go func() {
		res <- r.m.Up(context.Background(), prof("a", true), Secrets{})
	}()
	<-bd.in
	if err := r.m.PanicOff(); err != nil { // times out on mu held by Up, then forces ahead
		t.Fatal(err)
	}
	close(bd.release)
	if err := <-res; !errors.Is(err, ErrCancelled) {
		t.Fatal(err)
	}
	if r.m.Status().State != Disarmed || r.m.Active() {
		t.Fatalf("%+v", r.m.Status())
	}
	calls := r.l.get()
	if calls[len(calls)-1] != "Disarm()" {
		t.Fatal(calls)
	}
	select {
	case <-r.d.last().dead:
	default:
		t.Fatal("late tunnel not shut down")
	}
}
