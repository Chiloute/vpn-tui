// Package state is the state machine of the single active VPN profile.
// Rule: on any doubt or error we stay locked, never disarmed.
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/health"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
)

const (
	Disarmed     = "disarmed"
	Armed        = "armed"
	Reconnecting = "reconnecting"
	Locked       = "locked"
)

var (
	ErrAlreadyActive = errors.New("already active")
	ErrCancelled     = errors.New("cancelled by panic-off/down")
)

type Endpoint struct {
	IP    netip.Addr
	Port  int
	Proto string // "udp"|"tcp"
}

// Secrets is never logged nor persisted.
type Secrets struct{ Username, Password, PrivateKey, PresharedKey string }

func (Secrets) String() string   { return "[redacted]" }
func (Secrets) GoString() string { return "[redacted]" }

type Info struct {
	PID     int // OpenVPN process, 0 for WireGuard
	Iface   string
	LHOST   netip.Addr
	Learned []netip.Prefix
}

type Spec struct {
	Profile   *profile.Profile
	Iface     string
	Endpoints []Endpoint
}

type Firewall interface {
	Lock(Spec) error
	Arm(Spec) error
	Disarm() error
}

type Tunnel interface {
	Down() error
	Dead() <-chan struct{}
	Stats() (rx, tx uint64)
}

type Driver interface {
	Endpoints(ctx context.Context, p *profile.Profile) ([]Endpoint, error)
	Up(ctx context.Context, p *profile.Profile, s Secrets, eps []Endpoint) (Tunnel, Info, error)
}

type Status struct {
	State      string
	Profile    string
	Killswitch bool
	LHOST      string
	Scope      []string
	Since      *time.Time
	Attempt    int
	Max        int
	Iface      string
	Rx, Tx     uint64
}

// Adopter is optionally implemented by a Driver to re-attach to a tunnel that survived a daemon restart.
type Adopter interface {
	Adopt(ctx context.Context, p *profile.Profile, iface string, pid int) (Tunnel, Info, error)
}

// NoopFirewall does nothing (real nftables arrives in phase 4).
type NoopFirewall struct{}

func (NoopFirewall) Lock(Spec) error { return nil }
func (NoopFirewall) Arm(Spec) error  { return nil }
func (NoopFirewall) Disarm() error   { return nil }

type session struct {
	p       *profile.Profile
	eps     []Endpoint
	iface   string
	lhost   string
	scope   []string
	pid     int
	tun     Tunnel // nil when the tunnel never came up or is dead
	closing atomic.Bool
	done    chan struct{}   // closed when the reconnection loop run on this session has returned; nil if none
	ctx     context.Context // cancelled by Down/PanicOff/Up of another profile: stops reconnection
	cancel  context.CancelFunc
	sec     *Secrets // memory only; nil once wiped or after a daemon restart
}

func newSession(p *profile.Profile, eps []Endpoint) *session {
	s := &session{p: p, eps: eps}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	return s
}

func (s *session) stop() { s.cancel() }

// derive copies s with another tunnel (nil = dead), sharing ctx and secrets.
func (s *session) derive(tun Tunnel) *session {
	return &session{p: s.p, eps: s.eps, iface: s.iface, lhost: s.lhost, scope: s.scope, pid: s.pid,
		tun: tun, ctx: s.ctx, cancel: s.cancel, sec: s.sec, done: s.done}
}

func (s *session) ks() bool { return s.p.Killswitch.Enabled }

type Manager struct {
	Drivers   map[string]Driver
	FW        Firewall
	Bus       *events.Bus
	StatePath string

	Reconnect struct {
		MaxAttempts int
		Backoff     health.Backoff
	}
	Sleep        func(ctx context.Context, d time.Duration) error // injectable; default is a ctx-aware timer
	MarkerPath   string                                           // persistent armed marker (no secrets)
	DeleteIface  func(string) error                               // used by Reconcile for orphan interfaces
	PanicTimeout time.Duration                                    // bound on tunnel Down in PanicOff (default 3s)

	attempt, max int                // protected by smu
	gen          atomic.Int64       // bumped by every Up/Down/PanicOff; stale commits are dropped
	upCancel     context.CancelFunc // protected by smu; aborts the driver Up in flight (Down/PanicOff)

	mu    sync.Mutex // serializes Up/Down
	smu   sync.Mutex // protects the fields below
	sess  *session
	state string
	since time.Time
}

func (m *Manager) Active() bool {
	m.smu.Lock()
	defer m.smu.Unlock()
	return m.sess != nil
}

func (m *Manager) Status() Status {
	m.smu.Lock()
	defer m.smu.Unlock()
	st := Status{State: m.state, Scope: []string{}}
	if m.state == Reconnecting {
		st.Attempt, st.Max = m.attempt, m.max
	}
	if st.State == "" {
		st.State = Disarmed
	}
	if !m.since.IsZero() {
		t := m.since
		st.Since = &t
	}
	if s := m.sess; s != nil {
		st.Profile, st.Killswitch, st.LHOST, st.Iface = s.p.ID, s.ks(), s.lhost, s.iface
		st.Scope = append(st.Scope, s.scope...)
		if s.tun != nil {
			st.Rx, st.Tx = s.tun.Stats()
		}
	}
	return st
}

func (m *Manager) set(state string, s *session) {
	m.smu.Lock()
	defer m.smu.Unlock()
	if m.state != state || m.since.IsZero() {
		m.since = time.Now().UTC()
	}
	m.state, m.sess = state, s
	if state != Reconnecting { // counters are set by the reconnect loop before it enters this state
		m.attempt, m.max = 0, 0
	}
	pe := Persisted{State: state, Since: &m.since, Updated: time.Now().UTC()}
	if s != nil {
		pe.Profile, pe.Iface, pe.LHOST, pe.PID = s.p.ID, s.iface, s.lhost, s.pid
	}
	if m.StatePath != "" {
		if err := writeAtomic(m.StatePath, pe); err != nil {
			m.emitLocked("error", "persist state: "+err.Error())
		}
	}
}

func (m *Manager) emit(kind, detail string) {
	m.smu.Lock()
	defer m.smu.Unlock()
	m.emitLocked(kind, detail)
}

func (m *Manager) emitLocked(kind, detail string) {
	if m.Bus == nil {
		return
	}
	e := events.Event{State: m.state, Kind: kind, Detail: detail}
	if e.State == "" { // before the first transition (reconcile clean)
		e.State = Disarmed
	}
	if m.sess != nil {
		e.Profile = m.sess.p.ID
	}
	m.Bus.Publish(e)
}

// fail records the error and stays locked (or keeps the given state when no lock applies).
func (m *Manager) fail(state string, s *session, err error) error {
	m.set(state, s)
	m.emit("error", err.Error())
	return err
}

// lockFail applies the lock for s (in doubt, lock for real), records the error and returns it.
func (m *Manager) lockFail(s *session, err error) error {
	m.lockdown(Spec{Profile: s.p, Iface: s.iface, Endpoints: s.eps}, s)
	m.emit("error", err.Error())
	return err
}

func union(a, b []Endpoint) []Endpoint {
	out := slices.Clone(a)
	for _, e := range b {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

func (m *Manager) Up(ctx context.Context, p *profile.Profile, sec Secrets) error {
	gen := m.gen.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gen.Load() != gen { // Down/PanicOff ran while we waited for mu
		return ErrCancelled
	}

	m.smu.Lock()
	prev, cur := m.sess, m.state
	m.smu.Unlock()
	if prev != nil && cur == Armed && prev.p.ID == p.ID {
		return ErrAlreadyActive
	}
	drv, ok := m.Drivers[p.Type]
	if !ok {
		return fmt.Errorf("no driver for type %q", p.Type)
	}
	eps, err := drv.Endpoints(ctx, p)
	if err != nil && prev != nil && prev.p.ID == p.ID && len(prev.eps) > 0 {
		eps, err = prev.eps, nil // the lock blocks DNS: reuse the endpoints resolved before it
	}
	if err != nil {
		if prev != nil || cur == Locked { // nothing touched; never record disarmed over a live table
			m.emit("error", err.Error())
			return err
		}
		return m.fail(Disarmed, nil, err)
	}
	next := newSession(p, eps)
	next.sec = &sec
	locked := cur == Locked // did we leave a firewall lock in place?

	if prev != nil {
		prev.stop()           // end any reconnection loop before touching the firewall
		if prev.done != nil { // let an attempt in flight release vpntui0 and the OpenVPN files
			select {
			case <-prev.done:
			case <-time.After(loopStopWait):
			}
		}
		if prev.ks() {
			a := Spec{Profile: prev.p, Iface: prev.iface, Endpoints: union(prev.eps, eps)}
			if err := m.FW.Lock(a); err != nil {
				m.set(Locked, prev)
				m.emit("error", err.Error())
				return err
			}
			locked = true
		}
		if prev.tun != nil {
			prev.closing.Store(true)
			if err := prev.tun.Down(); err != nil {
				prev.closing.Store(false)
				return m.lockFail(prev, err)
			}
		}
		if locked {
			m.set(Locked, nil)
		} else {
			m.set(Disarmed, nil)
		}
	}

	if next.ks() {
		if err := m.FW.Lock(Spec{Profile: p, Endpoints: eps}); err != nil {
			return m.fail(Locked, next, err)
		}
		locked = true
		m.set(Locked, next)
	}

	dctx, dcancel := context.WithCancel(ctx)
	m.smu.Lock()
	m.upCancel = dcancel
	m.smu.Unlock()
	tun, info, err := drv.Up(dctx, p, sec, eps)
	m.smu.Lock()
	m.upCancel = nil
	m.smu.Unlock()
	dcancel()
	if m.gen.Load() != gen { // PanicOff/Down/another Up ran meanwhile: touch nothing
		if err == nil {
			if derr := tun.Down(); derr != nil {
				m.emit("error", "tunnel cancelled: "+derr.Error())
			}
		}
		return ErrCancelled
	}
	if err != nil {
		if next.ks() || locked {
			return m.fail(Locked, next, err)
		}
		if derr := m.FW.Disarm(); derr != nil {
			return m.fail(Locked, next, errors.Join(err, derr))
		}
		return m.fail(Disarmed, nil, err)
	}
	next = next.derive(tun) // never mutate a published session: Status reads it under smu only
	next.iface, next.pid = info.Iface, info.PID
	if info.LHOST.IsValid() {
		next.lhost = info.LHOST.String()
	}
	for _, l := range info.Learned {
		next.scope = append(next.scope, l.String())
	}
	if next.ks() {
		if err := m.FW.Arm(Spec{Profile: p, Iface: info.Iface, Endpoints: eps}); err != nil {
			go m.watch(next)
			return m.fail(Locked, next, err)
		}
	} else if locked { // user chose a profile without kill switch: release A's lock
		if err := m.FW.Disarm(); err != nil {
			go m.watch(next)
			return m.fail(Locked, next, err)
		}
	}
	m.set(Armed, next)
	m.writeMarker(next)
	m.emit("up", "profile "+p.ID+" active on "+info.Iface)
	if len(next.scope) > 0 {
		m.emit("scope_learned", strings.Join(next.scope, ","))
	}
	go m.watch(next)
	return nil
}

func (m *Manager) Down() error {
	m.gen.Add(1)
	m.smu.Lock()
	if m.sess != nil {
		m.sess.stop() // unblock a reconnection loop before waiting for mu
	}
	if m.upCancel != nil {
		m.upCancel() // and a connection in progress
	}
	m.smu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.smu.Lock()
	s, st := m.sess, m.state
	m.smu.Unlock()
	if s == nil && st != Locked {
		return nil
	}
	if s != nil {
		s.stop()
		if s.tun != nil {
			s.closing.Store(true)
			if err := s.tun.Down(); err != nil {
				s.closing.Store(false)
				return m.lockFail(s, err)
			}
		}
	}
	if err := m.FW.Disarm(); err != nil {
		if s == nil {
			return m.fail(Locked, nil, err)
		}
		return m.lockFail(s, err)
	}
	m.removeMarker()
	m.emitDown(s)
	return nil
}

func (m *Manager) emitDown(s *session) {
	m.set(Disarmed, nil)
	if m.Bus != nil {
		e := events.Event{State: Disarmed, Kind: "down"}
		if s != nil {
			e.Profile = s.p.ID
		}
		m.Bus.Publish(e)
	}
}

// Persisted is the content of state.json; never contains secrets.
type Persisted struct {
	Profile string     `json:"profile"`
	State   string     `json:"state"`
	Iface   string     `json:"iface"`
	LHOST   string     `json:"lhost"`
	PID     int        `json:"pid"`
	Since   *time.Time `json:"since"`
	Updated time.Time  `json:"updated"`
}

func Load(path string) (*Persisted, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func writeAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".state-*") // created 0600
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil { // the marker must survive a power loss: it drives --restore-lock
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
