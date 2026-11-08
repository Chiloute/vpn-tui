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
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
)

const (
	Disarmed     = "disarmed"
	Armed        = "armed"
	Reconnecting = "reconnecting"
	Locked       = "locked"
)

var ErrAlreadyActive = errors.New("déjà actif")

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
	tun     Tunnel // nil when the tunnel never came up
	closing atomic.Bool
}

func (s *session) ks() bool { return s.p.Killswitch.Enabled }

type Manager struct {
	Drivers   map[string]Driver
	FW        Firewall
	Bus       *events.Bus
	StatePath string

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
	pe := Persisted{State: state, Since: &m.since, Updated: time.Now().UTC()}
	if s != nil {
		pe.Profile, pe.Iface, pe.LHOST = s.p.ID, s.iface, s.lhost
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
	m.mu.Lock()
	defer m.mu.Unlock()

	m.smu.Lock()
	prev := m.sess
	m.smu.Unlock()
	if prev != nil && prev.tun != nil && prev.p.ID == p.ID {
		return ErrAlreadyActive
	}
	drv, ok := m.Drivers[p.Type]
	if !ok {
		return fmt.Errorf("pas de pilote pour le type %q", p.Type)
	}
	eps, err := drv.Endpoints(ctx, p)
	if err != nil {
		if prev != nil { // A untouched; just report
			m.emit("error", err.Error())
			return err
		}
		return m.fail(Disarmed, nil, err)
	}
	next := &session{p: p, eps: eps}
	locked := false // did we leave a firewall lock in place?

	if prev != nil {
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
				m.set(Locked, prev)
				m.emit("error", err.Error())
				return err
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

	tun, info, err := drv.Up(ctx, p, sec, eps)
	if err != nil {
		if next.ks() || locked {
			return m.fail(Locked, next, err)
		}
		if derr := m.FW.Disarm(); derr != nil {
			return m.fail(Locked, next, errors.Join(err, derr))
		}
		return m.fail(Disarmed, nil, err)
	}
	next.tun, next.iface = tun, info.Iface
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
	m.emit("up", "profil "+p.ID+" actif sur "+info.Iface)
	if len(next.scope) > 0 {
		m.emit("scope_learned", strings.Join(next.scope, ","))
	}
	go m.watch(next)
	return nil
}

func (m *Manager) Down() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.smu.Lock()
	s := m.sess
	m.smu.Unlock()
	if s == nil {
		return nil
	}
	if s.tun != nil {
		s.closing.Store(true)
		if err := s.tun.Down(); err != nil {
			s.closing.Store(false)
			return m.fail(Locked, s, err)
		}
	}
	if err := m.FW.Disarm(); err != nil {
		return m.fail(Locked, s, err)
	}
	m.emitDown(s)
	return nil
}

func (m *Manager) emitDown(s *session) {
	m.set(Disarmed, nil)
	if m.Bus != nil {
		m.Bus.Publish(events.Event{Profile: s.p.ID, State: Disarmed, Kind: "down"})
	}
}

// watch locks the firewall when the tunnel dies unexpectedly.
func (m *Manager) watch(s *session) {
	<-s.tun.Dead()
	if s.closing.Load() {
		return
	}
	m.smu.Lock()
	cur := m.sess == s
	m.smu.Unlock()
	if !cur {
		return
	}
	if s.ks() {
		if err := m.FW.Lock(Spec{Profile: s.p, Iface: s.iface, Endpoints: s.eps}); err != nil {
			m.emit("error", err.Error())
		}
		m.set(Locked, s)
	} else {
		m.set(Disarmed, nil)
	}
	m.emit("drop", "tunnel tombé")
	m.reconnect(s)
}

// reconnect is the phase 4 hook (backoff, Reconnecting state). Intentionally a no-op.
func (m *Manager) reconnect(*session) {}

// Persisted is the content of state.json; never contains secrets.
type Persisted struct {
	Profile string     `json:"profile"`
	State   string     `json:"state"`
	Iface   string     `json:"iface"`
	LHOST   string     `json:"lhost"`
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

func writeAtomic(path string, p Persisted) error {
	b, err := json.Marshal(p)
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
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
