package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
)

const (
	orphanIface  = "vpntui0"
	noSecretsMsg = "secrets unavailable after daemon restart"
)

// marker is the persistent "armed" file; it never contains secrets.
type markerFile struct {
	Profile   string     `json:"profile"`
	Iface     string     `json:"iface"`
	Endpoints []Endpoint `json:"endpoints"`
	ArmedAt   time.Time  `json:"armed_at"`
}

// Kernel is what Reconcile needs to know about the host.
type Kernel interface {
	TableExists() bool
	IfaceExists(name string) bool
	PidAlive(pid int) bool
}

// writeMarker records an armed kill-switch profile (or removes the marker when it has none).
func (m *Manager) writeMarker(s *session) {
	if m.MarkerPath == "" {
		return
	}
	if !s.ks() {
		m.removeMarker()
		return
	}
	if err := writeAtomic(m.MarkerPath, markerFile{s.p.ID, s.iface, s.eps, time.Now().UTC()}); err != nil {
		m.emit("error", "persist marker: "+err.Error())
	}
}

func (m *Manager) removeMarker() {
	if m.MarkerPath == "" {
		return
	}
	if err := os.Remove(m.MarkerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		m.emit("error", "remove marker: "+err.Error())
	}
}

// lockStub is a fail-closed profile used when the real one is unknown.
func lockStub(id string) *profile.Profile {
	return &profile.Profile{ID: id, Killswitch: profile.Killswitch{Enabled: true, BlockIPv6: true}}
}

func (m *Manager) sleep(ctx context.Context, d time.Duration) error {
	if m.Sleep != nil {
		return m.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// step runs fn under mu unless the session was cancelled or replaced; it reports whether fn ran.
func (m *Manager) step(s *session, fn func()) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.smu.Lock()
	cur := m.sess != nil && m.sess.ctx == s.ctx
	m.smu.Unlock()
	if !cur || s.ctx.Err() != nil {
		return false
	}
	fn()
	return true
}

// watch locks the firewall when the tunnel dies unexpectedly, then reconnects.
func (m *Manager) watch(s *session) {
	<-s.tun.Dead()
	if s.closing.Load() {
		return
	}
	d := s.derive(nil)
	spec := Spec{Profile: s.p, Iface: s.iface, Endpoints: s.eps}
	var reconnect bool
	if !m.step(s, func() {
		if s.ks() {
			if err := m.FW.Lock(spec); err != nil {
				m.emit("error", err.Error())
			}
			m.set(Locked, d)
		} else {
			m.set(Reconnecting, d)
		}
		m.emit("drop", "tunnel dropped")
		if s.sec == nil { // resumed after a daemon restart: cannot reconnect
			if s.ks() {
				m.emit("lock", noSecretsMsg)
			} else {
				m.set(Disarmed, nil)
			}
			return
		}
		reconnect = true
	}) || !reconnect {
		return
	}
	m.reconnect(d)
}

// reconnect retries Driver.Up with backoff; the firewall stays locked meanwhile and is never disarmed here.
func (m *Manager) reconnect(s *session) {
	max := m.Reconnect.MaxAttempts
	drv := m.Drivers[s.p.Type]
	if drv == nil {
		max = 0
	}
	for a := 1; a <= max; a++ {
		if !m.step(s, func() {
			m.smu.Lock()
			m.attempt, m.max = a, max // before set(): Status must never show reconnecting 0/0
			m.smu.Unlock()
			m.set(Reconnecting, s)
			m.emit("reconnect", fmt.Sprintf("attempt %d/%d", a, max))
		}) {
			return
		}
		if m.sleep(s.ctx, m.Reconnect.Backoff.Delay(a)) != nil {
			return
		}
		gen := m.gen.Load()
		tun, info, err := drv.Up(s.ctx, s.p, *s.sec, s.eps)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			continue
		}
		done := false
		ran := m.step(s, func() {
			if m.gen.Load() != gen {
				return
			}
			next := s.derive(tun)
			next.iface, next.pid, next.lhost, next.scope = info.Iface, info.PID, "", nil
			if info.LHOST.IsValid() {
				next.lhost = info.LHOST.String()
			}
			for _, l := range info.Learned {
				next.scope = append(next.scope, l.String())
			}
			if s.ks() {
				if err := m.FW.Arm(Spec{Profile: s.p, Iface: info.Iface, Endpoints: s.eps}); err != nil {
					m.emit("error", err.Error())
					return
				}
			}
			m.set(Armed, next)
			m.writeMarker(next)
			m.emit("up", "profile "+s.p.ID+" reconnected on "+info.Iface)
			go m.watch(next)
			done = true
		})
		if done {
			return
		}
		if err := tun.Down(); err != nil {
			m.emit("error", "tunnel: "+err.Error())
		}
		if !ran {
			return
		}
	}
	// exhausted: stay locked durably until Down/PanicOff
	m.step(s, func() {
		l := s.derive(nil)
		l.sec = nil
		if s.ks() {
			if err := m.FW.Lock(Spec{Profile: s.p, Iface: s.iface, Endpoints: s.eps}); err != nil {
				m.emit("error", err.Error())
			}
			m.set(Locked, l)
			m.emit("lock", "reconnection attempts exhausted")
		} else {
			m.set(Disarmed, nil)
			m.emit("error", "reconnection attempts exhausted")
		}
	})
}

// PanicOff tears everything down: cancels reconnection, best-effort tunnel Down, Disarm, wipes marker and secrets.
func (m *Manager) PanicOff() error {
	m.gen.Add(1)
	m.smu.Lock()
	s := m.sess
	m.smu.Unlock()
	if s != nil {
		s.stop()
		s.closing.Store(true)
	}
	// Take mu to serialize with Up/Down, but never wait longer than the panic timeout.
	to := m.PanicTimeout
	if to <= 0 {
		to = 3 * time.Second
	}
	deadline := time.Now().Add(to)
	for !m.mu.TryLock() {
		if time.Now().After(deadline) {
			goto force
		}
		time.Sleep(time.Millisecond)
	}
	defer m.mu.Unlock()
force:
	m.smu.Lock()
	s = m.sess
	m.smu.Unlock()
	if s != nil {
		s.stop()
		s.closing.Store(true)
		if s.tun != nil {
			res := make(chan error, 1)
			go func() { res <- s.tun.Down() }()
			select {
			case err := <-res:
				if err != nil {
					m.emit("error", "panic-off tunnel: "+err.Error())
				}
			case <-time.After(to):
				m.emit("error", "panic-off tunnel: timeout")
			}
		}
	}
	derr := m.FW.Disarm()
	if derr != nil {
		m.emit("error", "panic-off disarm: "+derr.Error())
	}
	m.set(Disarmed, nil)
	m.removeMarker()
	m.emit("panic_off", "")
	return derr
}

func (m *Manager) readMarker() (*markerFile, error) {
	if m.MarkerPath == "" {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(m.MarkerPath)
	if err != nil {
		return nil, err
	}
	var mk markerFile
	if err := json.Unmarshal(b, &mk); err != nil {
		return nil, err
	}
	return &mk, nil
}

// lockdown locks with spec and records the locked state (never disarms). sess may be nil.
func (m *Manager) lockdown(spec Spec, sess *session) error {
	err := m.FW.Lock(spec)
	m.set(Locked, sess)
	if err != nil {
		m.emit("error", err.Error())
	}
	return err
}

// markerSession rebuilds a tunnel-less locked session from the marker.
func markerSession(mk *markerFile) (*session, Spec) {
	p := lockStub(mk.Profile)
	s := newSession(p, mk.Endpoints)
	s.iface = mk.Iface
	return s, Spec{Profile: p, Iface: mk.Iface, Endpoints: mk.Endpoints}
}

// RestoreLock re-applies the lock at boot when a marker exists; no marker means no-op.
func (m *Manager) RestoreLock() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	mk, err := m.readMarker()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil { // present but unreadable: lock everything
		lerr := m.lockdown(Spec{Profile: lockStub("")}, nil)
		return errors.Join(err, lerr)
	}
	s, spec := markerSession(mk)
	err = m.lockdown(spec, s)
	m.emit("lock", "lock restored at startup")
	return err
}

// Reconcile aligns the daemon with the host at startup, before serving requests.
//
// Decision table (A = persisted state in armed/reconnecting/locked, or state.json unreadable):
//
//	!A, no table, no vpntui0          -> clean
//	!A, table present                 -> Lock (marker spec, else empty)       -> locked
//	!A, no table, vpntui0 present     -> DeleteIface                          -> orphan_cleaned
//	A=armed, iface up, pid alive (or 0), profile exists, Adopter, Adopt ok,
//	  endpoints known, Arm ok         -> Arm + armed (no secrets)             -> resumed
//	A, anything else                  -> Lock                                 -> locked
//	any firewall/DeleteIface error    -> Lock attempt, outcome locked, error returned
//
// Reconcile never calls Disarm.
func (m *Manager) Reconcile(ctx context.Context, k Kernel, get func(id string) (*profile.Profile, error)) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pers, perr := Load(m.StatePath)
	active := perr != nil && !errors.Is(perr, os.ErrNotExist) // unreadable: assume the worst
	if perr == nil {
		active = pers.State == Armed || pers.State == Reconnecting || pers.State == Locked
	}
	var id string
	if pers != nil {
		id = pers.Profile
	}
	var p *profile.Profile
	if id != "" && get != nil {
		if q, err := get(id); err == nil {
			p = q
		}
	}
	// lock locks using the marker when available, else the profile, else an empty spec.
	lock := func(cause error) (string, error) {
		var sess *session
		spec := Spec{Profile: lockStub(id)}
		if mk, err := m.readMarker(); err == nil {
			sess, spec = markerSession(mk)
			if p != nil {
				sess.p, spec.Profile = p, p
			}
		}
		lerr := m.lockdown(spec, sess)
		m.emit("reconcile", "locked")
		return "locked", errors.Join(cause, lerr)
	}

	tableUp := k.TableExists()
	if !active {
		switch {
		case tableUp:
			return lock(nil)
		case k.IfaceExists(orphanIface):
			if m.DeleteIface == nil {
				return lock(errors.New("no DeleteIface"))
			}
			if err := m.DeleteIface(orphanIface); err != nil {
				return lock(err)
			}
			m.emit("reconcile", "orphan_cleaned")
			return "orphan_cleaned", nil
		}
		m.emit("reconcile", "clean")
		return "clean", nil
	}

	if pers == nil || pers.State != Armed || p == nil || pers.Iface == "" || !k.IfaceExists(pers.Iface) ||
		(pers.PID != 0 && !k.PidAlive(pers.PID)) {
		return lock(nil)
	}
	drv, ok := m.Drivers[p.Type].(Adopter)
	if !ok {
		return lock(nil)
	}
	eps, err := m.Drivers[p.Type].Endpoints(ctx, p)
	if err != nil {
		return lock(err)
	}
	tun, info, err := drv.Adopt(ctx, p, pers.Iface, pers.PID)
	if err != nil {
		return lock(err)
	}
	s := newSession(p, eps) // no secrets: sec stays nil
	s.tun, s.iface, s.pid = tun, info.Iface, info.PID
	if info.LHOST.IsValid() {
		s.lhost = info.LHOST.String()
	}
	for _, l := range info.Learned {
		s.scope = append(s.scope, l.String())
	}
	if s.ks() {
		if err := m.FW.Arm(Spec{Profile: p, Iface: s.iface, Endpoints: eps}); err != nil {
			lerr := m.lockdown(Spec{Profile: p, Iface: s.iface, Endpoints: eps}, s) // Down tears the adopted tunnel down
			go m.watch(s)
			m.emit("reconcile", "locked")
			return "locked", errors.Join(err, lerr)
		}
	}
	m.set(Armed, s)
	m.writeMarker(s)
	m.emit("reconcile", "resumed")
	go m.watch(s)
	return "resumed", nil
}
