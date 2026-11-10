// Package driver adapts the wg and ovpn packages to state.Driver.
// Every Up re-reads and re-parses the stored config (defense in depth).
package driver

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/dns"
	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
)

// Iface is the fixed name of the tunnel interface.
const Iface = "vpntui0"

// teardownDelay is a var for tests.
var teardownDelay = time.Second

// ErrSecrets means required secrets are missing (messages never carry values).
var ErrSecrets = errors.New("missing secrets")

// withDNS applies the profile DNS on Iface (nothing when it has no servers) and returns stop preceded by a
// best-effort Revert. An Apply failure only logs: the tunnel stays up (nft already blocks 53/853 outside it).
func withDNS(ctx context.Context, r *dns.Resolved, p *profile.Profile, stop func() error) func() error {
	if len(p.DNS.Servers) == 0 {
		return stop
	}
	if r == nil || r.Bin == "" {
		slog.Warn("dns: resolvectl unavailable, profile DNS not applied", "profile", p.ID)
		return stop
	}
	var addrs []netip.Addr
	for _, s := range p.DNS.Servers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			slog.Warn("dns: invalid server", "profile", p.ID)
			return stop
		}
		addrs = append(addrs, a)
	}
	if err := r.Apply(ctx, Iface, addrs, p.DNS.Force); err != nil {
		slog.Warn("dns: cannot apply", "profile", p.ID, "err", err)
	}
	return func() error {
		if err := r.Revert(context.WithoutCancel(ctx), Iface); err != nil {
			slog.Warn("dns: cannot revert", "err", err)
		}
		return stop()
	}
}

// tunnel implements state.Tunnel.
type tunnel struct {
	stop   func() error
	stats  func() (uint64, uint64)
	dead   <-chan struct{}
	cancel context.CancelFunc
}

func (t *tunnel) Down() error {
	err := t.stop()
	t.cancel()
	return err
}
func (t *tunnel) Dead() <-chan struct{}  { return t.dead }
func (t *tunnel) Stats() (rx, tx uint64) { return t.stats() }

// newTunnel merges the driver's own death signal (own may be nil; its ctx is cancelled by Down) with netinfo.WatchGone.
//
// Once dead, the tunnel is torn down after teardownDelay (time for the manager to lock the firewall first),
// so that a dead interface or process never lingers; safe (may be nil) vetoes that teardown.
func newTunnel(own func(context.Context) <-chan struct{}, stop func() error, stats func() (uint64, uint64), safe func() bool) *tunnel {
	ctx, cancel := context.WithCancel(context.Background())
	var ownCh <-chan struct{}
	if own != nil {
		ownCh = own(ctx)
	}
	gone := netinfo.WatchGone(ctx, Iface)
	out := make(chan struct{})
	go func() {
		select {
		case <-ownCh:
		case <-gone:
		}
		close(out)
		time.Sleep(teardownDelay)
		if safe == nil || safe() {
			stop() // idempotent; error irrelevant here
		}
	}()
	return &tunnel{stop: stop, stats: stats, dead: out, cancel: cancel}
}

var def1 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
	netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
	netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
}

// learned lists the routes of the interface, minus default routes and def1 halves.
func learned() []netip.Prefix {
	rs, err := netinfo.Routes(Iface)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, r := range rs {
		if !slices.Contains(def1, r) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// watchHandshake closes the returned channel when data was sent without a valid session: the last
// handshake (or start, if none) is older than timeout AND tx grew since it, on two consecutive checks
// (so a first packet after idle, which triggers a new handshake, is not a drop). Idle tunnels stay alive.
// last, tx, now and every are injectable.
func watchHandshake(ctx context.Context, last func() time.Time, tx func() uint64, start time.Time, timeout, every time.Duration, now func() time.Time) <-chan struct{} {
	dead := make(chan struct{})
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		ref, txRef, strikes := start, tx(), 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if hs := last(); !hs.IsZero() && !hs.Equal(ref) {
					ref, txRef = hs, tx() // new handshake: restart the baseline
				}
				if now().Sub(ref) > timeout && tx() > txRef {
					if strikes++; strikes >= 2 {
						close(dead)
						return
					}
				} else {
					strikes = 0
				}
			}
		}
	}()
	return dead
}
