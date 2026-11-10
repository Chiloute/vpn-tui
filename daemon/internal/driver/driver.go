// Package driver adapts the wg and ovpn packages to state.Driver.
// Every Up re-reads and re-parses the stored config (defense in depth).
package driver

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
)

// Iface is the fixed name of the tunnel interface.
const Iface = "vpntui0"

// ErrSecrets means required secrets are missing (messages never carry values).
var ErrSecrets = errors.New("secrets manquants")

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

// newTunnel merges the driver's own death signal (may be nil) with netinfo.WatchGone.
func newTunnel(own <-chan struct{}, stop func() error, stats func() (uint64, uint64)) *tunnel {
	ctx, cancel := context.WithCancel(context.Background())
	gone := netinfo.WatchGone(ctx, Iface)
	out := make(chan struct{})
	go func() {
		defer close(out)
		select {
		case <-own:
		case <-gone:
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
