package driver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/dns"
	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/Chiloute/vpn-tui/daemon/internal/wg"
	"github.com/vishvananda/netlink"
)

type WireGuard struct {
	Store            *profile.Store
	HandshakeTimeout time.Duration // default 180s
	CheckEvery       time.Duration // default 5s
	HandshakeWait    time.Duration // max wait for the first handshake in Up, default 10s (not --connect-timeout: main.go is out of scope)
	DNS              *dns.Resolved // nil: profile DNS is not applied
}

// tunnel wraps a link; a stale handshake kills it like a vanished interface does.
func (d WireGuard) tunnel(ctx context.Context, p *profile.Profile, l *wg.Link) *tunnel {
	to, every := d.HandshakeTimeout, d.CheckEvery
	if to <= 0 {
		to = 180 * time.Second
	}
	if every <= 0 {
		every = 5 * time.Second
	}
	start := time.Now()
	idx := ifindex() // shortcut: a reconnection racing the teardown is only vetoed once its iface exists
	return newTunnel(func(ctx context.Context) <-chan struct{} {
		return watchHandshake(ctx, l.LastHandshake, func() uint64 { _, tx := l.Stats(); return tx }, start, to, every, time.Now)
	}, withDNS(ctx, d.DNS, p, l.Down), l.Stats, func() bool { cur := ifindex(); return cur == 0 || cur == idx })
}

// Adopt re-attaches to the interface left by a previous daemon.
func (d WireGuard) Adopt(ctx context.Context, p *profile.Profile, iface string, _ int) (state.Tunnel, state.Info, error) {
	if iface != Iface {
		return nil, state.Info{}, fmt.Errorf("interface inattendue %q", iface)
	}
	l, err := wg.Adopt(iface)
	if err != nil {
		return nil, state.Info{}, err
	}
	return d.tunnel(ctx, p, l), d.info(), nil
}

func (WireGuard) info() state.Info {
	info := state.Info{Iface: Iface, Learned: learned()}
	info.LHOST, _ = netinfo.IPv4(Iface) // IPv6-only tunnel: no LHOST
	return info
}

func (d WireGuard) config(p *profile.Profile) (*wg.Config, error) {
	b, err := d.Store.ReadConfig(p.ID)
	if err != nil {
		return nil, err
	}
	return wg.Parse(b)
}

func (d WireGuard) Endpoints(ctx context.Context, p *profile.Profile) ([]state.Endpoint, error) {
	c, err := d.config(p)
	if err != nil {
		return nil, err
	}
	aps, err := wg.Resolve(ctx, c)
	if err != nil {
		return nil, err
	}
	var out []state.Endpoint
	for _, ap := range aps {
		if ap.IsValid() {
			out = append(out, state.Endpoint{IP: ap.Addr(), Port: int(ap.Port()), Proto: "udp"})
		}
	}
	return out, nil
}

func (d WireGuard) Up(ctx context.Context, p *profile.Profile, s state.Secrets, eps []state.Endpoint) (state.Tunnel, state.Info, error) {
	c, err := d.config(p)
	if err != nil {
		return nil, state.Info{}, err
	}
	if s.PrivateKey == "" {
		return nil, state.Info{}, fmt.Errorf("%w : clé privée absente", ErrSecrets)
	}
	aps := make([]netip.AddrPort, len(c.Peers))
	next := 0
	for i, pe := range c.Peers {
		if pe.HasPresharedKey && s.PresharedKey == "" {
			return nil, state.Info{}, fmt.Errorf("%w : clé pré-partagée absente", ErrSecrets)
		}
		if pe.Endpoint == "" {
			continue
		}
		if next >= len(eps) {
			return nil, state.Info{}, errors.New("endpoints résolus incohérents avec le profil")
		}
		aps[i] = netip.AddrPortFrom(eps[next].IP, uint16(eps[next].Port))
		next++
	}
	if next != len(eps) {
		return nil, state.Info{}, errors.New("endpoints résolus incohérents avec le profil")
	}
	l, err := wg.Up(ctx, Iface, c, s.PrivateKey, s.PresharedKey, aps)
	if err != nil {
		return nil, state.Info{}, err
	}
	wait := d.HandshakeWait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	if err := l.AwaitHandshake(ctx, c, wait); err != nil { // tears the link down on failure
		return nil, state.Info{}, err
	}
	return d.tunnel(ctx, p, l), d.info(), nil
}

// ifindex returns the index of the tunnel interface (0 if absent).
func ifindex() int {
	if l, err := netlink.LinkByName(Iface); err == nil {
		return l.Attrs().Index
	}
	return 0
}
