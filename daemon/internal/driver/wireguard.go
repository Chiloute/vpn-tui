package driver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/Chiloute/vpn-tui/daemon/internal/wg"
)

type WireGuard struct{ Store *profile.Store }

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
	info := state.Info{Iface: Iface, Learned: learned()}
	info.LHOST, _ = netinfo.IPv4(Iface) // IPv6-only tunnel: no LHOST
	return newTunnel(nil, l.Down, l.Stats), info, nil
}
