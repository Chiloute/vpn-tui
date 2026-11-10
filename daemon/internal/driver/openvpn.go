package driver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/dns"
	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
	"github.com/Chiloute/vpn-tui/daemon/internal/ovpn"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
)

type OpenVPN struct {
	Store          *profile.Store
	RunDir, Bin    string
	User, Group    string
	ConnectTimeout time.Duration
	DNS            *dns.Resolved // nil: profile DNS is not applied
}

func (d OpenVPN) config(p *profile.Profile) (*ovpn.Config, error) {
	b, err := d.Store.ReadConfig(p.ID)
	if err != nil {
		return nil, err
	}
	return ovpn.Parse(b)
}

func (d OpenVPN) Endpoints(ctx context.Context, p *profile.Profile) ([]state.Endpoint, error) {
	c, err := d.config(p)
	if err != nil {
		return nil, err
	}
	rs, err := ovpn.Resolve(ctx, c)
	if err != nil {
		return nil, err
	}
	out := make([]state.Endpoint, len(rs))
	for i, r := range rs {
		out[i] = state.Endpoint{IP: r.IP, Port: r.Port, Proto: r.Proto}
	}
	return out, nil
}

func needsAuth(c *ovpn.Config) bool {
	for _, l := range strings.Split(string(c.Sanitized), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == "auth-user-pass" {
			return true
		}
	}
	return false
}

func (d OpenVPN) Up(ctx context.Context, p *profile.Profile, s state.Secrets, eps []state.Endpoint) (state.Tunnel, state.Info, error) {
	c, err := d.config(p)
	if err != nil {
		return nil, state.Info{}, err
	}
	o := ovpn.StartOpts{Bin: d.Bin, RunDir: d.RunDir, ID: p.ID, Iface: Iface, Config: c,
		User: d.User, Group: d.Group, ConnectTimeout: d.ConnectTimeout}
	if needsAuth(c) {
		if s.Username == "" || s.Password == "" {
			return nil, state.Info{}, fmt.Errorf("%w : identifiant ou mot de passe absent", ErrSecrets)
		}
		o.Username, o.Password = s.Username, s.Password
	}
	for _, e := range eps {
		o.Remotes = append(o.Remotes, ovpn.Resolved{IP: e.IP, Port: e.Port, Proto: e.Proto})
	}
	proc, err := ovpn.Start(ctx, o)
	if err != nil {
		return nil, state.Info{}, err
	}
	info := state.Info{Iface: Iface, LHOST: proc.LocalIP(), Learned: learned()}
	if !info.LHOST.Is4() {
		info.LHOST, _ = netinfo.IPv4(Iface)
	}
	info.PID = proc.Pid()
	return d.ovpnTunnel(ctx, p, proc), info, nil
}

func (d OpenVPN) ovpnTunnel(ctx context.Context, p *profile.Profile, proc *ovpn.Process) *tunnel {
	return newTunnel(func(context.Context) <-chan struct{} { return proc.Dead() }, withDNS(ctx, d.DNS, p, proc.Stop),
		func() (uint64, uint64) { return 0, 0 }, nil)
}

// Adopt re-attaches to the OpenVPN left by a previous daemon (comm checked by ovpn.Adopt).
func (d OpenVPN) Adopt(ctx context.Context, p *profile.Profile, iface string, pid int) (state.Tunnel, state.Info, error) {
	if iface != Iface {
		return nil, state.Info{}, fmt.Errorf("interface inattendue %q", iface)
	}
	proc, err := ovpn.Adopt(pid, iface, d.RunDir)
	if err != nil {
		return nil, state.Info{}, err
	}
	info := state.Info{PID: pid, Iface: Iface, Learned: learned()}
	info.LHOST, _ = netinfo.IPv4(Iface)
	return d.ovpnTunnel(ctx, p, proc), info, nil
}
