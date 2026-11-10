package wg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// fwmark et table du routage « tunnel complet » (identiques à wg-quick).
const fwmark = 51820

// Resolve résout l'endpoint de chaque peer (un résultat par peer ; AddrPort
// zéro si le peer n'a pas d'endpoint).
func Resolve(ctx context.Context, c *Config) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, len(c.Peers))
	for i, p := range c.Peers {
		if p.Endpoint == "" {
			continue
		}
		host, ps, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q : %w", p.Endpoint, err)
		}
		port, err := strconv.Atoi(ps)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q : port invalide", p.Endpoint)
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("résolution de l'endpoint %q impossible : %v", p.Endpoint, err)
		}
		out[i] = netip.AddrPortFrom(ips[0].Unmap(), uint16(port))
	}
	return out, nil
}

// Link est une interface WireGuard montée.
type Link struct {
	iface string
	fams  []int // familles routées par fwmark (tunnel complet)
	once  sync.Once
	err   error
}

func (l *Link) Iface() string { return l.iface }

// fullFamilies renvoie les familles (AF_INET/AF_INET6) ayant un AllowedIPs /0.
func fullFamilies(c *Config) []int {
	var v4, v6 bool
	for _, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			if a.Bits() == 0 {
				v4 = v4 || a.Addr().Is4()
				v6 = v6 || a.Addr().Is6()
			}
		}
	}
	var f []int
	if v4 {
		f = append(f, unix.AF_INET)
	}
	if v6 {
		f = append(f, unix.AF_INET6)
	}
	return f
}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// buildConfig construit la config wgctrl. Les erreurs ne contiennent jamais de secret.
func buildConfig(c *Config, privateKey, presharedKey string, eps []netip.AddrPort, mark int) (wgtypes.Config, error) {
	if len(eps) != len(c.Peers) {
		return wgtypes.Config{}, errors.New("nombre d'endpoints différent du nombre de peers")
	}
	priv, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return wgtypes.Config{}, errors.New("clé privée invalide")
	}
	cfg := wgtypes.Config{PrivateKey: &priv, ReplacePeers: true}
	if c.ListenPort > 0 {
		cfg.ListenPort = &c.ListenPort
	}
	if mark != 0 {
		cfg.FirewallMark = &mark
	}
	for i, p := range c.Peers {
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("clé publique du peer %d invalide", i)
		}
		pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true}
		for _, a := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, *ipNet(a))
		}
		if p.HasPresharedKey {
			psk, err := wgtypes.ParseKey(presharedKey)
			if err != nil {
				return wgtypes.Config{}, errors.New("clé pré-partagée invalide")
			}
			pc.PresharedKey = &psk
		}
		if eps[i].IsValid() {
			pc.Endpoint = &net.UDPAddr{IP: eps[i].Addr().AsSlice(), Port: int(eps[i].Port())}
		}
		if p.PersistentKeepalive > 0 {
			ka := time.Duration(p.PersistentKeepalive) * time.Second
			pc.PersistentKeepaliveInterval = &ka
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	return cfg, nil
}

func rules(fam int) []*netlink.Rule {
	m := uint32(0xffffffff)
	a := netlink.NewRule()
	a.Family, a.Invert, a.Mark, a.Mask, a.Table, a.Priority = fam, true, fwmark, &m, fwmark, 32765
	b := netlink.NewRule()
	b.Family, b.Table, b.SuppressPrefixlen, b.Priority = fam, unix.RT_TABLE_MAIN, 0, 32764
	return []*netlink.Rule{a, b}
}

func delRules(fams []int) {
	for _, f := range fams {
		for _, r := range rules(f) {
			for i := 0; i < 8 && netlink.RuleDel(r) == nil; i++ {
			}
		}
	}
}

// Up crée et configure l'interface. En cas d'erreur, tout est défait.
func Up(ctx context.Context, iface string, c *Config, privateKey, presharedKey string, endpoints []netip.AddrPort) (_ *Link, err error) {
	l := &Link{iface: iface, fams: fullFamilies(c)}
	mark := 0
	if len(l.fams) > 0 {
		mark = fwmark
	}
	cfg, err := buildConfig(c, privateKey, presharedKey, endpoints, mark)
	if err != nil {
		return nil, err
	}
	if old, e := netlink.LinkByName(iface); e == nil {
		if err := netlink.LinkDel(old); err != nil {
			return nil, fmt.Errorf("suppression de l'interface résiduelle %s : %w", iface, err)
		}
	}
	la := netlink.NewLinkAttrs()
	la.Name = iface
	if c.MTU > 0 {
		la.MTU = c.MTU
	}
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); err != nil {
		return nil, fmt.Errorf("création de %s : %w", iface, err)
	}
	defer func() {
		if err != nil {
			_ = l.Down()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wc, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wc.Close()
	if err := wc.ConfigureDevice(iface, cfg); err != nil {
		return nil, fmt.Errorf("configuration wireguard : %w", err)
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	for _, a := range c.Addresses {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet(a)}); err != nil {
			return nil, fmt.Errorf("adresse %s : %w", a, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, err
	}
	delRules(l.fams) // règles résiduelles éventuelles
	for _, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			table := unix.RT_TABLE_MAIN
			if a.Bits() == 0 {
				table = fwmark
			}
			r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: ipNet(a), Table: table, Scope: netlink.SCOPE_LINK}
			if err := netlink.RouteReplace(r); err != nil {
				return nil, fmt.Errorf("route %s : %w", a, err)
			}
		}
	}
	for _, f := range l.fams {
		for _, r := range rules(f) {
			if err := netlink.RuleAdd(r); err != nil {
				return nil, fmt.Errorf("règle de routage : %w", err)
			}
		}
	}
	return l, nil
}

// Down supprime les règles puis l'interface ; idempotent.
func (l *Link) Down() error {
	l.once.Do(func() {
		delRules(l.fams)
		link, err := netlink.LinkByName(l.iface)
		if err != nil {
			var nf netlink.LinkNotFoundError
			if !errors.As(err, &nf) {
				l.err = err
			}
			return
		}
		l.err = netlink.LinkDel(link)
	})
	return l.err
}

func (l *Link) device() (*wgtypes.Device, error) {
	wc, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer wc.Close()
	return wc.Device(l.iface)
}

// Stats renvoie les octets reçus/émis cumulés (0,0 en cas d'erreur).
func (l *Link) Stats() (rx, tx uint64) {
	d, err := l.device()
	if err != nil {
		return 0, 0
	}
	for _, p := range d.Peers {
		rx += uint64(p.ReceiveBytes)
		tx += uint64(p.TransmitBytes)
	}
	return rx, tx
}

// LastHandshake renvoie le dernier handshake le plus récent (zéro si aucun).
func (l *Link) LastHandshake() time.Time {
	d, err := l.device()
	if err != nil {
		return time.Time{}
	}
	var t time.Time
	for _, p := range d.Peers {
		if p.LastHandshakeTime.After(t) {
			t = p.LastHandshakeTime
		}
	}
	return t
}
