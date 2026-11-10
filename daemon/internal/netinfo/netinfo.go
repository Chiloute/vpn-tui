// Package netinfo regroupe des utilitaires netlink partagés (lecture seule).
package netinfo

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// WGTable est la table de routage du tunnel complet (fwmark, comme wg-quick).
const WGTable = 51820

// IPv4 renvoie la première adresse IPv4 de l'interface.
func IPv4(iface string) (netip.Addr, error) {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP.To4()); ok {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("aucune adresse IPv4 sur %s", iface)
}

// Exists indique si l'interface existe.
func Exists(iface string) bool {
	_, err := netlink.LinkByName(iface)
	return err == nil
}

// Routes renvoie les routes (tables main et 51820) dont l'oif est iface.
func Routes(iface string) ([]netip.Prefix, error) {
	l, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, err
	}
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	var all []netlink.Route
	for _, t := range []int{unix.RT_TABLE_MAIN, WGTable} {
		rs, err := netlink.RouteListFiltered(netlink.FAMILY_ALL,
			&netlink.Route{LinkIndex: l.Attrs().Index, Table: t}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
	}
	return filterRoutes(all, addrs), nil
}

var linkLocal = netip.MustParsePrefix("fe80::/64")

// filterRoutes retire fe80::/64 et les routes « connected » (proto kernel) des adresses de l'interface.
func filterRoutes(rs []netlink.Route, addrs []netlink.Addr) []netip.Prefix {
	own := map[netip.Prefix]bool{}
	for _, a := range addrs {
		if p, ok := toPrefix(a.IPNet, 0); ok {
			own[p.Masked()] = true
		}
	}
	var out []netip.Prefix
	for _, r := range rs {
		p, ok := toPrefix(r.Dst, r.Family)
		if !ok || p == linkLocal || (r.Protocol == unix.RTPROT_KERNEL && own[p]) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// toPrefix convertit un IPNet ; nil = route par défaut de la famille fam.
func toPrefix(n *net.IPNet, fam int) (netip.Prefix, bool) {
	if n == nil {
		if fam == unix.AF_INET6 {
			return netip.PrefixFrom(netip.IPv6Unspecified(), 0), true
		}
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0), true
	}
	ip, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	ip = ip.Unmap()
	if ip.Is4() && len(n.Mask) == net.IPv6len {
		ones -= 96 // masque sur 16 octets
	}
	return netip.PrefixFrom(ip, ones), true
}

// WatchGone renvoie un canal fermé quand l'interface disparaît (ou si ctx est annulé).
func WatchGone(ctx context.Context, iface string) <-chan struct{} {
	gone := make(chan struct{})
	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(ch, done); err != nil {
		close(gone)
		return gone
	}
	go func() {
		defer close(gone)
		defer close(done)
		// abonné d'abord, puis vérification : pas de fenêtre manquée
		if !Exists(iface) {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case u, ok := <-ch:
				if !ok || (u.Header.Type == unix.RTM_DELLINK && u.Attrs().Name == iface) {
					return
				}
			}
		}
	}()
	return gone
}
