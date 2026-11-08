// Package nft builds the kill switch ruleset (pure) and applies it atomically
// through netlink, only ever touching the table "inet vpn_tui".
package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Chiloute/vpn-tui/daemon/internal/state"
)

// Mode selects the ruleset flavour.
type Mode int

const (
	Armed  Mode = iota // tunnel up: scope only reachable through the tunnel
	Locked             // tunnel down/unknown: only lo and VPN endpoints
)

// TableName is the only table this package ever touches.
const TableName = "vpn_tui"

// Rule is the single intermediate representation: every non-zero field is a
// match (ANDed, rendered in this order), Drop selects the verdict.
type Rule struct {
	Oif      string         // oifname "<Oif>"
	IPv6Only bool           // meta nfproto ipv6
	Daddr    []netip.Prefix // ip/ip6 daddr { set } (single family)
	NotDaddr []netip.Prefix // ip/ip6 daddr != { set } (same family as Daddr)
	Host     netip.Addr     // ip/ip6 daddr <addr>
	Proto    string         // "udp" | "tcp"; requires Ports
	Ports    []int          // <proto> dport <port | { ports }>
	Drop     bool
}

type Ruleset struct{ Output, Forward []Rule }

var ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_.@:-]{1,15}$`)

func accept(r Rule) Rule { return r }
func drop(r Rule) Rule   { r.Drop = true; return r }

// normalize sorts, dedups and drops prefixes covered by another one.
func normalize(ps []netip.Prefix) []netip.Prefix {
	ps = slices.Clone(ps)
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	var out []netip.Prefix
	for _, p := range ps {
		if n := len(out); n > 0 && out[n-1].Overlaps(p) { // sorted: previous one is the wider
			continue
		}
		out = append(out, p)
	}
	return out
}

func parsePrefixes(what string, l []string) (v4, v6 []netip.Prefix, err error) {
	for _, c := range l {
		p, err := netip.ParsePrefix(c)
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return nil, nil, fmt.Errorf("nft: %s : CIDR invalide %q", what, c)
		}
		if p = p.Masked(); p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return normalize(v4), normalize(v6), nil
}

// Build is pure: it validates the spec and returns the ruleset, no I/O.
func Build(s state.Spec, m Mode) (Ruleset, error) {
	if s.Profile == nil {
		return Ruleset{}, errors.New("nft: profil manquant")
	}
	if m != Armed && m != Locked {
		return Ruleset{}, errors.New("nft: mode inconnu")
	}
	var eps []Rule
	for _, e := range s.Endpoints {
		ip := e.IP.Unmap()
		if !ip.IsValid() || ip.Zone() != "" || e.Port < 1 || e.Port > 65535 || (e.Proto != "udp" && e.Proto != "tcp") {
			return Ruleset{}, fmt.Errorf("nft: endpoint invalide %v", e)
		}
		eps = append(eps, accept(Rule{Host: ip, Proto: e.Proto, Ports: []int{e.Port}}))
	}
	lo := accept(Rule{Oif: "lo"})

	if m == Locked {
		return Ruleset{
			Output:  append(append([]Rule{lo}, eps...), drop(Rule{})),
			Forward: []Rule{drop(Rule{})},
		}, nil
	}

	if !ifaceRe.MatchString(s.Iface) {
		return Ruleset{}, fmt.Errorf("nft: interface invalide %q (armed sans tunnel interdit)", s.Iface)
	}
	k, sc := s.Profile.Killswitch, s.Profile.Scope
	s4, s6, err := parsePrefixes("scope.cidrs", sc.CIDRs)
	if err != nil {
		return Ruleset{}, err
	}
	x4, x6, err := parsePrefixes("scope.exclude", sc.Exclude)
	if err != nil {
		return Ruleset{}, err
	}
	var common []Rule // scope + ipv6 block, shared by output and forward
	if len(s4) > 0 {
		common = append(common, drop(Rule{Daddr: s4, NotDaddr: x4}))
	}
	if len(s6) > 0 {
		common = append(common, drop(Rule{Daddr: s6, NotDaddr: x6}))
	}
	if k.BlockIPv6 {
		common = append(common, drop(Rule{IPv6Only: true}))
	}
	tun := accept(Rule{Oif: s.Iface})

	out := append([]Rule{lo, tun}, eps...)
	out = append(out, common...)
	if s.Profile.DNS.Force {
		dns := []int{53, 853}
		out = append(out, drop(Rule{Proto: "udp", Ports: dns}), drop(Rule{Proto: "tcp", Ports: dns}))
	}
	fwd := append([]Rule{tun}, common...)
	if !k.AllowInternet {
		out, fwd = append(out, drop(Rule{})), append(fwd, drop(Rule{}))
	}
	return Ruleset{Output: out, Forward: fwd}, nil
}

func ipTag(a netip.Addr) string {
	if a.Is4() {
		return "ip"
	}
	return "ip6"
}

func setStr(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return "{ " + strings.Join(s, ", ") + " }"
}

func (r Rule) String() string {
	var f []string
	if r.Oif != "" {
		f = append(f, `oifname "`+r.Oif+`"`)
	}
	if r.IPv6Only {
		f = append(f, "meta nfproto ipv6")
	}
	if len(r.Daddr) > 0 {
		f = append(f, ipTag(r.Daddr[0].Addr())+" daddr "+setStr(r.Daddr))
		if len(r.NotDaddr) > 0 {
			f = append(f, ipTag(r.Daddr[0].Addr())+" daddr != "+setStr(r.NotDaddr))
		}
	}
	if r.Host.IsValid() {
		f = append(f, ipTag(r.Host)+" daddr "+r.Host.String())
	}
	if len(r.Ports) == 1 {
		f = append(f, r.Proto+" dport "+strconv.Itoa(r.Ports[0]))
	} else if len(r.Ports) > 1 {
		p := make([]string, len(r.Ports))
		for i, n := range r.Ports {
			p[i] = strconv.Itoa(n)
		}
		f = append(f, r.Proto+" dport { "+strings.Join(p, ", ")+" }")
	}
	if r.Drop {
		f = append(f, "drop")
	} else {
		f = append(f, "accept")
	}
	return strings.Join(f, " ")
}

// Render returns the complete `nft -f` text of the table, deterministic.
func (r Ruleset) Render() string {
	var b strings.Builder
	b.WriteString("table inet " + TableName + " {\n")
	for _, c := range []struct {
		name  string
		rules []Rule
	}{{"output", r.Output}, {"forward", r.Forward}} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority filter - 10; policy accept;\n", c.name, c.name)
		for _, ru := range c.rules {
			b.WriteString("\t\t" + ru.String() + "\n")
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}
