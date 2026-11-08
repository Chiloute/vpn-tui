package nft

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
)

var update = flag.Bool("update", false, "regenerate golden files")

func spec(allow, v6, dns bool, cidrs, excl []string, eps ...state.Endpoint) state.Spec {
	return state.Spec{
		Iface:     "tun0",
		Endpoints: eps,
		Profile: &profile.Profile{
			Scope:      profile.Scope{CIDRs: cidrs, Exclude: excl},
			Killswitch: profile.Killswitch{Enabled: true, AllowInternet: allow, BlockIPv6: v6},
			DNS:        profile.DNS{Force: dns},
		},
	}
}

var (
	ep4  = state.Endpoint{IP: netip.MustParseAddr("203.0.113.7"), Port: 51820, Proto: "udp"}
	ep6  = state.Endpoint{IP: netip.MustParseAddr("2001:db8::7"), Port: 443, Proto: "tcp"}
	v4   = []string{"10.10.0.0/16"}
	both = []string{"10.10.0.0/16", "172.16.0.0/12", "fd00:10::/32"}
)

func goldenCases() map[string]struct {
	s state.Spec
	m Mode
} {
	type c = struct {
		s state.Spec
		m Mode
	}
	out := map[string]c{
		"locked":          {spec(true, true, true, v4, nil, ep4, ep6), Locked},
		"locked_no_ep":    {spec(true, true, true, v4, nil), Locked},
		"armed_no_scope":  {spec(false, true, false, nil, nil, ep4), Armed},
		"armed_dual_excl": {spec(true, false, false, both, []string{"10.10.5.0/24", "fd00:10:1::/48"}, ep4), Armed},
		"armed_endpoints": {spec(true, false, false, v4, nil, ep4, ep6, state.Endpoint{IP: ep4.IP, Port: 1194, Proto: "tcp"}, state.Endpoint{IP: ep6.IP, Port: 51820, Proto: "udp"}), Armed},
	}
	for i := range 8 {
		a, v, d := i&1 != 0, i&2 != 0, i&4 != 0
		out[fmt.Sprintf("armed_allow%t_v6%t_dns%t", a, v, d)] = c{spec(a, v, d, v4, nil, ep4), Armed}
	}
	return out
}

func TestGolden(t *testing.T) {
	for name, c := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			rs, err := Build(c.s, c.m)
			if err != nil {
				t.Fatal(err)
			}
			got := rs.Render()
			p := filepath.Join("testdata", name+".nft")
			if *update {
				if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("golden %s differs:\n%s", p, got)
			}
		})
	}
}

func TestBuildErrors(t *testing.T) {
	bad := map[string]state.Spec{
		"nil profile":  {Iface: "tun0"},
		"empty iface":  func() state.Spec { s := spec(true, true, true, v4, nil); s.Iface = ""; return s }(),
		"quote iface":  func() state.Spec { s := spec(true, true, true, v4, nil); s.Iface = `a" drop`; return s }(),
		"bad cidr":     spec(true, true, true, []string{"nope"}, nil),
		"bad exclude":  spec(true, true, true, v4, []string{"1.2.3.4/99"}),
		"bad endpoint": spec(true, true, true, v4, nil, state.Endpoint{Port: 1, Proto: "udp"}),
		"bad port":     spec(true, true, true, v4, nil, state.Endpoint{IP: ep4.IP, Port: 0, Proto: "udp"}),
		"bad proto":    spec(true, true, true, v4, nil, state.Endpoint{IP: ep4.IP, Port: 1, Proto: "icmp"}),
	}
	for n, s := range bad {
		if _, err := Build(s, Armed); err == nil {
			t.Errorf("%s: err=%v", n, err)
		}
	}
	// locked ignores the interface and tolerates no endpoint
	if _, err := Build(spec(true, true, true, v4, nil), Locked); err != nil {
		t.Error(err)
	}
	if rs, _ := Build(spec(true, true, true, []string{"10.0.0.0/8", "10.1.0.0/16", "10.0.0.0/8"}, nil), Armed); !strings.Contains(rs.Render(), "ip daddr { 10.0.0.0/8 } drop") {
		t.Errorf("not normalized:\n%s", rs.Render())
	}
}

func netip4(s string) netip.Addr { return netip.MustParseAddr(s) }
