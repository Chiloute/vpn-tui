package nft

// Integration tests, rootless in a fresh user+net namespace:
//
//	unshare -Urn go test -count=1 ./daemon/internal/nft/
//
// Skipped without CAP_NET_ADMIN or without the nft binary in PATH.

import (
	"net"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/vishvananda/netlink"
)

func needNetns(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft absent")
	}
	if err := DeleteTable(); err != nil {
		t.Skipf("pas de CAP_NET_ADMIN / nftables (%v)", err)
	}
}

func nftRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("nft %v: %v\n%s", args, err, out)
	}
	return string(out)
}

var (
	handleRe = regexp.MustCompile(` # handle \d+`)
	setRe    = regexp.MustCompile(`\{ ([^}]*) \}`)
)

// norm hides cosmetic nft differences: handles, indentation, priority
// spelling and set element order.
func norm(s string) string {
	s = handleRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "priority filter - 10", "priority -10")
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		l = setRe.ReplaceAllStringFunc(l, func(m string) string {
			e := strings.Split(m[2:len(m)-2], ", ")
			slices.Sort(e)
			return "{ " + strings.Join(e, ", ") + " }"
		})
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func TestApplyMatchesRender(t *testing.T) {
	needNetns(t)
	t.Cleanup(func() { DeleteTable() })
	nftRun(t, "add", "table", "inet", "autre")
	nftRun(t, "add", "chain", "inet", "autre", "c", "{ type filter hook input priority 0; }")
	nftRun(t, "add", "rule", "inet", "autre", "c", "counter")
	other := nftRun(t, "list", "table", "inet", "autre")

	fw := New()
	for name, c := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			var err error
			if c.m == Armed {
				err = fw.Arm(c.s)
			} else {
				err = fw.Lock(c.s)
			}
			if err != nil {
				t.Fatal(err)
			}
			rs, _ := Build(c.s, c.m)
			got, want := norm(nftRun(t, "list", "table", "inet", TableName)), norm(rs.Render())
			if got != want {
				t.Errorf("nft list != Render\n--- list\n%s\n--- render\n%s", got, want)
			}
			if ok, err := TableExists(); err != nil || !ok {
				t.Errorf("TableExists = %v, %v", ok, err)
			}
		})
	}
	for range 2 { // idempotent
		if err := fw.Disarm(); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := TableExists(); err != nil || ok {
		t.Errorf("TableExists after Disarm = %v, %v", ok, err)
	}
	if got := nftRun(t, "list", "table", "inet", "autre"); got != other {
		t.Errorf("autre table modified:\n%s\n!=\n%s", got, other)
	}
}

func dummy(t *testing.T, name, addr string) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		t.Skipf("dummy: %v", err)
	}
	l, _ := netlink.LinkByName(name)
	a, _ := netlink.ParseAddr(addr)
	if err := netlink.AddrAdd(l, a); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(l); err != nil {
		t.Fatal(err)
	}
}

func udpSend(ip string) error {
	c, err := net.Dial("udp", ip+":51820")
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write([]byte("x"))
	return err
}

func TestBehavior(t *testing.T) {
	needNetns(t)
	t.Cleanup(func() { DeleteTable() })
	dummy(t, "tun0", "10.10.0.1/16")   // tunnel: scope 10.10/16 reachable here
	dummy(t, "eth0", "203.0.113.1/24") // clear-text link: endpoint
	dummy(t, "eth1", "10.20.0.1/16")   // scope leak path (not the tunnel)

	s := spec(true, false, false, []string{"10.10.0.0/16", "10.20.0.0/16"}, nil, state.Endpoint{IP: netip4("203.0.113.7"), Port: 51820, Proto: "udp"})
	fw := New()
	check := func(step string, wantScope10, wantScope20, wantEP bool) {
		t.Helper()
		for ip, want := range map[string]bool{"10.10.0.5": wantScope10, "10.20.0.5": wantScope20, "203.0.113.7": wantEP} {
			if err := udpSend(ip); (err == nil) != want {
				t.Errorf("%s: send %s err=%v, want ok=%v", step, ip, err, want)
			}
		}
	}
	check("sans règles", true, true, true)
	if err := fw.Lock(s); err != nil {
		t.Fatal(err)
	}
	check("locked", false, false, true)
	s.Iface = "tun0"
	if err := fw.Arm(s); err != nil {
		t.Fatal(err)
	}
	check("armed", true, false, true) // only the tunnel reaches the scope
	if err := fw.Disarm(); err != nil {
		t.Fatal(err)
	}
	check("disarmed", true, true, true)
}
