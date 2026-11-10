// Real netlink tests: `unshare -Urn go test ./daemon/internal/netinfo/`
// (skipped without CAP_NET_ADMIN).
package netinfo

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func ipn(s string) *net.IPNet {
	_, n, _ := net.ParseCIDR(s)
	return n
}

func TestFilterRoutes(t *testing.T) {
	a, _ := netlink.ParseAddr("10.0.0.2/24")
	rs := []netlink.Route{
		{Dst: ipn("10.0.0.0/24"), Protocol: unix.RTPROT_KERNEL, Family: unix.AF_INET}, // connected
		{Dst: ipn("10.0.0.0/24"), Protocol: unix.RTPROT_BOOT, Family: unix.AF_INET},   // identical AllowedIP: kept
		{Dst: ipn("fe80::/64"), Protocol: unix.RTPROT_KERNEL, Family: unix.AF_INET6},  // link-local
		{Dst: ipn("192.168.1.0/24"), Family: unix.AF_INET},
		{Dst: nil, Family: unix.AF_INET6},
	}
	got := filterRoutes(rs, []netlink.Addr{*a})
	want := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("::/0")}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestDummyLink(t *testing.T) {
	la := netlink.NewLinkAttrs()
	la.Name = "nitest0"
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: la}); err != nil {
		t.Skipf("no CAP_NET_ADMIN: %v", err)
	}
	l, _ := netlink.LinkByName("nitest0")
	defer netlink.LinkDel(l)
	a, _ := netlink.ParseAddr("10.77.0.1/24")
	if err := netlink.AddrAdd(l, a); err != nil {
		t.Fatal(err)
	}
	netlink.LinkSetUp(l)
	if ip, err := IPv4("nitest0"); err != nil || ip.String() != "10.77.0.1" {
		t.Fatalf("IPv4 = %v, %v", ip, err)
	}
	rs, err := Routes("nitest0")
	if err != nil || len(rs) != 0 { // only the connected route: filtered
		t.Fatalf("Routes = %v, %v", rs, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gone := WatchGone(ctx, "nitest0")
	select {
	case <-gone:
		t.Fatal("closed too early")
	case <-time.After(100 * time.Millisecond):
	}
	netlink.LinkDel(l)
	select {
	case <-gone:
	case <-time.After(3 * time.Second):
		t.Fatal("WatchGone did not trigger")
	}
	if Exists("nitest0") {
		t.Fatal("still exists")
	}
}
