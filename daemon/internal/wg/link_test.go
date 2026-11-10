// Integration tests (two netns linked by a veth) run with:
//
//	unshare -Urn go test ./daemon/internal/wg/ ./daemon/internal/netinfo/
//
// Without CAP_NET_ADMIN they are skipped; unit tests run everywhere.
package wg

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func pfx(s ...string) []netip.Prefix {
	var o []netip.Prefix
	for _, x := range s {
		o = append(o, netip.MustParsePrefix(x))
	}
	return o
}

func TestBuildConfig(t *testing.T) {
	priv, _ := wgtypes.GeneratePrivateKey()
	pub := priv.PublicKey().String()
	psk, _ := wgtypes.GenerateKey()
	c := &Config{ListenPort: 1234, Peers: []Peer{
		{PublicKey: pub, AllowedIPs: pfx("10.0.0.0/24"), PersistentKeepalive: 25, HasPresharedKey: true},
		{PublicKey: pub, AllowedIPs: pfx("10.1.0.0/24")},
	}}
	eps := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:51820"), {}}
	cfg, err := buildConfig(c, priv.String(), psk.String(), eps, fwmark)
	if err != nil {
		t.Fatal(err)
	}
	p0, p1 := cfg.Peers[0], cfg.Peers[1]
	if *cfg.FirewallMark != fwmark || *cfg.ListenPort != 1234 || p0.Endpoint.String() != "192.0.2.1:51820" ||
		p0.PresharedKey == nil || p1.PresharedKey != nil || p1.Endpoint != nil ||
		*p0.PersistentKeepaliveInterval != 25*time.Second || p0.AllowedIPs[0].String() != "10.0.0.0/24" {
		t.Fatalf("unexpected config : %+v", cfg)
	}
	// errors do not leak secrets
	_, err = buildConfig(c, "SECRETSECRET", psk.String(), eps, 0)
	if err == nil || strings.Contains(err.Error(), "SECRETSECRET") {
		t.Fatalf("err = %v", err)
	}
	if _, err = buildConfig(c, priv.String(), "PSKSECRET", eps, 0); err == nil || strings.Contains(err.Error(), "PSKSECRET") {
		t.Fatalf("err = %v", err)
	}
	if _, err = buildConfig(c, priv.String(), psk.String(), eps[:1], 0); err == nil {
		t.Fatal("inconsistent endpoints/peers accepted")
	}
}

func TestFullFamilies(t *testing.T) {
	for _, tc := range []struct {
		ips  []string
		want int
	}{{[]string{"10.0.0.0/8"}, 0}, {[]string{"0.0.0.0/0"}, 1}, {[]string{"0.0.0.0/0", "::/0"}, 2}, {[]string{"::/0"}, 1}} {
		c := &Config{Peers: []Peer{{AllowedIPs: pfx(tc.ips...)}}}
		if got := fullFamilies(c); len(got) != tc.want {
			t.Errorf("%v : %v", tc.ips, got)
		}
	}
}

func TestResolve(t *testing.T) {
	c := &Config{Peers: []Peer{{Endpoint: "192.0.2.7:51820"}, {}, {Endpoint: "[2001:db8::1]:9"}}}
	got, err := Resolve(context.Background(), c)
	if err != nil || got[0].String() != "192.0.2.7:51820" || got[1].IsValid() || got[2].String() != "[2001:db8::1]:9" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := Resolve(context.Background(), &Config{Peers: []Peer{{Endpoint: "nonexistent.invalid:1"}}}); err == nil {
		t.Fatal("unresolvable endpoint accepted")
	}
}

// --- integration ---

// inNS runs fn in a locked thread placed in ns; the thread is never
// returned to the runtime (it ends with the goroutine) so it pollutes no other test.
func inNS(t *testing.T, ns netns.NsHandle, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer close(done)
		if ns.IsOpen() {
			if err := netns.Set(ns); err != nil {
				t.Error(err)
				return
			}
		}
		fn()
	}()
	<-done
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

const (
	srvPort = 51821
	echoAP  = "10.200.0.1:9999"
)

// topo creates the second netns, the veth (10.99.0.1 <-> 10.99.0.2), a WireGuard server
// (10.200.0.1, port 51821) and a UDP echo on echoAP. Returns the server public key
// and the client private key (the server allows 10.200.0.2/32).
func topo(t *testing.T) (srvPub wgtypes.Key, cliPriv wgtypes.Key) {
	t.Helper()
	probe := netlink.NewLinkAttrs()
	probe.Name = "wgprobe0"
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: probe}); err != nil {
		t.Skipf("no CAP_NET_ADMIN/wireguard: %v", err)
	}
	pl, _ := netlink.LinkByName("wgprobe0")
	must(t, netlink.LinkDel(pl))

	var ns2 netns.NsHandle
	inNS(t, netns.None(), func() { // throwaway thread: netns.New switches the thread into it
		var err error
		ns2, err = netns.New()
		must2(t, err)
	})
	t.Cleanup(func() { ns2.Close() })

	la := netlink.NewLinkAttrs()
	la.Name = "vt0"
	must(t, netlink.LinkAdd(&netlink.Veth{LinkAttrs: la, PeerName: "vt1", PeerNamespace: netlink.NsFd(int(ns2))}))
	t.Cleanup(func() {
		if l, err := netlink.LinkByName("vt0"); err == nil {
			netlink.LinkDel(l)
		}
	})
	l0, _ := netlink.LinkByName("vt0")
	a, _ := netlink.ParseAddr("10.99.0.1/24")
	must(t, netlink.AddrAdd(l0, a))
	must(t, netlink.LinkSetUp(l0))

	srvPriv, _ := wgtypes.GeneratePrivateKey()
	cliPriv, _ = wgtypes.GeneratePrivateKey()
	var echo *net.UDPConn
	inNS(t, ns2, func() {
		lo, _ := netlink.LinkByName("lo")
		must2(t, netlink.LinkSetUp(lo))
		l1, err := netlink.LinkByName("vt1")
		must2(t, err)
		a, _ := netlink.ParseAddr("10.99.0.2/24")
		must2(t, netlink.AddrAdd(l1, a))
		must2(t, netlink.LinkSetUp(l1))
		wa := netlink.NewLinkAttrs()
		wa.Name = "wgsrv"
		must2(t, netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: wa}))
		wl, _ := netlink.LinkByName("wgsrv")
		a, _ = netlink.ParseAddr("10.200.0.1/24")
		must2(t, netlink.AddrAdd(wl, a))
		port := srvPort
		wc, err := wgctrl.New()
		must2(t, err)
		defer wc.Close()
		must2(t, wc.ConfigureDevice("wgsrv", wgtypes.Config{PrivateKey: &srvPriv, ListenPort: &port, Peers: []wgtypes.PeerConfig{{
			PublicKey:  cliPriv.PublicKey(),
			AllowedIPs: []net.IPNet{{IP: net.IPv4(10, 200, 0, 2), Mask: net.CIDRMask(32, 32)}},
		}}}))
		must2(t, netlink.LinkSetUp(wl))
		echo, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(echoAP)))
		must2(t, err)
	})
	if t.Failed() {
		t.FailNow()
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], from)
		}
	}()
	return srvPriv.PublicKey(), cliPriv
}

func must2(t *testing.T, err error) {
	if err != nil {
		t.Error(err)
	}
}

func echoRoundTrip(t *testing.T) {
	t.Helper()
	c, err := net.Dial("udp4", echoAP)
	must(t, err)
	defer c.Close()
	buf := make([]byte, 8)
	for i := 0; i < 8; i++ {
		c.Write([]byte("ping"))
		c.SetReadDeadline(time.Now().Add(time.Second))
		if n, err := c.Read(buf); err == nil && string(buf[:n]) == "ping" {
			return
		}
	}
	t.Fatal("no response through the tunnel")
}

func hasRules(t *testing.T) bool {
	t.Helper()
	rs, err := netlink.RuleList(netlink.FAMILY_V4)
	must(t, err)
	for _, r := range rs {
		if r.Table == fwmark {
			return true
		}
	}
	return false
}

func has(ps []netip.Prefix, want string) bool {
	for _, p := range ps {
		if p.String() == want {
			return true
		}
	}
	return false
}

func integration(t *testing.T, allowed []string, full bool) {
	srvPub, cliPriv := topo(t)
	psk := ""
	c := &Config{
		Addresses: pfx("10.200.0.2/32"),
		MTU:       1380,
		Peers: []Peer{{
			PublicKey:           srvPub.String(),
			Endpoint:            "10.99.0.2:51821",
			AllowedIPs:          pfx(allowed...),
			PersistentKeepalive: 5,
		}},
	}
	eps, err := Resolve(context.Background(), c)
	must(t, err)
	l, err := Up(context.Background(), "wgcli0", c, cliPriv.String(), psk, eps)
	must(t, err)
	defer l.Down()

	echoRoundTrip(t)
	if ip, err := netinfo.IPv4("wgcli0"); err != nil || ip.String() != "10.200.0.2" {
		t.Fatalf("IPv4 = %v, %v", ip, err)
	}
	rs, err := netinfo.Routes("wgcli0")
	must(t, err)
	for _, a := range allowed {
		if !has(rs, a) {
			t.Fatalf("Routes %v does not contain %s", rs, a)
		}
	}
	if rx, tx := l.Stats(); rx == 0 || tx == 0 {
		t.Fatalf("Stats = %d/%d", rx, tx)
	}
	if l.LastHandshake().IsZero() {
		t.Fatal("no handshake")
	}
	if got := hasRules(t); got != full {
		t.Fatalf("fwmark rules present = %v, want %v", got, full)
	}

	gone := netinfo.WatchGone(context.Background(), "wgcli0")
	must(t, l.Down())
	select {
	case <-gone:
	case <-time.After(3 * time.Second):
		t.Fatal("WatchGone not triggered")
	}
	if netinfo.Exists("wgcli0") || hasRules(t) {
		t.Fatal("leftover interface or rules after Down")
	}
	must(t, l.Down()) // idempotent
}

func TestIntegrationSplit(t *testing.T) {
	integration(t, []string{"10.200.0.1/32", "192.168.77.0/24"}, false)
}

func TestIntegrationFullTunnel(t *testing.T) {
	integration(t, []string{"0.0.0.0/0"}, true)
}

func TestUpErrorCleansUp(t *testing.T) {
	topo(t)
	c := &Config{Addresses: pfx("10.200.0.9/32"), Peers: []Peer{{PublicKey: wgtypes.Key{1}.String(), AllowedIPs: pfx("0.0.0.0/0")}}}
	priv, _ := wgtypes.GeneratePrivateKey()
	// invalid prefix: the failure happens after the interface is created
	c.Addresses = append(c.Addresses, netip.Prefix{})
	if _, err := Up(context.Background(), "wgbad0", c, priv.String(), "", []netip.AddrPort{{}}); err == nil {
		t.Fatal("error expected")
	}
	if netinfo.Exists("wgbad0") || hasRules(t) {
		t.Fatal("nothing must remain after a failed Up")
	}
}
