// Intégration (netns rootless) : nix develop -c unshare -Urn go test ./daemon/internal/driver/
// Sans CAP_NET_ADMIN (ou sans nft) les tests sont skippés.
package driver

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
	"github.com/Chiloute/vpn-tui/daemon/internal/nft"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWatchHandshake(t *testing.T) {
	base := time.Unix(1000, 0)
	type env struct {
		clock, hs, tx atomic.Int64 // seconds / seconds (0 = none) / bytes
	}
	run := func(e *env) (<-chan struct{}, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		return watchHandshake(ctx, func() time.Time {
			if v := e.hs.Load(); v != 0 {
				return base.Add(time.Duration(v) * time.Second)
			}
			return time.Time{}
		}, func() uint64 { return uint64(e.tx.Load()) }, base, 180*time.Second, time.Millisecond,
			func() time.Time { return base.Add(time.Duration(e.clock.Load()) * time.Second) }), cancel
	}
	dies := func(dead <-chan struct{}) bool {
		select {
		case <-dead:
			return true
		case <-time.After(60 * time.Millisecond):
			return false
		}
	}
	e := &env{}
	e.tx.Store(100)
	dead, cancel := run(e)
	defer cancel()
	e.clock.Store(1000) // inactif, très vieux, rien émis : pas de chute
	if dies(dead) {
		t.Fatal("tunnel inactif déclaré mort")
	}
	e.tx.Store(200) // données émises sans session valide
	if !dies(dead) {
		t.Fatal("trafic émis sans handshake non détecté")
	}

	e = &env{} // handshake récent + trafic : pas de chute
	e.hs.Store(900)
	e.clock.Store(1000)
	e.tx.Store(1)
	dead, cancel2 := run(e)
	defer cancel2()
	e.tx.Store(999)
	if dies(dead) {
		t.Fatal("handshake récent déclaré mort")
	}
	e.hs.Store(950) // nouveau handshake : base remise à zéro
	e.clock.Store(1129)
	e.tx.Store(5000)
	if dies(dead) {
		t.Fatal("chute malgré handshake récent")
	}
	e.clock.Store(1131) // 181s après 950, trafic émis depuis
	e.tx.Store(6000)
	if !dies(dead) {
		t.Fatal("handshake périmé + trafic non détecté")
	}
}

func needNetns(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft absent")
	}
	probe := netlink.NewLinkAttrs()
	probe.Name = "wgprobe0"
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: probe}); err != nil {
		t.Skipf("pas de CAP_NET_ADMIN/wireguard : %v", err)
	}
	pl, _ := netlink.LinkByName("wgprobe0")
	netlink.LinkDel(pl)
	nft.DeleteTable()
	t.Cleanup(func() { nft.DeleteTable() })
}

func nftList(t *testing.T) string {
	t.Helper()
	out, _ := exec.Command("nft", "list", "table", "inet", "vpn_tui").CombinedOutput()
	return string(out)
}

func waitFor(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("délai dépassé : %s", what)
}

// lab: a WireGuard "server" on the loopback of the netns and a profile pointing at it.
func lab(t *testing.T) (*profile.Store, *profile.Profile, string, wgtypes.Key, wgtypes.Key) {
	t.Helper()
	lo, _ := netlink.LinkByName("lo")
	netlink.LinkSetUp(lo)
	srvKey, _ := wgtypes.GeneratePrivateKey()
	cliKey, _ := wgtypes.GeneratePrivateKey()
	la := netlink.NewLinkAttrs()
	la.Name = "wgsrv"
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l, _ := netlink.LinkByName("wgsrv"); netlink.LinkDel(l) })
	wc, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { wc.Close() })
	port := 51821
	_, cidr, _ := net.ParseCIDR("10.200.0.2/32")
	if err := wc.ConfigureDevice("wgsrv", wgtypes.Config{PrivateKey: &srvKey, ListenPort: &port,
		Peers: []wgtypes.PeerConfig{{PublicKey: cliKey.PublicKey(), AllowedIPs: []net.IPNet{*cidr}}}}); err != nil {
		t.Fatal(err)
	}
	l, _ := netlink.LinkByName("wgsrv")
	a, _ := netlink.ParseAddr("10.200.0.1/24")
	netlink.AddrAdd(l, a)
	netlink.LinkSetUp(l)

	conf := fmt.Sprintf("[Interface]\nPrivateKey = @keyring\nAddress = 10.200.0.2/32\n\n[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:%d\nAllowedIPs = 10.200.0.0/24\nPersistentKeepalive = 1\n",
		srvKey.PublicKey(), port)
	st := &profile.Store{Root: t.TempDir()}
	st.Init()
	p, err := st.Import("wireguard", "wg", "wg1", conf)
	if err != nil {
		t.Fatal(err)
	}
	return st, p, cliKey.String(), srvKey, cliKey
}

func netnsManager(t *testing.T, st *profile.Store) *state.Manager {
	old := teardownDelay
	teardownDelay = 200 * time.Millisecond
	t.Cleanup(func() { teardownDelay = old })
	m := &state.Manager{
		Drivers: map[string]state.Driver{"wireguard": WireGuard{Store: st, HandshakeTimeout: 2 * time.Second, CheckEvery: 100 * time.Millisecond}},
		FW:      nft.New(), StatePath: filepath.Join(t.TempDir(), "state.json"), MarkerPath: filepath.Join(t.TempDir(), "armed.json"),
	}
	m.Sleep = func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() } // no reconnection here
	m.Reconnect.MaxAttempts = 1
	t.Cleanup(func() { m.PanicOff() })
	return m
}

func TestKillSwitchNetns(t *testing.T) {
	needNetns(t)
	st, p, priv, _, cliKey := lab(t)
	m := netnsManager(t, st)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.Up(ctx, p, state.Secrets{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	if out := nftList(t); !strings.Contains(out, `oifname "vpntui0" accept`) {
		t.Fatalf("pas armed :\n%s", out)
	}
	if s := m.Status(); s.State != state.Armed {
		t.Fatalf("%+v", s)
	}

	// le serveur oublie le peer : plus de handshake → Dead → verrou
	wc, _ := wgctrl.New()
	defer wc.Close()
	if err := wc.ConfigureDevice("wgsrv", wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: cliKey.PublicKey(), Remove: true}}}); err != nil {
		t.Fatal(err)
	}
	go func() { // du trafic émis sans session valide déclenche la chute
		c, err := net.Dial("udp", "10.200.0.1:9")
		if err != nil {
			return
		}
		defer c.Close()
		for i := 0; i < 150; i++ {
			c.Write([]byte("x"))
			time.Sleep(100 * time.Millisecond)
		}
	}()
	waitFor(t, "table verrouillée", 15*time.Second, func() bool {
		out := nftList(t)
		return out != "" && !strings.Contains(out, `oifname "vpntui0" accept`)
	})
	if out := nftList(t); !strings.Contains(out, "drop") || !strings.Contains(out, `oifname "lo" accept`) {
		t.Fatalf("pas locked :\n%s", out)
	}
	if s := m.Status().State; s != state.Reconnecting && s != state.Locked {
		t.Fatalf("état %s", s)
	}
	// l'interface morte ne traîne pas
	waitFor(t, "interface démontée", 5*time.Second, func() bool { return !netinfo.Exists(Iface) })
}

func TestPanicOffNetns(t *testing.T) {
	needNetns(t)
	st, p, priv, _, _ := lab(t)
	m := netnsManager(t, st)
	if err := m.Up(context.Background(), p, state.Secrets{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nftList(t), `oifname "vpntui0" accept`) || !netinfo.Exists(Iface) {
		t.Fatal("pas armed")
	}
	if err := m.PanicOff(); err != nil {
		t.Fatal(err)
	}
	if ok, err := nft.TableExists(); ok || err != nil {
		t.Fatalf("table encore là : %v %v", ok, err)
	}
	if netinfo.Exists(Iface) {
		t.Fatal("interface encore là après panic_off")
	}
}

func TestWireGuardAdoptNetns(t *testing.T) {
	needNetns(t)
	st, p, priv, _, _ := lab(t)
	d := WireGuard{Store: st}
	eps, err := d.Endpoints(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Adopt(context.Background(), p, Iface, 0); err == nil {
		t.Fatal("adoption sans interface")
	}
	tun, _, err := d.Up(context.Background(), p, state.Secrets{PrivateKey: priv}, eps)
	if err != nil {
		t.Fatal(err)
	}
	adopted, info, err := d.Adopt(context.Background(), p, Iface, 0)
	if err != nil {
		t.Fatal(err)
	}
	if info.Iface != Iface || info.LHOST.String() != "10.200.0.2" || len(info.Learned) != 1 || info.Learned[0].String() != "10.200.0.0/24" {
		t.Fatalf("%+v", info)
	}
	_ = tun
	if err := adopted.Down(); err != nil {
		t.Fatal(err)
	}
	if netinfo.Exists(Iface) {
		t.Fatal("interface encore là")
	}
}
