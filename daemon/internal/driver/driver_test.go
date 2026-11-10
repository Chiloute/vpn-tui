// Intégration (netns rootless) : unshare -Urn go test ./daemon/internal/driver/
// Sans CAP_NET_ADMIN le test est skippé.
package driver

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/Chiloute/vpn-tui/daemon/internal/wg"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWireGuardUpDown(t *testing.T) {
	probe := netlink.NewLinkAttrs()
	probe.Name = "wgprobe0"
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: probe}); err != nil {
		t.Skipf("pas de CAP_NET_ADMIN/wireguard : %v", err)
	}
	pl, _ := netlink.LinkByName("wgprobe0")
	netlink.LinkDel(pl)

	priv, _ := wgtypes.GeneratePrivateKey()
	peer, _ := wgtypes.GeneratePrivateKey()
	conf := fmt.Sprintf("[Interface]\nPrivateKey = @keyring\nAddress = 10.200.0.2/32\n\n[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 10.200.0.0/24, 10.201.0.0/16\n",
		peer.PublicKey())
	st := &profile.Store{Root: t.TempDir()}
	st.Init()
	p, err := st.Import("wireguard", "wg", "wg1", conf)
	if err != nil {
		t.Fatal(err)
	}
	m := &state.Manager{Drivers: map[string]state.Driver{"wireguard": WireGuard{Store: st, HandshakeWait: 300 * time.Millisecond}}, FW: state.NoopFirewall{},
		StatePath: filepath.Join(t.TempDir(), "state.json")}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := m.Up(ctx, p, state.Secrets{}); err == nil {
		t.Fatal("up sans clé privée accepté")
	}
	if netinfo.Exists(Iface) {
		t.Fatal("interface créée malgré l'échec")
	}
	// peer injoignable (192.0.2.1) : pas de handshake -> échec, tout est défait (le succès est couvert en netns)
	err = m.Up(ctx, p, state.Secrets{PrivateKey: priv.String()})
	if !errors.Is(err, wg.ErrNoHandshake) {
		t.Fatalf("up sans peer : %v", err)
	}
	if netinfo.Exists(Iface) || m.Status().State != state.Locked { // kill switch: échec d'up -> verrouillé
		t.Fatalf("résidu après échec de handshake : %v %+v", netinfo.Exists(Iface), m.Status())
	}
}
