package main

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
	"github.com/Chiloute/vpn-tui/daemon/internal/nft"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/rpc"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/vishvananda/netlink"
)

func testOpts(t *testing.T) opts {
	d := t.TempDir()
	return opts{stateDir: d, runDir: filepath.Join(d, "run"), cacheDir: filepath.Join(d, "cache"),
		marker: filepath.Join(d, "armed.json"), maxAttempts: 1}
}

func TestRestoreLockNoMarker(t *testing.T) {
	if err := restoreLockCmd(testOpts(t)); err != nil {
		t.Fatal(err)
	}
}

func TestPanicOffNetns(t *testing.T) {
	la := netlink.NewLinkAttrs()
	la.Name = "vpntui0"
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: la}); err != nil {
		t.Skipf("no CAP_NET_ADMIN/wireguard: %v", err)
	}
	t.Cleanup(func() { nft.DeleteTable() })
	o := testOpts(t)
	os.MkdirAll(o.runDir, 0o700)
	spec := state.Spec{Profile: &profile.Profile{ID: "x", Killswitch: profile.Killswitch{Enabled: true}}}
	if err := nft.New().Lock(spec); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(o.marker, []byte("{}"), 0o600)
	// pid of a live process that is not openvpn: must be left alone
	os.WriteFile(filepath.Join(o.runDir, "state.json"), []byte(`{"state":"armed","pid":`+strconv.Itoa(os.Getpid())+`}`), 0o600)

	var out bytes.Buffer
	if err := panicOffCmd(o, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if ok, _ := nft.TableExists(); ok || netinfo.Exists("vpntui0") {
		t.Fatal("table or interface still present")
	}
	for _, f := range []string{o.marker, filepath.Join(o.runDir, "state.json")} {
		if _, err := os.Stat(f); err == nil {
			t.Fatalf("%s still present", f)
		}
	}
	if b, _ := os.ReadFile(o.journal()); !strings.Contains(string(b), `"panic_off"`) {
		t.Fatalf("journal: %s", b)
	}
	if !strings.Contains(out.String(), "skip") {
		t.Fatalf("non-openvpn pid not ignored:\n%s", out.String())
	}
	if err := panicOffCmd(o, &out); err != nil { // idempotent
		t.Fatal(err)
	}
}

type fakeFW struct{ calls []string }

func (f *fakeFW) Lock(state.Spec) error { f.calls = append(f.calls, "Lock"); return nil }
func (f *fakeFW) Arm(state.Spec) error  { f.calls = append(f.calls, "Arm"); return nil }
func (f *fakeFW) Disarm() error         { f.calls = append(f.calls, "Disarm"); return nil }

type fakeTun struct{ dead chan struct{} }

func (f fakeTun) Down() error             { f.calls(); return nil }
func (f fakeTun) Dead() <-chan struct{}   { return f.dead }
func (f fakeTun) Stats() (uint64, uint64) { return 0, 0 }
func (f fakeTun) calls()                  { downs.Add(1) }

var downs atomic.Int32

type fakeDrv struct{}

func (fakeDrv) Endpoints(context.Context, *profile.Profile) ([]state.Endpoint, error) {
	return []state.Endpoint{{IP: netip.MustParseAddr("192.0.2.1"), Port: 51820, Proto: "udp"}}, nil
}
func (fakeDrv) Up(context.Context, *profile.Profile, state.Secrets, []state.Endpoint) (state.Tunnel, state.Info, error) {
	return fakeTun{make(chan struct{})}, state.Info{Iface: "vpntui0"}, nil
}

// Stopping the daemon (SIGTERM path) must leave everything armed: no Disarm, no tunnel Down.
func TestExitNeverDisarms(t *testing.T) {
	fw := &fakeFW{}
	m := &state.Manager{Drivers: map[string]state.Driver{"wireguard": fakeDrv{}}, FW: fw}
	p := &profile.Profile{ID: "x", Type: "wireguard", Killswitch: profile.Killswitch{Enabled: true}}
	if err := m.Up(context.Background(), p, state.Secrets{}); err != nil {
		t.Fatal(err)
	}
	srv, _ := rpc.New()
	srv.Mgr = m
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "s.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, srv, ln) }()
	cancel() // SIGTERM
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serve does not return")
	}
	if slices.Contains(fw.calls, "Disarm") || downs.Load() != 0 || m.Status().State != state.Armed {
		t.Fatalf("calls=%v downs=%d state=%s", fw.calls, downs.Load(), m.Status().State)
	}
}
