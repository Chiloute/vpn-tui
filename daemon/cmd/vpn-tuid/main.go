// Command vpn-tuid is the privileged VPN daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/driver"
	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/rpc"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
)

var version = "dev"

func main() {
	socket := flag.String("socket", "/run/vpn-tui/vpn-tuid.sock", "unix socket path (ignored under systemd activation)")
	group := flag.String("group", "vpn-tui", "group allowed to connect")
	idle := flag.Duration("idle-timeout", 60*time.Second, "exit after this long without connection")
	stateDir := flag.String("state-dir", "/var/lib/vpn-tui", "state directory (profiles live in <state-dir>/profiles)")
	runDir := flag.String("run-dir", "/run/vpn-tui", "runtime directory (state.json, openvpn runtime files; created 0700)")
	cacheDir := flag.String("cache-dir", "/var/cache/vpn-tui", "cache directory (events.jsonl journal)")
	openvpn := flag.String("openvpn", "", "openvpn binary (default: looked up in PATH)")
	ovpnUser := flag.String("ovpn-user", "nobody", "user openvpn drops to (empty: no drop)")
	ovpnGroup := flag.String("ovpn-group", "nogroup", "group openvpn drops to (empty: no drop)")
	connTimeout := flag.Duration("connect-timeout", 60*time.Second, "openvpn connection timeout")
	ver := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *ver {
		fmt.Println(version)
		return
	}
	o := opts{*socket, *group, *stateDir, *runDir, *cacheDir, *openvpn, *ovpnUser, *ovpnGroup, *connTimeout, *idle}
	if err := run(o); err != nil {
		slog.Error("vpn-tuid", "err", err)
		os.Exit(1)
	}
}

type opts struct {
	socket, group, stateDir, runDir, cacheDir, openvpn, ovpnUser, ovpnGroup string
	connTimeout, idle                                                       time.Duration
}

func run(o opts) error {
	store := &profile.Store{Root: o.stateDir}
	if err := store.Init(); err != nil {
		return err
	}
	if err := os.MkdirAll(o.runDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(o.cacheDir, 0o750); err != nil {
		return err
	}
	mgr := &state.Manager{
		Drivers: map[string]state.Driver{
			profile.TypeWireGuard: driver.WireGuard{Store: store},
			profile.TypeOpenVPN: driver.OpenVPN{Store: store, RunDir: o.runDir, Bin: o.openvpn,
				User: o.ovpnUser, Group: o.ovpnGroup, ConnectTimeout: o.connTimeout},
		},
		FW:        state.NoopFirewall{}, // shortcut: pas de kill switch réel, remplacé par nft en phase 4
		Bus:       events.NewBus(filepath.Join(o.cacheDir, "events.jsonl")),
		StatePath: filepath.Join(o.runDir, "state.json"),
	}
	srv, err := rpc.New()
	if err != nil {
		return err
	}
	srv.Store, srv.Mgr = store, mgr
	srv.Busy = mgr.Active
	srv.Member = rpc.GroupMember(o.group)
	srv.IdleTimeout = o.idle

	ln, owned, err := listen(o.socket)
	if err != nil {
		return err
	}
	if owned {
		defer os.Remove(o.socket)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	err = srv.Serve(ctx, ln)
	if derr := mgr.Down(); derr != nil { // SIGTERM: tear the tunnel down before exiting
		slog.Error("down on exit", "err", derr)
		err = errors.Join(err, derr)
	}
	return err
}

// listen uses the systemd-passed fd 3 when LISTEN_PID/LISTEN_FDS say so,
// otherwise creates the socket itself (owned=true).
func listen(path string) (ln net.Listener, owned bool, err error) {
	if os.Getenv("LISTEN_PID") == fmt.Sprint(os.Getpid()) && os.Getenv("LISTEN_FDS") != "" {
		var n int
		if _, e := fmt.Sscan(os.Getenv("LISTEN_FDS"), &n); e == nil && n >= 1 {
			f := os.NewFile(3, "systemd-socket")
			defer f.Close()
			ln, err = net.FileListener(f)
			return ln, false, err
		}
	}
	os.Remove(path) // stale socket from a previous run
	if ln, err = net.Listen("unix", path); err != nil {
		return nil, false, err
	}
	if err = os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, true, err
	}
	return ln, true, nil
}
