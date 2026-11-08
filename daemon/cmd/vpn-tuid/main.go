// Command vpn-tuid is the privileged VPN daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/dns"
	"github.com/Chiloute/vpn-tui/daemon/internal/driver"
	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/health"
	"github.com/Chiloute/vpn-tui/daemon/internal/kernel"
	"github.com/Chiloute/vpn-tui/daemon/internal/nft"
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
	maxAttempts := flag.Int("reconnect-max-attempts", 10, "reconnection attempts before staying locked")
	maxBackoff := flag.Duration("reconnect-max-backoff", 60*time.Second, "cap of the reconnection backoff")
	hsTimeout := flag.Duration("handshake-timeout", 180*time.Second, "WireGuard: tunnel considered dead after this long without handshake")
	marker := flag.String("marker", "", "armed marker file (default <state-dir>/armed.json)")
	journalAge := flag.Duration("journal-max-age", 168*time.Hour, "events journal retention")
	panicOff := flag.Bool("panic-off", false, "tear everything down (firewall, tunnel, markers) and exit; needs no daemon")
	restoreLock := flag.Bool("restore-lock", false, "oneshot at boot: re-apply the kill switch lock if the armed marker exists, then exit")
	resolvectl := flag.String("resolvectl", "", "resolvectl binary (default: looked up in PATH; none found: profile DNS disabled)")
	ver := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *ver {
		fmt.Println(version)
		return
	}
	if *marker == "" {
		*marker = filepath.Join(*stateDir, "armed.json")
	}
	if *resolvectl == "" {
		*resolvectl, _ = exec.LookPath("resolvectl") // empty: DNS disabled, warned at Up if a profile needs it
	}
	o := opts{resolvectl: *resolvectl, socket: *socket, group: *group, stateDir: *stateDir, runDir: *runDir, cacheDir: *cacheDir, openvpn: *openvpn,
		ovpnUser: *ovpnUser, ovpnGroup: *ovpnGroup, marker: *marker, connTimeout: *connTimeout, idle: *idle,
		maxBackoff: *maxBackoff, hsTimeout: *hsTimeout, journalAge: *journalAge, maxAttempts: *maxAttempts}
	var err error
	switch {
	case *panicOff:
		err = panicOffCmd(o, os.Stdout)
	case *restoreLock:
		err = restoreLockCmd(o)
	default:
		err = run(o)
	}
	if err != nil {
		slog.Error("vpn-tuid", "err", err)
		os.Exit(1)
	}
}

type opts struct {
	resolvectl, socket, group, stateDir, runDir, cacheDir, openvpn, ovpnUser, ovpnGroup, marker string
	connTimeout, idle, maxBackoff, hsTimeout, journalAge                                        time.Duration
	maxAttempts                                                                                 int
}

func (o opts) journal() string { return filepath.Join(o.cacheDir, "events.jsonl") }

// manager builds the Manager shared by the daemon and --restore-lock.
func (o opts) manager(store *profile.Store) *state.Manager {
	m := &state.Manager{
		Drivers: map[string]state.Driver{
			profile.TypeWireGuard: driver.WireGuard{Store: store, HandshakeTimeout: o.hsTimeout, DNS: &dns.Resolved{Bin: o.resolvectl}},
			profile.TypeOpenVPN: driver.OpenVPN{Store: store, RunDir: o.runDir, Bin: o.openvpn,
				User: o.ovpnUser, Group: o.ovpnGroup, ConnectTimeout: o.connTimeout, DNS: &dns.Resolved{Bin: o.resolvectl}},
		},
		FW:          nft.New(),
		Bus:         events.NewBus(o.journal()),
		StatePath:   filepath.Join(o.runDir, "state.json"),
		MarkerPath:  o.marker,
		DeleteIface: kernel.DeleteIface,
	}
	m.Reconnect.MaxAttempts = o.maxAttempts
	m.Reconnect.Backoff = health.Backoff{Initial: time.Second, Max: o.maxBackoff}
	return m
}

// restoreLockCmd re-applies the lock from the marker (nothing to do without marker).
func restoreLockCmd(o opts) error {
	if err := os.MkdirAll(o.runDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(o.cacheDir, 0o750); err != nil {
		return err
	}
	return o.manager(&profile.Store{Root: o.stateDir}).RestoreLock()
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
	mgr := o.manager(store)
	srv, err := rpc.New()
	if err != nil {
		return err
	}
	srv.Store, srv.Mgr = store, mgr
	srv.Busy = func() bool { return mgr.Active() || mgr.Status().State != state.Disarmed } // a lock keeps the daemon alive
	srv.Member = rpc.GroupMember(o.group)
	srv.IdleTimeout = o.idle

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go mgr.Bus.RunPurge(ctx, o.journalAge, time.Hour) // purges immediately, then hourly
	// Align with the host before accepting any connection; on error Reconcile has already locked.
	outcome, rerr := mgr.Reconcile(ctx, kernel.Kernel{}, store.Get)
	if rerr != nil {
		slog.Error("reconcile", "outcome", outcome, "err", rerr)
	} else {
		slog.Info("reconcile", "outcome", outcome)
	}
	ln, owned, err := listen(o.socket)
	if err != nil {
		return err
	}
	if owned {
		defer os.Remove(o.socket)
	}
	return serve(ctx, srv, ln)
}

// serve runs until ctx is done. It never disarms on exit (restart, rebuild): firewall, tunnel and
// marker stay in place and Reconcile picks them up. Only the down / panic_off RPCs and --panic-off disarm.
func serve(ctx context.Context, srv *rpc.Server, ln net.Listener) error {
	return srv.Serve(ctx, ln)
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
