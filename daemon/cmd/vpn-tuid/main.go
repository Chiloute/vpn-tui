// Command vpn-tuid is the privileged VPN daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/rpc"
)

var version = "dev"

func main() {
	socket := flag.String("socket", "/run/vpn-tui/vpn-tuid.sock", "unix socket path (ignored under systemd activation)")
	group := flag.String("group", "vpn-tui", "group allowed to connect")
	idle := flag.Duration("idle-timeout", 60*time.Second, "exit after this long without connection")
	ver := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *ver {
		fmt.Println(version)
		return
	}
	if err := run(*socket, *group, *idle); err != nil {
		slog.Error("vpn-tuid", "err", err)
		os.Exit(1)
	}
}

func run(path, group string, idle time.Duration) error {
	srv, err := rpc.New()
	if err != nil {
		return err
	}
	srv.Member = rpc.GroupMember(group)
	srv.IdleTimeout = idle

	ln, owned, err := listen(path)
	if err != nil {
		return err
	}
	if owned {
		defer os.Remove(path)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
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
