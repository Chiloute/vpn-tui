// Package dns applies a profile's DNS settings to the tunnel interface through resolvectl (systemd-resolved).
// The binary is run with an argument array, never through a shell.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"time"
)

var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

const callTimeout = 5 * time.Second

// Resolved drives resolvectl. Run is injectable for tests (nil: real exec).
type Resolved struct {
	Bin string
	Run func(ctx context.Context, bin string, args ...string) error
}

func run(ctx context.Context, bin string, args ...string) error {
	if out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w: %.200s", bin, args[0], err, out)
	}
	return nil
}

func (r *Resolved) call(ctx context.Context, args ...string) error {
	f := r.Run
	if f == nil {
		f = run
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return f(ctx, r.Bin, args...)
}

// Apply sets the DNS servers of iface; with force, all domains are routed through it.
func (r *Resolved) Apply(ctx context.Context, iface string, servers []netip.Addr, force bool) error {
	if !ifaceRe.MatchString(iface) {
		return errors.New("dns: interface invalide")
	}
	if len(servers) == 0 {
		return nil
	}
	args := []string{"dns", iface}
	for _, s := range servers {
		if !s.IsValid() {
			return errors.New("dns: adresse invalide")
		}
		args = append(args, s.String())
	}
	if err := r.call(ctx, args...); err != nil {
		return err
	}
	if force {
		if err := r.call(ctx, "domain", iface, "~."); err != nil {
			return err
		}
		return r.call(ctx, "default-route", iface, "true")
	}
	return r.call(ctx, "default-route", iface, "false")
}

// Revert drops all per-link DNS settings of iface.
func (r *Resolved) Revert(ctx context.Context, iface string) error {
	if !ifaceRe.MatchString(iface) {
		return errors.New("dns: interface invalide")
	}
	return r.call(ctx, "revert", iface)
}
