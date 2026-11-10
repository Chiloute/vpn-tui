// Package kernel implements state.Kernel on the real host.
// Fail-closed: any error while probing is answered "present/alive", so that
// Reconcile locks instead of assuming the host is clean.
package kernel

import (
	"errors"

	"github.com/Chiloute/vpn-tui/daemon/internal/nft"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Kernel probes the host; the zero value is ready to use. Fields are test hooks.
type Kernel struct {
	table func() (bool, error)
	link  func(string) error // nil = found
	kill  func(pid int, sig unix.Signal) error
}

var _ state.Kernel = Kernel{}

func (k Kernel) TableExists() bool {
	f := k.table
	if f == nil {
		f = nft.TableExists
	}
	ok, err := f()
	return err != nil || ok
}

func (k Kernel) IfaceExists(name string) bool {
	f := k.link
	if f == nil {
		f = func(n string) error { _, err := netlink.LinkByName(n); return err }
	}
	err := f(name)
	var nf netlink.LinkNotFoundError
	return err == nil || !errors.As(err, &nf)
}

func (k Kernel) PidAlive(pid int) bool {
	f := k.kill
	if f == nil {
		f = func(p int, s unix.Signal) error { return unix.Kill(p, s) }
	}
	err := f(pid, 0)
	return err == nil || !errors.Is(err, unix.ESRCH) // EPERM: alive; unknown error: alive
}

// DeleteIface removes the interface; an absent one is success.
func DeleteIface(name string) error {
	l, err := netlink.LinkByName(name)
	var nf netlink.LinkNotFoundError
	if errors.As(err, &nf) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(l)
}
