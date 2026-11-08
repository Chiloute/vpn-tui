package kernel

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestFailClosed(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		err  error
		want bool
	}{{nil, true}, {boom, true}, {netlink.LinkNotFoundError{}, false}} {
		if got := (Kernel{link: func(string) error { return c.err }}).IfaceExists("x"); got != c.want {
			t.Errorf("iface %v: %v", c.err, got)
		}
	}
	for _, c := range []struct {
		ok   bool
		err  error
		want bool
	}{{false, nil, false}, {true, nil, true}, {false, boom, true}} {
		if got := (Kernel{table: func() (bool, error) { return c.ok, c.err }}).TableExists(); got != c.want {
			t.Errorf("table %v %v: %v", c.ok, c.err, got)
		}
	}
	for _, c := range []struct {
		err  error
		want bool
	}{{nil, true}, {unix.EPERM, true}, {boom, true}, {unix.ESRCH, false}} {
		if got := (Kernel{kill: func(int, unix.Signal) error { return c.err }}).PidAlive(1); got != c.want {
			t.Errorf("pid %v: %v", c.err, got)
		}
	}
}
