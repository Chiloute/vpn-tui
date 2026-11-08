package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Chiloute/vpn-tui/daemon/internal/driver"
	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/kernel"
	"github.com/Chiloute/vpn-tui/daemon/internal/nft"
	"github.com/Chiloute/vpn-tui/daemon/internal/ovpn"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/Chiloute/vpn-tui/daemon/internal/wg"
)

// panicOffCmd is the emergency exit: no socket, no RPC, no Manager. Every step runs
// even if a previous one failed; the joined error makes the exit code non-zero.
func panicOffCmd(o opts, out io.Writer) error {
	var errs []error
	step := func(what string, err error) {
		if err != nil {
			fmt.Fprintf(out, "ECHEC  %s : %v\n", what, err)
			errs = append(errs, fmt.Errorf("%s : %w", what, err))
			return
		}
		fmt.Fprintf(out, "ok     %s\n", what)
	}
	statePath := filepath.Join(o.runDir, "state.json")

	step("table nft vpn_tui supprimée", nft.DeleteTable())

	switch pers, err := state.Load(statePath); {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		step("lecture de state.json", err)
	case pers.PID > 0:
		// ovpn.Adopt refuses any pid whose /proc/<pid>/comm is not "openvpn"
		if p, aerr := ovpn.Adopt(pers.PID, driver.Iface, o.runDir); aerr != nil {
			fmt.Fprintf(out, "skip   openvpn pid %d : %v\n", pers.PID, aerr)
		} else {
			step(fmt.Sprintf("openvpn pid %d arrêté", pers.PID), p.Stop())
		}
	}

	wg.PurgeRules()
	fmt.Fprintln(out, "ok     règles fwmark 51820 supprimées")
	step("interface "+driver.Iface+" supprimée", kernel.DeleteIface(driver.Iface))

	for _, f := range []string{o.marker, statePath} {
		if err := os.Remove(f); errors.Is(err, os.ErrNotExist) {
			err = nil
		} else {
			step(f+" supprimé", err)
		}
	}

	if err := os.MkdirAll(o.cacheDir, 0o750); err == nil {
		events.NewBus(o.journal()).Publish(events.Event{State: state.Disarmed, Kind: "panic_off", Detail: "vpn-tuid --panic-off"})
		fmt.Fprintln(out, "ok     événement panic_off journalisé")
	} else {
		step("journal", err)
	}
	return errors.Join(errs...)
}
