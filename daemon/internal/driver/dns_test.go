package driver

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Chiloute/vpn-tui/daemon/internal/dns"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
)

func TestWithDNS(t *testing.T) {
	var calls [][]string
	var fail error
	r := &dns.Resolved{Bin: "rc", Run: func(_ context.Context, _ string, a ...string) error {
		calls = append(calls, a)
		return fail
	}}
	stopped := 0
	stop := func() error { stopped++; return nil }
	ctx := context.Background()

	p := &profile.Profile{}
	withDNS(ctx, r, p, stop)
	if len(calls) != 0 {
		t.Fatalf("calls with no servers: %v", calls)
	}

	p.DNS = profile.DNS{Servers: []string{"10.0.0.1"}, Force: true}
	fail = errors.New("boom") // Apply fails: stop still returned, tunnel kept
	st := withDNS(ctx, r, p, stop)
	if st == nil || stopped != 0 {
		t.Fatal("tunnel must be kept")
	}
	calls, fail = nil, nil
	if err := st(); err != nil || stopped != 1 {
		t.Fatal("stop not called")
	}
	if !reflect.DeepEqual(calls, [][]string{{"revert", Iface}}) {
		t.Fatalf("revert before stop expected: %v", calls)
	}

	calls = nil
	withDNS(ctx, r, p, stop)
	want := [][]string{{"dns", Iface, "10.0.0.1"}, {"domain", Iface, "~."}, {"default-route", Iface, "true"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("%v", calls)
	}

	calls = nil
	withDNS(ctx, &dns.Resolved{}, p, stop) // no binary: no call, no panic
	withDNS(ctx, nil, p, stop)
}
