package dns

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

func rec(calls *[][]string, err error) *Resolved {
	return &Resolved{Bin: "rc", Run: func(_ context.Context, bin string, a ...string) error {
		*calls = append(*calls, append([]string{bin}, a...))
		return err
	}}
}

func TestApply(t *testing.T) {
	sv := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700::1111")}
	var c [][]string
	if err := rec(&c, nil).Apply(context.Background(), "vpntui0", sv, true); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"rc", "dns", "vpntui0", "1.1.1.1", "2606:4700::1111"}, {"rc", "domain", "vpntui0", "~."}, {"rc", "default-route", "vpntui0", "true"}}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("%v", c)
	}
	c = nil
	rec(&c, nil).Apply(context.Background(), "vpntui0", sv, false)
	want = [][]string{{"rc", "dns", "vpntui0", "1.1.1.1", "2606:4700::1111"}, {"rc", "default-route", "vpntui0", "false"}}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("%v", c)
	}
}

func TestApplyRejects(t *testing.T) {
	var c [][]string
	r := rec(&c, nil)
	if r.Apply(context.Background(), "vpntui0", []netip.Addr{{}}, false) == nil {
		t.Fatal("invalid ip accepted")
	}
	if r.Apply(context.Background(), "a b;x", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, false) == nil {
		t.Fatal("bad iface accepted")
	}
	if r.Revert(context.Background(), "-x y") == nil {
		t.Fatal("bad iface accepted")
	}
	if r.Apply(context.Background(), "vpntui0", nil, true) != nil || len(c) != 0 {
		t.Fatalf("empty servers must be a no-op: %v", c)
	}
}

func TestErrorsAndRevert(t *testing.T) {
	var c [][]string
	if rec(&c, errors.New("x")).Apply(context.Background(), "vpntui0", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, true) == nil || len(c) != 1 {
		t.Fatal("error not propagated")
	}
	c = nil
	rec(&c, nil).Revert(context.Background(), "vpntui0")
	if !reflect.DeepEqual(c, [][]string{{"rc", "revert", "vpntui0"}}) {
		t.Fatalf("%v", c)
	}
}
