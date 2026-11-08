package nft

import (
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/Chiloute/vpn-tui/daemon/internal/state"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Firewall implements state.Firewall. Each transition is one netlink batch.
type Firewall struct{ mu sync.Mutex }

var _ state.Firewall = (*Firewall)(nil)

func New() *Firewall { return &Firewall{} }

func (f *Firewall) Lock(s state.Spec) error { return f.apply(s, Locked) }
func (f *Firewall) Arm(s state.Spec) error  { return f.apply(s, Armed) }
func (f *Firewall) Disarm() error           { return DeleteTable() }

func (f *Firewall) apply(s state.Spec, m Mode) error {
	rs, err := Build(s, m) // validate before touching the kernel
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, err := nftables.New()
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	accept := nftables.ChainPolicyAccept
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	// add+del+add in one batch: replaces an existing table atomically and
	// never fails when it is absent.
	c.AddTable(t)
	c.DelTable(t)
	c.AddTable(t)
	for _, ch := range []struct {
		name  string
		hook  *nftables.ChainHook
		rules []Rule
	}{{"output", nftables.ChainHookOutput, rs.Output}, {"forward", nftables.ChainHookForward, rs.Forward}} {
		chain := c.AddChain(&nftables.Chain{
			Name: ch.name, Table: t, Type: nftables.ChainTypeFilter, Hooknum: ch.hook,
			Priority: nftables.ChainPriorityRef(-10), Policy: &accept,
		})
		for _, r := range ch.rules {
			exprs, err := r.exprs(c, t)
			if err != nil {
				return err
			}
			c.AddRule(&nftables.Rule{Table: t, Chain: chain, Exprs: exprs})
		}
	}
	return c.Flush()
}

func TableExists() (bool, error) {
	c, err := nftables.New()
	if err != nil {
		return false, err
	}
	defer c.CloseLasting()
	ts, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	for _, t := range ts {
		if t.Name == TableName {
			return true, nil
		}
	}
	return false, nil
}

// DeleteTable removes only inet vpn_tui; idempotent (add then del in one batch).
func DeleteTable() error {
	c, err := nftables.New()
	if err != nil {
		return err
	}
	defer c.CloseLasting()
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	c.AddTable(t)
	c.DelTable(t)
	return c.Flush()
}

func cmpEq(b []byte) *expr.Cmp {
	return &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b}
}

func ifname(n string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, n)
	return b
}

// addrSet adds an anonymous interval set of prefixes and returns its lookup.
func addrSet(c *nftables.Conn, t *nftables.Table, ps []netip.Prefix, invert bool) (*expr.Lookup, error) {
	kt := nftables.TypeIPAddr
	if ps[0].Addr().Is6() {
		kt = nftables.TypeIP6Addr
	}
	var el []nftables.SetElement
	for _, p := range ps {
		el = append(el, nftables.SetElement{Key: p.Addr().AsSlice()})
		// exclusive end; none when the prefix reaches the end of the space
		if end := lastAddr(p).Next(); end.IsValid() {
			el = append(el, nftables.SetElement{Key: end.AsSlice(), IntervalEnd: true})
		}
	}
	s := &nftables.Set{Table: t, Anonymous: true, Constant: true, Interval: true, KeyType: kt}
	if err := c.AddSet(s, el); err != nil {
		return nil, err
	}
	return &expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID, Invert: invert}, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func portSet(c *nftables.Conn, t *nftables.Table, ports []int) (*expr.Lookup, error) {
	var el []nftables.SetElement
	for _, p := range ports {
		el = append(el, nftables.SetElement{Key: binary.BigEndian.AppendUint16(nil, uint16(p))})
	}
	s := &nftables.Set{Table: t, Anonymous: true, Constant: true, KeyType: nftables.TypeInetService}
	if err := c.AddSet(s, el); err != nil {
		return nil, err
	}
	return &expr.Lookup{SourceRegister: 1, SetName: s.Name, SetID: s.ID}, nil
}

func nfproto(v6 bool) []expr.Any {
	p := byte(unix.NFPROTO_IPV4)
	if v6 {
		p = unix.NFPROTO_IPV6
	}
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, cmpEq([]byte{p})}
}

func daddr(v6 bool) *expr.Payload {
	if v6 {
		return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16}
	}
	return &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}
}

// exprs translates the IR into netlink expressions (same match order as String).
func (r Rule) exprs(c *nftables.Conn, t *nftables.Table) ([]expr.Any, error) {
	var e []expr.Any
	if r.Oif != "" {
		e = append(e, &expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1}, cmpEq(ifname(r.Oif)))
	}
	if r.IPv6Only {
		e = append(e, nfproto(true)...)
	}
	if len(r.Daddr) > 0 {
		v6 := r.Daddr[0].Addr().Is6()
		l, err := addrSet(c, t, r.Daddr, false)
		if err != nil {
			return nil, err
		}
		e = append(e, nfproto(v6)...)
		e = append(e, daddr(v6), l)
		if len(r.NotDaddr) > 0 {
			n, err := addrSet(c, t, r.NotDaddr, true)
			if err != nil {
				return nil, err
			}
			e = append(e, daddr(v6), n) // nfproto already checked above
		}
	}
	if r.Host.IsValid() {
		e = append(e, nfproto(r.Host.Is6())...)
		e = append(e, daddr(r.Host.Is6()), cmpEq(r.Host.AsSlice()))
	}
	if len(r.Ports) > 0 {
		proto := byte(unix.IPPROTO_UDP)
		if r.Proto == "tcp" {
			proto = unix.IPPROTO_TCP
		}
		e = append(e, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, cmpEq([]byte{proto}),
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
		if len(r.Ports) == 1 {
			e = append(e, cmpEq(binary.BigEndian.AppendUint16(nil, uint16(r.Ports[0]))))
		} else {
			l, err := portSet(c, t, r.Ports)
			if err != nil {
				return nil, err
			}
			e = append(e, l)
		}
	}
	v := expr.VerdictAccept
	if r.Drop {
		v = expr.VerdictDrop
	}
	return append(e, &expr.Verdict{Kind: v}), nil
}
