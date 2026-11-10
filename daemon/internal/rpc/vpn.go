package rpc

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/driver"
	"github.com/Chiloute/vpn-tui/daemon/internal/events"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/state"
)

const CodeBusy = -32004

// subscribed marks the events_subscribe ack: handle() then turns the connection into a stream.
type subscribed struct {
	OK bool `json:"ok"`
}

func notImpl() (any, *rpcError, bool) {
	return nil, &rpcError{CodeNotImplemen, "not_implemented"}, true
}

// vpnMethod handles status/up/down/scope_learn_accept/events_subscribe; ok=false: not one of them.
func (s *Server) vpnMethod(method string, raw json.RawMessage) (res any, e *rpcError, ok bool) {
	switch method {
	case "status":
		if s.Mgr == nil {
			return disarmedStatus, nil, true
		}
		return s.status(), nil, true
	case "up", "down", "events_subscribe", "scope_learn_accept":
	default:
		return nil, nil, false
	}
	if s.Mgr == nil || s.Store == nil && (method == "up" || method == "scope_learn_accept") {
		return notImpl()
	}
	var p struct {
		ID      string
		CIDRs   []string `json:"cidrs"`
		Secrets *struct {
			Username     string `json:"username"`
			Password     string `json:"password"`
			PrivateKey   string `json:"private_key"`
			PresharedKey string `json:"preshared_key"`
		}
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &rpcError{CodeInvalidPar, "invalid params"}, true
		}
	}
	slog.Info("rpc", "method", method, "id", p.ID) // never the secrets
	switch method {
	case "down":
		if err := s.Mgr.Down(); err != nil {
			return nil, connErr(err), true
		}
		return map[string]any{"ok": true}, nil, true
	case "events_subscribe":
		if s.Mgr.Bus == nil {
			return notImpl()
		}
		return subscribed{true}, nil, true
	case "scope_learn_accept":
		return s.learnAccept(p.ID, p.CIDRs)
	}
	prof, err := s.Store.Get(p.ID)
	if err != nil {
		return nil, fail(err), true
	}
	var sec state.Secrets
	if p.Secrets != nil {
		sec = state.Secrets{Username: p.Secrets.Username, Password: p.Secrets.Password,
			PrivateKey: p.Secrets.PrivateKey, PresharedKey: p.Secrets.PresharedKey}
	}
	if prof.Secrets.KeyringRef != "" && (prof.Type == profile.TypeOpenVPN && sec.Username == "" || prof.Type == profile.TypeWireGuard && sec.PrivateKey == "") {
		return nil, &rpcError{CodeInvalidPar, "secrets manquants pour ce profil"}, true
	}
	err = s.Mgr.Up(s.ctx, prof, sec)
	sec = state.Secrets{} // not kept
	if err != nil {
		return nil, connErr(err), true
	}
	return map[string]any{"ok": true}, nil, true
}

// connErr maps a manager error; driver errors never contain secret values.
func connErr(err error) *rpcError {
	switch {
	case errors.Is(err, state.ErrAlreadyActive):
		return &rpcError{CodeBusy, "profil déjà actif"}
	case errors.Is(err, driver.ErrSecrets):
		return &rpcError{CodeInvalidPar, err.Error()}
	}
	slog.Error("vpn", "err", err)
	return &rpcError{-32603, "échec de la connexion : " + trunc(err.Error())}
}

func trunc(m string) string {
	if r := []rune(m); len(r) > 900 {
		return string(r[:900])
	}
	return m
}

func (s *Server) learnAccept(id string, cidrs []string) (any, *rpcError, bool) {
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err != nil || p != p.Masked() || p.Addr().Zone() != "" {
			return nil, &rpcError{CodeInvalidPar, "CIDR invalide ou non canonique"}, true
		}
	}
	p, err := s.Store.Get(id)
	if err != nil {
		return nil, fail(err), true
	}
	sc := p.Scope
	for _, c := range cidrs {
		if !slices.Contains(sc.CIDRs, c) {
			sc.CIDRs = append(slices.Clone(sc.CIDRs), c)
		}
		if !slices.Contains(sc.Learned, c) {
			sc.Learned = append(slices.Clone(sc.Learned), c)
		}
	}
	x, err := s.Store.Update(id, profile.Update{Scope: &sc})
	if err != nil {
		return nil, fail(err), true
	}
	return view(x), nil, true
}

// status maps Manager.Status on result_status; scope is the active profile's scope.cidrs.
func (s *Server) status() map[string]any {
	st := s.Mgr.Status()
	var profileID, lhost, since, iface any
	scope := []string{}
	if st.Profile != "" {
		profileID = st.Profile
		if s.Store != nil {
			if p, err := s.Store.Get(st.Profile); err == nil {
				scope = nn(slices.Clone(p.Scope.CIDRs))
			}
		}
	}
	if a, err := netip.ParseAddr(st.LHOST); err == nil && a.Is4() {
		lhost = st.LHOST
	}
	if st.Since != nil {
		since = st.Since.UTC().Format(time.RFC3339)
	}
	if st.Iface != "" {
		iface = st.Iface
	}
	return map[string]any{
		"state": st.State, "profile": profileID, "killswitch": st.Killswitch, "lhost": lhost,
		"scope": scope, "since": since, "reconnect": map[string]int{"attempt": st.Attempt, "max": st.Max},
		"interface": iface, "rx_bytes": st.Rx, "tx_bytes": st.Tx,
	}
}

// stream acks events_subscribe then pushes one notification per event until the
// client closes or the server stops. No read deadline on this connection.
func (s *Server) stream(conn net.Conn, sc *bufio.Scanner, id any) {
	ch, cancel := s.Mgr.Bus.Subscribe() // before the ack: no event missed after it
	defer cancel()
	send(conn, id, map[string]any{"ok": true}, nil)
	conn.SetReadDeadline(time.Time{})
	gone := make(chan struct{})
	go func() {
		defer close(gone)
		for sc.Scan() { // ignore anything the client sends; ends on close
		}
	}()
	for {
		select {
		case <-gone:
			return
		case <-s.ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(struct {
				JSONRPC string       `json:"jsonrpc"`
				Method  string       `json:"method"`
				Params  events.Event `json:"params"`
			}{"2.0", "event", e})
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(append(b, '\n')); err != nil {
				return
			}
		}
	}
}
