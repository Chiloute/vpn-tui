package rpc

import (
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/Chiloute/vpn-tui/daemon/internal/ovpn"
	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/daemon/internal/wg"
)

const (
	CodeNotFound       = -32005
	CodeImportRejected = -32006
)

func nn(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func view(p *profile.Profile) map[string]any {
	return map[string]any{
		"id": p.ID, "name": p.Name, "type": p.Type, "tags": nn(p.Tags), "color": p.Color,
		"scope":       map[string]any{"cidrs": nn(p.Scope.CIDRs), "exclude": nn(p.Scope.Exclude), "learned": nn(p.Scope.Learned)},
		"killswitch":  map[string]any{"enabled": p.Killswitch.Enabled, "allow_internet": p.Killswitch.AllowInternet, "block_ipv6": p.Killswitch.BlockIPv6},
		"dns":         map[string]any{"servers": nn(p.DNS.Servers), "force": p.DNS.Force},
		"has_secrets": p.Secrets.KeyringRef != "",
	}
}

func fail(e error) *rpcError {
	var o *ovpn.RejectError
	var w *wg.RejectError
	var iv *profile.InvalidError
	msg := e.Error()
	if utf8.RuneCountInString(msg) > 1000 {
		msg = string([]rune(msg)[:1000])
	}
	switch {
	case errors.Is(e, profile.ErrNotFound):
		return &rpcError{CodeNotFound, "not_found"}
	case errors.Is(e, profile.ErrExists), errors.As(e, &o), errors.As(e, &w), errors.As(e, &iv):
		return &rpcError{CodeImportRejected, msg}
	}
	slog.Error("profile store", "err", e)
	return &rpcError{-32603, "internal error"}
}

// profileMethod handles list/profile_*; ok=false means the method is not one of them.
func (s *Server) profileMethod(method string, raw json.RawMessage) (res any, e *rpcError, ok bool) {
	if method != "list" && !strings.HasPrefix(method, "profile_") {
		return nil, nil, false
	}
	st := s.Store
	if st == nil {
		return nil, &rpcError{CodeNotImplemen, "not_implemented"}, true
	}
	var p struct {
		ID, Type, Name, Color *string
		Content               string
		Tags                  *[]string
		Scope                 *profile.Scope
		Killswitch            *profile.Killswitch
		DNS                   *profile.DNS
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &rpcError{CodeInvalidPar, "invalid params"}, true
		}
	}
	str := func(x *string) string {
		if x == nil {
			return ""
		}
		return *x
	}
	// Never log content or secrets: method, id, type only.
	slog.Info("rpc", "method", method, "id", str(p.ID), "type", str(p.Type))
	switch method {
	case "list":
		l, err := st.List()
		if err != nil {
			return nil, fail(err), true
		}
		out := make([]any, len(l))
		for i, x := range l {
			out[i] = view(x)
		}
		return map[string]any{"profiles": out}, nil, true
	case "profile_import":
		x, err := st.Import(str(p.Type), str(p.Name), str(p.ID), p.Content)
		if err != nil {
			return nil, fail(err), true
		}
		return view(x), nil, true
	case "profile_update":
		x, err := st.Update(str(p.ID), profile.Update{Name: p.Name, Tags: p.Tags, Color: p.Color, Scope: p.Scope, Killswitch: p.Killswitch, DNS: p.DNS})
		if err != nil {
			return nil, fail(err), true
		}
		return view(x), nil, true
	case "profile_delete":
		if err := st.Delete(str(p.ID)); err != nil {
			return nil, fail(err), true
		}
		return map[string]any{"ok": true}, nil, true
	}
	return nil, nil, false
}
