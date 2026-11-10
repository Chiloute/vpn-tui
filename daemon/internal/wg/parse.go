// Package wg parses WireGuard profiles (restricted wg-quick format).
//
// Strict allowlist: no plaintext secret is accepted. The client
// replaces PrivateKey/PresharedKey with the "@keyring" sentinel.
// DNS choice: search domain names are REJECTED (IPs only).
package wg

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxSize is the maximum accepted size of a profile.
const MaxSize = 16 * 1024

const sentinel = "@keyring"

type Peer struct {
	PublicKey           string
	Endpoint            string // host:port, host DNS ou IP
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
	HasPresharedKey     bool
}

type Config struct {
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int
	Peers      []Peer
	Sanitized  []byte
}

// RejectError describes a profile rejection.
type RejectError struct {
	Line   int
	Key    string
	Reason string
}

func (e *RejectError) Error() string {
	switch {
	case e.Line > 0 && e.Key != "":
		return fmt.Sprintf("WireGuard profile rejected (line %d, key %q): %s", e.Line, e.Key, e.Reason)
	case e.Line > 0:
		return fmt.Sprintf("WireGuard profile rejected (line %d): %s", e.Line, e.Reason)
	case e.Key != "":
		return fmt.Sprintf("WireGuard profile rejected (key %q): %s", e.Key, e.Reason)
	}
	return "WireGuard profile rejected: " + e.Reason
}

const secretReason = "plaintext secret: the client must move it to the keyring"

var rejected = map[string]string{
	"postup":     "script forbidden",
	"postdown":   "script forbidden",
	"preup":      "script forbidden",
	"predown":    "script forbidden",
	"saveconfig": "disk write forbidden",
	"table":      "routing managed by the daemon",
	"fwmark":     "routing managed by the daemon",
}

type section struct {
	name string
	line int
	kv   map[string]string
	kl   map[string]int
}

func Parse(content []byte) (*Config, error) {
	if len(content) > MaxSize {
		return nil, &RejectError{Reason: fmt.Sprintf("file too large (max %d bytes)", MaxSize)}
	}
	if !utf8.Valid(content) {
		return nil, &RejectError{Reason: "invalid UTF-8"}
	}
	if strings.IndexByte(string(content), 0) >= 0 {
		return nil, &RejectError{Reason: "NUL byte forbidden"}
	}

	var secs []*section
	var cur *section
	for i, raw := range strings.Split(string(content), "\n") {
		n := i + 1
		l := strings.TrimSpace(raw)
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		if l[0] == '[' {
			name := strings.ToLower(l)
			if name != "[interface]" && name != "[peer]" {
				return nil, &RejectError{Line: n, Reason: "unknown section " + l}
			}
			cur = &section{name: name, line: n, kv: map[string]string{}, kl: map[string]int{}}
			secs = append(secs, cur)
			continue
		}
		if cur == nil {
			return nil, &RejectError{Line: n, Reason: "directive outside a section"}
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return nil, &RejectError{Line: n, Reason: "invalid line (expected \"Key = value\")"}
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		lk := strings.ToLower(k)
		if r, bad := rejected[lk]; bad {
			return nil, &RejectError{Line: n, Key: k, Reason: r}
		}
		if (lk == "privatekey" || lk == "presharedkey") && v != sentinel {
			return nil, &RejectError{Line: n, Key: k, Reason: secretReason}
		}
		allowed := map[string]bool{"privatekey": true, "address": true, "dns": true, "mtu": true, "listenport": true}
		if cur.name == "[peer]" {
			allowed = map[string]bool{"publickey": true, "presharedkey": true, "endpoint": true, "allowedips": true, "persistentkeepalive": true}
		}
		if !allowed[lk] {
			return nil, &RejectError{Line: n, Key: k, Reason: "unknown or disallowed key in " + cur.name}
		}
		if _, dup := cur.kv[lk]; dup {
			return nil, &RejectError{Line: n, Key: k, Reason: "duplicate key"}
		}
		cur.kv[lk], cur.kl[lk] = v, n
	}

	if len(secs) == 0 || secs[0].name != "[interface]" {
		return nil, &RejectError{Reason: "[Interface] section missing or not first"}
	}
	cfg := &Config{}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if err := parseInterface(secs[0], cfg, &b); err != nil {
		return nil, err
	}
	for _, s := range secs[1:] {
		if s.name == "[interface]" {
			return nil, &RejectError{Line: s.line, Reason: "only one [Interface] section allowed"}
		}
		if err := parsePeer(s, cfg, &b); err != nil {
			return nil, err
		}
	}
	if len(cfg.Peers) == 0 {
		return nil, &RejectError{Reason: "at least one [Peer] section is required"}
	}
	cfg.Sanitized = []byte(b.String())
	return cfg, nil
}

func parseInterface(s *section, c *Config, b *strings.Builder) error {
	if _, ok := s.kv["privatekey"]; !ok {
		return &RejectError{Line: s.line, Key: "PrivateKey", Reason: "missing PrivateKey"}
	}
	b.WriteString("PrivateKey = " + sentinel + "\n")
	v, ok := s.kv["address"]
	if !ok {
		return &RejectError{Line: s.line, Key: "Address", Reason: "missing Address"}
	}
	ps, err := prefixes(v)
	if err != nil {
		return &RejectError{Line: s.kl["address"], Key: "Address", Reason: err.Error()}
	}
	c.Addresses = ps
	b.WriteString("Address = " + joinP(ps) + "\n")
	if v, ok := s.kv["dns"]; ok {
		var ss []string
		for _, f := range split(v) {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return &RejectError{Line: s.kl["dns"], Key: "DNS", Reason: fmt.Sprintf("%q is not an IP address (domain names rejected)", f)}
			}
			c.DNS = append(c.DNS, a)
			ss = append(ss, a.String())
		}
		if len(ss) == 0 {
			return &RejectError{Line: s.kl["dns"], Key: "DNS", Reason: "empty list"}
		}
		b.WriteString("DNS = " + strings.Join(ss, ", ") + "\n")
	}
	if v, ok := s.kv["mtu"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 576 || n > 9000 {
			return &RejectError{Line: s.kl["mtu"], Key: "MTU", Reason: "must be an integer between 576 and 9000"}
		}
		c.MTU = n
		fmt.Fprintf(b, "MTU = %d\n", n)
	}
	if v, ok := s.kv["listenport"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return &RejectError{Line: s.kl["listenport"], Key: "ListenPort", Reason: "must be an integer between 0 and 65535"}
		}
		c.ListenPort = n
		fmt.Fprintf(b, "ListenPort = %d\n", n)
	}
	return nil
}

func parsePeer(s *section, c *Config, b *strings.Builder) error {
	var p Peer
	b.WriteString("\n[Peer]\n")
	pk, ok := s.kv["publickey"]
	if !ok {
		return &RejectError{Line: s.line, Key: "PublicKey", Reason: "missing PublicKey"}
	}
	if raw, err := base64.StdEncoding.DecodeString(pk); err != nil || len(raw) != 32 {
		return &RejectError{Line: s.kl["publickey"], Key: "PublicKey", Reason: "must be a 32-byte base64 key"}
	}
	p.PublicKey = pk
	b.WriteString("PublicKey = " + pk + "\n")
	if _, ok := s.kv["presharedkey"]; ok {
		p.HasPresharedKey = true
		b.WriteString("PresharedKey = " + sentinel + "\n")
	}
	if v, ok := s.kv["endpoint"]; ok {
		if err := checkEndpoint(v); err != nil {
			return &RejectError{Line: s.kl["endpoint"], Key: "Endpoint", Reason: err.Error()}
		}
		p.Endpoint = v
		b.WriteString("Endpoint = " + v + "\n")
	}
	v, ok := s.kv["allowedips"]
	if !ok {
		return &RejectError{Line: s.line, Key: "AllowedIPs", Reason: "missing AllowedIPs"}
	}
	ps, err := prefixes(v)
	if err != nil {
		return &RejectError{Line: s.kl["allowedips"], Key: "AllowedIPs", Reason: err.Error()}
	}
	p.AllowedIPs = ps
	b.WriteString("AllowedIPs = " + joinP(ps) + "\n")
	if v, ok := s.kv["persistentkeepalive"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return &RejectError{Line: s.kl["persistentkeepalive"], Key: "PersistentKeepalive", Reason: "must be an integer between 0 and 65535"}
		}
		p.PersistentKeepalive = n
		if n > 0 {
			fmt.Fprintf(b, "PersistentKeepalive = %d\n", n)
		}
	}
	c.Peers = append(c.Peers, p)
	return nil
}

func split(v string) []string {
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func prefixes(v string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range split(v) {
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", f)
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty list (at least one CIDR required)")
	}
	return out, nil
}

func joinP(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

func checkEndpoint(v string) error {
	host, port, err := net.SplitHostPort(v)
	if err != nil || host == "" {
		return fmt.Errorf("invalid endpoint %q (expected host:port)", v)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid endpoint port %q", port)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("hostname too long")
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return fmt.Errorf("forbidden character in hostname %q", host)
		}
	}
	return nil
}
