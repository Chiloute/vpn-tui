// Package ovpn parses imported OpenVPN configurations against a strict
// allowlist. OpenVPN runs the result as root: any unknown directive is
// rejected.
//
// Design choices: a directive prefixed with "--" is rejected (no
// normalisation). Case sensitivity is the same as OpenVPN's. Comments (# or ;)
// are only recognised at the start of a line, as in OpenVPN.
package ovpn

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxSize is the maximum accepted size of an .ovpn file.
const MaxSize = 48 * 1024

// Remote is a server extracted from a remote directive.
type Remote struct {
	Host  string
	Port  int
	Proto string // "udp" or "tcp"
}

// Config is the result of a successful Parse.
type Config struct {
	Remotes   []Remote
	Sanitized []byte
}

// RejectError describes why a config was rejected.
type RejectError struct {
	Line      int
	Directive string
	Reason    string
}

func (e *RejectError) Error() string {
	if e.Line == 0 {
		return e.Reason
	}
	return fmt.Sprintf("line %d: directive \"%s\" %s", e.Line, e.Directive, e.Reason)
}

const (
	reasonNotAllowed = "is not allowed"
	reasonFile       = "is forbidden (references an external file: only inline blocks are accepted)"
	reasonSecret     = "plaintext secret: the client must move it to the keyring"
)

var dangerous = map[string]string{
	"up":                    "is forbidden (runs a script)",
	"down":                  "is forbidden (runs a script)",
	"route-up":              "is forbidden (runs a script)",
	"route-pre-down":        "is forbidden (runs a script)",
	"ipchange":              "is forbidden (runs a command)",
	"tls-verify":            "is forbidden (runs a script)",
	"learn-address":         "is forbidden (runs a script)",
	"client-connect":        "is forbidden (runs a script)",
	"client-disconnect":     "is forbidden (runs a script)",
	"auth-user-pass-verify": "is forbidden (runs a script)",
	"script-security":       "is forbidden (allows running scripts)",
	"plugin":                "is forbidden (loads native code)",
	"iproute":               "is forbidden (runs an arbitrary program)",
	"config":                "is forbidden (includes an external file)",
	"cd":                    "is forbidden (changes directory)",
	"chroot":                "is forbidden (changes the root)",
	"writepid":              "is forbidden (writes an arbitrary file)",
	"log":                   "is forbidden (writes an arbitrary file)",
	"log-append":            "is forbidden (writes an arbitrary file)",
	"status":                "is forbidden (writes an arbitrary file)",
	"daemon":                "is forbidden (changes the execution mode)",
	"ca":                    reasonFile,
	"cert":                  reasonFile,
	"key":                   reasonFile,
	"tls-auth":              reasonFile,
	"tls-crypt":             reasonFile,
	"tls-crypt-v2":          reasonFile,
	"askpass":               reasonFile,
}

var dangerousPrefix = map[string]string{
	"management": "is forbidden (opens a control interface)",
	"setenv":     "is forbidden (modifies the environment)",
	"pkcs11-":    "is forbidden (loads an external library)",
}

// argSpec validates the arguments of a directive.
type argSpec func(args []string) string // returns "" if OK, otherwise the reason

var (
	none    = func(a []string) string { return exact(a, 0) }
	oneInt  = func(a []string) string { return ints(a, 1, 1) }
	oneName = func(a []string) string { return names(a, 1, 1) }
	// cipher/auth "none" would send the tunnel in clear text.
	cryptoName = func(a []string) string {
		if len(a) == 1 && strings.EqualFold(a[0], "none") {
			return "\"none\" forbidden (cleartext traffic)"
		}
		return oneName(a)
	}
)

var allowed = map[string]argSpec{
	"client": none, "nobind": none, "persist-key": none, "persist-tun": none,
	"remote-random": none, "auth-nocache": none, "pull": none,
	"route-nopull": none, "block-outside-dns": none, "auth-user-pass": none,
	"dev":      lit("tun"),
	"dev-type": lit("tun"),
	"proto": func(a []string) string {
		if exact(a, 1) != "" {
			return exact(a, 1)
		}
		if _, ok := normProto(a[0]); !ok {
			return "unknown protocol"
		}
		return ""
	},
	"resolv-retry": func(a []string) string {
		if len(a) == 1 && a[0] == "infinite" {
			return ""
		}
		return oneInt(a)
	},
	"remote-cert-tls":       func(a []string) string { return oneOf(a, "server", "client") },
	"key-direction":         func(a []string) string { return oneOf(a, "0", "1") },
	"comp-lzo":              lit("no"),
	"allow-compression":     lit("no"),
	"verify-x509-name":      verifyName,
	"cipher":                cryptoName,
	"data-ciphers":          oneName,
	"data-ciphers-fallback": oneName,
	"auth":                  cryptoName,
	"tls-cipher":            oneName,
	"tls-version-min": func(a []string) string {
		if len(a) == 2 && a[1] != "or-highest" {
			return "second argument expected: or-highest"
		}
		if len(a) == 0 || len(a) > 2 {
			return "1 or 2 arguments expected"
		}
		return names(a, 1, 2)
	},
	"explicit-exit-notify": func(a []string) string { return ints(a, 0, 1) },
	"tls-client":           none,
	"keepalive":            keepalive,
	"reneg-sec":            renegSec,
	"mssfix":               mssfix,
	"verb":                 oneInt, "mute": oneInt, "ping": oneInt, "ping-restart": oneInt,
	"connect-timeout": oneInt, "server-poll-timeout": oneInt,
	"connect-retry":    func(a []string) string { return ints(a, 1, 2) },
	"redirect-gateway": redirectGW,
	"route":            routeArgs,
}

func lit(v string) argSpec {
	return func(a []string) string {
		if len(a) != 1 || a[0] != v {
			return "only the value \"" + v + "\" is accepted"
		}
		return ""
	}
}

func oneOf(a []string, vals ...string) string {
	if len(a) == 1 {
		for _, v := range vals {
			if a[0] == v {
				return ""
			}
		}
	}
	return "expected value: " + strings.Join(vals, "|")
}

func exact(a []string, n int) string {
	if len(a) != n {
		return fmt.Sprintf("%d argument(s) expected", n)
	}
	return ""
}

func isInt(s string) bool {
	if s == "" || len(s) > 9 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ints(a []string, min, max int) string {
	if len(a) < min || len(a) > max {
		return "wrong number of arguments"
	}
	for _, s := range a {
		if !isInt(s) {
			return "integer expected"
		}
	}
	return ""
}

// isName reports whether s is a safe token (algorithms, certificate names...), with no space or metacharacter.
// inRange checks that every argument is an integer within [lo, hi].
func inRange(a []string, lo, hi int) string {
	for _, s := range a {
		if !isInt(s) {
			return "integer expected"
		}
		if n := atoi(s); n < lo || n > hi {
			return fmt.Sprintf("value out of range %d-%d", lo, hi)
		}
	}
	return ""
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// keepalive <interval> <timeout>: 1 <= interval <= 3600, interval < timeout <= 7200.
func keepalive(a []string) string {
	if len(a) != 2 {
		return "2 arguments expected"
	}
	if r := inRange(a[:1], 1, 3600); r != "" {
		return r
	}
	if r := inRange(a[1:], 1, 7200); r != "" {
		return r
	}
	if atoi(a[0]) >= atoi(a[1]) {
		return "timeout must be greater than interval"
	}
	return ""
}

// reneg-sec <max> [<min>], in seconds (OpenVPN 2.6 syntax), 0 to 7 days.
func renegSec(a []string) string {
	if len(a) < 1 || len(a) > 2 {
		return "1 or 2 arguments expected"
	}
	return inRange(a, 0, 604800)
}

// mssfix [<n>]: the OpenVPN 2.6 --help documents no "mtu" keyword, so it is refused.
func mssfix(a []string) string {
	if len(a) > 1 {
		return "at most 1 argument expected"
	}
	if len(a) == 1 && a[0] == "0" { // 0 disables mssfix
		return ""
	}
	return inRange(a, 576, 9000)
}

func isName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_.:+!@=/", r):
		default:
			return false
		}
	}
	return true
}

func names(a []string, min, max int) string {
	if len(a) < min || len(a) > max {
		return "wrong number of arguments"
	}
	for _, s := range a {
		if !isName(s) {
			return "characters not allowed"
		}
	}
	return ""
}

func verifyName(a []string) string {
	if len(a) < 1 || len(a) > 2 {
		return "1 or 2 arguments expected"
	}
	if len(a) == 2 && a[1] != "name" && a[1] != "name-prefix" && a[1] != "subject" {
		return "unknown type"
	}
	return names(a[:1], 1, 1)
}

func redirectGW(a []string) string {
	for _, s := range a {
		switch s {
		case "local", "autolocal", "def1", "bypass-dhcp", "bypass-dns", "block-local", "ipv6", "!ipv4":
		default:
			return "unknown option \"" + s + "\""
		}
	}
	return ""
}

func routeArgs(a []string) string {
	if len(a) < 1 || len(a) > 4 {
		return "1 to 4 arguments expected"
	}
	for i, s := range a {
		if s == "vpn_gateway" || s == "net_gateway" || s == "remote_host" || s == "default" || isInt(s) {
			continue
		}
		if _, err := netip.ParseAddr(s); err == nil && !strings.Contains(s, "%") {
			continue
		}
		return fmt.Sprintf("invalid argument %d", i+1)
	}
	return ""
}

func normProto(p string) (string, bool) {
	switch p {
	case "udp", "udp4", "udp6":
		return "udp", true
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return "tcp", true
	}
	return "", false
}

func validHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return !strings.Contains(h, "%")
	}
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	// a numeric last label rules out exotic IPv4 forms (127.1, 0x7f...).
	return !isInt(labels[len(labels)-1])
}

// tokenize splits a line on spaces, honouring single or double quotes.
func tokenize(line string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	in, quote := false, rune(0)
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, in = r, true
		case r == ' ' || r == '\t':
			if in {
				toks = append(toks, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unclosed quote")
	}
	if in {
		toks = append(toks, cur.String())
	}
	return toks, nil
}

var blocks = map[string]bool{"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true}

// checkPEM checks that the content is a sequence of PEM objects (or an OpenVPN
// static key) and returns only the validated lines: comment lines outside
// BEGIN/END (e.g. the `openvpn --genkey` header) are dropped.
func checkPEM(lines []string) ([]string, string) {
	label, n := "", 0
	var kept []string
	for _, l := range lines {
		if label == "" && (l[0] == '#' || l[0] == ';') {
			continue
		}
		kept = append(kept, l)
		switch {
		case strings.HasPrefix(l, "-----BEGIN ") && strings.HasSuffix(l, "-----"):
			if label != "" {
				return nil, "nested BEGIN"
			}
			label = strings.TrimSuffix(strings.TrimPrefix(l, "-----BEGIN "), "-----")
		case strings.HasPrefix(l, "-----END ") && strings.HasSuffix(l, "-----"):
			if label == "" || strings.TrimSuffix(strings.TrimPrefix(l, "-----END "), "-----") != label {
				return nil, "END without matching BEGIN"
			}
			label = ""
			n++
		case label == "":
			return nil, "content outside PEM"
		default:
			if i := strings.Index(l, ": "); i > 0 { // PEM header
				continue
			}
			for _, r := range l {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
					return nil, "invalid character in PEM"
				}
			}
		}
	}
	if label != "" {
		return nil, "unterminated PEM"
	}
	if n == 0 {
		return nil, "no PEM"
	}
	return kept, ""
}

// Parse validates content and returns the sanitized config.
func Parse(content []byte) (*Config, error) {
	g := func(r string) error { return &RejectError{Reason: r} }
	if len(content) > MaxSize {
		return nil, g(fmt.Sprintf("file too large (max %d bytes)", MaxSize))
	}
	if bytes.IndexByte(content, 0) >= 0 {
		return nil, g("NUL byte forbidden")
	}
	if !utf8.Valid(content) {
		return nil, g("invalid UTF-8")
	}
	for _, b := range content {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return nil, g("control character forbidden")
		}
	}

	var out bytes.Buffer
	cfg := &Config{}
	var remoteHasProto []bool
	globalProto := "udp"
	var blockName string
	var blockLine int
	var blockLines []string

	for i, raw := range strings.Split(string(content), "\n") {
		ln := i + 1
		line := strings.TrimSpace(raw)
		rej := func(d, r string) error { return &RejectError{ln, d, r} }

		if blockName != "" {
			if line == "</"+blockName+">" {
				kept, r := checkPEM(blockLines)
				if r != "" {
					return nil, &RejectError{blockLine, blockName, "invalid block (" + r + ")"}
				}
				out.WriteString("<" + blockName + ">\n")
				for _, l := range kept {
					out.WriteString(l + "\n")
				}
				out.WriteString("</" + blockName + ">\n")
				blockName = ""
			} else if strings.HasPrefix(line, "<") || (line != "" && strings.ContainsRune("#;", rune(line[0])) && strings.HasPrefix(strings.TrimLeft(line, "#; \t"), "<")) {
				return nil, rej(blockName, "nested or badly closed block")
			} else if line != "" {
				blockLines = append(blockLines, line)
			}
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '<' {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">")
			switch {
			case !strings.HasSuffix(line, ">") || strings.HasPrefix(line, "</"):
				return nil, rej(line, "invalid block tag")
			case name == "auth-user-pass":
				return nil, rej(name, reasonSecret)
			case !blocks[name]:
				return nil, rej(name, "unknown block")
			}
			blockName, blockLine, blockLines = name, ln, nil
			continue
		}

		toks, err := tokenize(line)
		if err != nil {
			return nil, rej(line, err.Error())
		}
		d, args := toks[0], toks[1:]
		if strings.HasPrefix(d, "--") {
			return nil, rej(d, "is forbidden (\"--\" prefix not accepted)")
		}
		if r, ok := dangerous[d]; ok {
			return nil, rej(d, r)
		}
		for p, r := range dangerousPrefix {
			if strings.HasPrefix(d, p) {
				return nil, rej(d, r)
			}
		}
		if d == "auth-user-pass" && len(args) > 0 {
			return nil, rej(d, reasonFile)
		}
		if d == "remote" {
			rm, hasProto, r := parseRemote(args)
			if r != "" {
				return nil, rej(d, "has an invalid argument ("+r+")")
			}
			cfg.Remotes = append(cfg.Remotes, rm)
			remoteHasProto = append(remoteHasProto, hasProto)
			line := fmt.Sprintf("remote %s %d", rm.Host, rm.Port)
			if hasProto {
				line += " " + rm.Proto
			}
			out.WriteString(line + "\n")
			continue
		}
		spec, ok := allowed[d]
		if !ok {
			return nil, rej(d, reasonNotAllowed)
		}
		if r := spec(args); r != "" {
			return nil, rej(d, "has an invalid argument ("+r+")")
		}
		if d == "proto" {
			globalProto, _ = normProto(args[0])
			args = []string{globalProto}
		}
		if d == "keepalive" || d == "reneg-sec" || d == "mssfix" {
			// regenerate from the validated values (drops leading zeros)
			for i, a := range args {
				args[i] = strconv.Itoa(atoi(a))
			}
		}
		out.WriteString(strings.Join(append([]string{d}, args...), " ") + "\n")
	}
	if blockName != "" {
		return nil, &RejectError{blockLine, blockName, "unclosed block"}
	}
	if len(cfg.Remotes) == 0 {
		return nil, g("no remote directive")
	}
	for i := range cfg.Remotes {
		if !remoteHasProto[i] {
			cfg.Remotes[i].Proto = globalProto
		}
	}
	cfg.Sanitized = out.Bytes()
	return cfg, nil
}

func parseRemote(a []string) (rm Remote, hasProto bool, reason string) {
	if len(a) < 1 || len(a) > 3 {
		return rm, false, "host [port] [proto] expected"
	}
	if !validHost(a[0]) {
		return rm, false, "invalid host"
	}
	rm = Remote{Host: a[0], Port: 1194}
	if len(a) > 1 {
		if !isInt(a[1]) {
			return rm, false, "invalid port"
		}
		p, _ := strconv.Atoi(a[1])
		if p < 1 || p > 65535 {
			return rm, false, "port out of range 1-65535"
		}
		rm.Port = p
	}
	if len(a) > 2 {
		p, ok := normProto(a[2])
		if !ok {
			return rm, false, "unknown protocol"
		}
		rm.Proto, hasProto = p, true
	}
	return rm, hasProto, ""
}
