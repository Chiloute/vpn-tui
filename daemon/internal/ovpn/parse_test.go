package ovpn

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

const base = "client\nremote a.example.com 1194\n"

const pemOK = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"

func readTD(t *testing.T, n string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAccepted(t *testing.T) {
	tests := []struct {
		file string
		want []Remote
	}{
		{"thm.ovpn", []Remote{{"ga-eu-west-3-vpn.vm.tryhackme.com", 1194, "udp"}}},
		{"htb.ovpn", []Remote{{"edge-eu-free-1.hackthebox.eu", 1337, "udp"}}},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			c, err := Parse(readTD(t, tc.file))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(c.Remotes, tc.want) {
				t.Fatalf("remotes = %+v", c.Remotes)
			}
			if !bytes.HasSuffix(c.Sanitized, []byte("\n")) {
				t.Fatal("pas de \\n final")
			}
			c2, err := Parse(c.Sanitized)
			if err != nil {
				t.Fatalf("re-parse : %v", err)
			}
			if !reflect.DeepEqual(c, c2) || !bytes.Equal(c.Sanitized, c2.Sanitized) {
				t.Fatal("non idempotent")
			}
		})
	}
}

func TestSanitizedOnlyAllowed(t *testing.T) {
	c, err := Parse(readTD(t, "thm.ovpn"))
	if err != nil {
		t.Fatal(err)
	}
	inBlock := false
	for _, l := range strings.Split(strings.TrimSpace(string(c.Sanitized)), "\n") {
		switch {
		case strings.HasPrefix(l, "</"):
			inBlock = false
		case strings.HasPrefix(l, "<"):
			inBlock = true
		case inBlock:
		default:
			d := strings.Fields(l)[0]
			if _, ok := allowed[d]; !ok && d != "remote" {
				t.Errorf("directive hors liste : %q", d)
			}
		}
	}
}

func TestRemoteNormalisation(t *testing.T) {
	c, err := Parse([]byte("proto tcp-client\nremote 10.0.0.1\nremote b.example.com 443 udp6\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Remote{{"10.0.0.1", 1194, "tcp"}, {"b.example.com", 443, "udp"}}
	if !reflect.DeepEqual(c.Remotes, want) {
		t.Fatalf("%+v", c.Remotes)
	}
}

func TestTokenizerAndComments(t *testing.T) {
	c, err := Parse([]byte("# c\n; c\n\n  client  \nremote \"a.example.com\" '443'\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Sanitized) != "client\nremote a.example.com 443\n" {
		t.Fatalf("%q", c.Sanitized)
	}
}

func TestRejected(t *testing.T) {
	cases := map[string]string{
		"up":                    "up /bin/sh",
		"down":                  "down /bin/sh",
		"route-up":              "route-up /x",
		"route-pre-down":        "route-pre-down /x",
		"ipchange":              "ipchange /x",
		"tls-verify":            "tls-verify /x",
		"learn-address":         "learn-address /x",
		"client-connect":        "client-connect /x",
		"client-disconnect":     "client-disconnect /x",
		"auth-user-pass-verify": "auth-user-pass-verify /x via-env",
		"script-security":       "script-security 2",
		"plugin":                "plugin /lib.so",
		"iproute":               "iproute /x",
		"config":                "config /etc/other.ovpn",
		"cd":                    "cd /",
		"chroot":                "chroot /",
		"writepid":              "writepid /x",
		"log":                   "log /x",
		"log-append":            "log-append /x",
		"status":                "status /x",
		"management":            "management 127.0.0.1 7505",
		"management-hold":       "management-hold",
		"daemon":                "daemon",
		"setenv":                "setenv A B",
		"setenv-safe":           "setenv-safe A B",
		"pkcs11-providers":      "pkcs11-providers /x.so",
		"pkcs11-id":             "pkcs11-id x",
		"ca file":               "ca /etc/ssl/x.pem",
		"cert file":             "cert /x",
		"key file":              "key /x",
		"tls-auth file":         "tls-auth /x 1",
		"tls-crypt file":        "tls-crypt /x",
		"tls-crypt-v2 file":     "tls-crypt-v2 /x",
		"askpass":               "askpass /x",
		"auth-user-pass file":   "auth-user-pass /etc/shadow",
		"double dash":           "--client",
		"double dash up":        "--up /bin/sh",
		"unknown":               "foo bar",
		"dev tap":               "dev tap",
		"dev-type tap":          "dev-type tap",
		"comp-lzo yes":          "comp-lzo yes",
		"cipher none":           "cipher none",
		"auth none":             "auth none",
		"comp-lzo bare":         "comp-lzo",
		"allow-compression yes": "allow-compression asym",
		"verb alpha":            "verb abc",
		"verb negative":         "verb -1",
		"ping alpha":            "ping x",
		"remote bad host":       "remote bad_host!.com",
		"remote semicolon":      "remote a.com;id 1194",
		"remote port 0":         "remote a.com 0",
		"remote port big":       "remote a.com 65536",
		"remote proto":          "remote a.com 1194 sctp",
		"remote numeric host":   "remote 127.1",
		"remote 4 args":         "remote a.com 1194 udp x",
		"proto bad":             "proto icmp",
		"remote-cert-tls bad":   "remote-cert-tls x",
		"cipher shell":          "cipher $(id)",
		"unclosed quote":        "cipher \"AES",
		"redirect bad":          "redirect-gateway foo",
		"route bad":             "route $(id)",
		"explicit-exit-notify":  "explicit-exit-notify x",
		"tls-version-min bad":   "tls-version-min 1.2 x",
		"key-direction 2":       "key-direction 2",
	}
	for name, l := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(base + l + "\n"))
			var re *RejectError
			if !errors.As(err, &re) {
				t.Fatalf("attendu RejectError, obtenu %v", err)
			}
			if re.Line != 3 {
				t.Fatalf("ligne = %d (%v)", re.Line, err)
			}
		})
	}
}

func TestReasons(t *testing.T) {
	_, err := Parse([]byte(base + "up /bin/sh\n"))
	if err == nil || err.Error() != "ligne 3 : directive « up » interdite (exécute un script)" {
		t.Fatalf("%v", err)
	}
	_, err = Parse([]byte(base + "foo\n"))
	if re := new(RejectError); !errors.As(err, &re) || re.Reason != "non autorisée" {
		t.Fatalf("%v", err)
	}
}

func TestBadInputs(t *testing.T) {
	blk := func(n, c string) string { return base + "<" + n + ">\n" + c + "</" + n + ">\n" }
	cases := map[string]string{
		"too big":          base + "#" + strings.Repeat("a", MaxSize),
		"NUL":              base + "verb 3\x00\n",
		"bad utf8":         base + "# \xff\xfe\n",
		"ctrl char":        base + "verb 3\x1b\n",
		"no remote":        "client\n",
		"unclosed block":   base + "<ca>\n" + pemOK,
		"nested block":     base + "<ca>\n<cert>\n" + pemOK + "</cert>\n</ca>\n",
		"unknown block":    blk("foo", pemOK),
		"stray close":      base + "</ca>\n",
		"secret block":     blk("auth-user-pass", "user\npass\n"),
		"not pem":          blk("ca", "hello\n"),
		"empty block":      blk("ca", ""),
		"pem unterminate":  blk("ca", "-----BEGIN CERTIFICATE-----\nAAAA\n"),
		"pem mismatch":     blk("ca", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END KEY-----\n"),
		"pem bad char":     blk("ca", "-----BEGIN CERTIFICATE-----\nAA;id\n-----END CERTIFICATE-----\n"),
		"directive in pem": blk("ca", pemOK+"up /bin/sh\n"),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); err == nil {
				t.Fatal("attendu une erreur")
			} else if !errors.As(err, new(*RejectError)) {
				t.Fatalf("type %T", err)
			}
		})
	}
	_, err := Parse([]byte(blk("auth-user-pass", "u\np\n")))
	if err == nil || !strings.Contains(err.Error(), "secret en clair : le client doit l'extraire vers le keyring") {
		t.Fatalf("%v", err)
	}
}

func TestTestdataRejected(t *testing.T) {
	for _, f := range []string{"thm-with-secrets.ovpn", "evil-up.ovpn", "evil-script-security.ovpn", "evil-unclosed.ovpn"} {
		if _, err := Parse(readTD(t, f)); err == nil {
			t.Errorf("%s accepté", f)
		}
	}
}

func TestAllowedDirectives(t *testing.T) {
	in := base + `dev tun
dev-type tun
proto udp
remote-random
resolv-retry 5
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name srv name
cipher AES-256-CBC
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-128-CBC
auth SHA256
tls-version-min 1.2 or-highest
tls-cipher TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
key-direction 1
explicit-exit-notify
verb 3
mute 20
comp-lzo no
allow-compression no
auth-user-pass
auth-nocache
connect-retry 5 10
connect-timeout 10
server-poll-timeout 10
ping 10
ping-restart 60
pull
route-nopull
route 10.0.0.0 255.0.0.0 vpn_gateway
redirect-gateway def1 bypass-dhcp
block-outside-dns
`
	if _, err := Parse([]byte(in)); err != nil {
		t.Fatal(err)
	}
}
