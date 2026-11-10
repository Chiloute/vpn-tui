package wg

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

var k = strings.Repeat("A", 43) + "="

func load(t *testing.T, n string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + n)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParse(t *testing.T) {
	good := load(t, "client.conf")
	rep := func(old, new string) string { return strings.Replace(good, old, new, 1) }
	cases := []struct{ name, in, want string }{
		{"with-secrets", load(t, "with-secrets.conf"), "plaintext secret"},
		{"postup", load(t, "postup.conf"), "script forbidden"},
		{"saveconfig", load(t, "saveconfig.conf"), "disk write"},
		{"predown", rep("MTU = 1380", "PreDown = x"), "script forbidden"},
		{"table", rep("MTU = 1380", "Table = off"), "routing"},
		{"fwmark", rep("MTU = 1380", "FwMark = 1"), "routing"},
		{"plaintext privatekey", rep("PrivateKey = @keyring", "PrivateKey = "+k), "plaintext secret"},
		{"unknown", rep("MTU = 1380", "Foo = 1"), "unknown"},
		{"missing privatekey", rep("PrivateKey = @keyring\n", ""), "missing PrivateKey"},
		{"invalid cidr", rep("10.0.0.2/32", "10.0.0.2"), "invalid CIDR"},
		{"empty address", rep("Address = 10.0.0.2/32, fd00::2/128", "Address ="), "empty list"},
		{"dns domain", rep("DNS = 10.0.0.1", "DNS = example.com"), "domain"},
		{"low mtu", rep("1380", "100"), "MTU"},
		{"high mtu", rep("1380", "9001"), "MTU"},
		{"invalid publickey", rep(k, "abc"), "PublicKey"},
		{"missing allowedips", rep("AllowedIPs = 0.0.0.0/0, ::/0\n", ""), "missing AllowedIPs"},
		{"keepalive", rep("= 25", "= 70000"), "PersistentKeepalive"},
		{"endpoint", rep("vpn.example.com:51820", "vpn.example.com"), "Endpoint"},
		{"no peer", good[:strings.Index(good, "[Peer]")], "[Peer]"},
		{"two interfaces", good + "\n[Interface]\n", "only one"},
		{"unknown section", good + "\n[Foo]\n", "unknown section"},
		{"nul", good + "\x00", "NUL"},
		{"utf8", good + "\xff", "UTF-8"},
		{"too large", good + strings.Repeat("#", MaxSize), "too large"},
		{"duplicate", good + "AllowedIPs = 10.0.0.0/8\n", "duplicate key"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.in))
		re, ok := err.(*RejectError)
		if !ok || !strings.Contains(re.Error(), c.want) {
			t.Errorf("%s: err=%v, want %q", c.name, err, c.want)
		}
	}
}

func TestParseOKAndIdempotent(t *testing.T) {
	in := load(t, "client.conf") + "\n[peer]\npublickey = " + k + "\nallowedips = 10.1.0.0/16\n"
	c, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Peers) != 2 || !c.Peers[0].HasPresharedKey || c.Peers[1].HasPresharedKey ||
		c.MTU != 1380 || len(c.Addresses) != 2 || len(c.DNS) != 1 || c.Peers[0].PersistentKeepalive != 25 {
		t.Fatalf("unexpected config: %+v", c)
	}
	if !bytes.HasSuffix(c.Sanitized, []byte("\n")) || bytes.Contains(c.Sanitized, []byte("#")) {
		t.Fatalf("sanitized: %q", c.Sanitized)
	}
	c2, err := Parse(c.Sanitized)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Sanitized, c2.Sanitized) {
		t.Fatalf("non idempotent:\n%s\n---\n%s", c.Sanitized, c2.Sanitized)
	}
}
