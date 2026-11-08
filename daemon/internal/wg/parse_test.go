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
		{"avec-secrets", load(t, "avec-secrets.conf"), "secret en clair"},
		{"postup", load(t, "postup.conf"), "script interdit"},
		{"saveconfig", load(t, "saveconfig.conf"), "écriture disque"},
		{"predown", rep("MTU = 1380", "PreDown = x"), "script interdit"},
		{"table", rep("MTU = 1380", "Table = off"), "routage"},
		{"fwmark", rep("MTU = 1380", "FwMark = 1"), "routage"},
		{"privatekey clair", rep("PrivateKey = @keyring", "PrivateKey = "+k), "secret en clair"},
		{"inconnue", rep("MTU = 1380", "Foo = 1"), "inconnue"},
		{"privatekey manquante", rep("PrivateKey = @keyring\n", ""), "PrivateKey manquante"},
		{"cidr invalide", rep("10.0.0.2/32", "10.0.0.2"), "CIDR invalide"},
		{"address vide", rep("Address = 10.0.0.2/32, fd00::2/128", "Address ="), "liste vide"},
		{"dns domaine", rep("DNS = 10.0.0.1", "DNS = example.com"), "domaine"},
		{"mtu bas", rep("1380", "100"), "MTU"},
		{"mtu haut", rep("1380", "9001"), "MTU"},
		{"publickey invalide", rep(k, "abc"), "PublicKey"},
		{"allowedips manquante", rep("AllowedIPs = 0.0.0.0/0, ::/0\n", ""), "AllowedIPs manquante"},
		{"keepalive", rep("= 25", "= 70000"), "PersistentKeepalive"},
		{"endpoint", rep("vpn.example.com:51820", "vpn.example.com"), "Endpoint"},
		{"sans peer", good[:strings.Index(good, "[Peer]")], "[Peer]"},
		{"deux interface", good + "\n[Interface]\n", "une seule"},
		{"section inconnue", good + "\n[Foo]\n", "section inconnue"},
		{"nul", good + "\x00", "NUL"},
		{"utf8", good + "\xff", "UTF-8"},
		{"trop gros", good + strings.Repeat("#", MaxSize), "trop gros"},
		{"dupliquée", good + "AllowedIPs = 10.0.0.0/8\n", "dupliquée"},
	}
	for _, c := range cases {
		_, err := Parse([]byte(c.in))
		re, ok := err.(*RejectError)
		if !ok || !strings.Contains(re.Error(), c.want) {
			t.Errorf("%s: err=%v, attendu %q", c.name, err, c.want)
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
		t.Fatalf("config inattendue: %+v", c)
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
