package ovpn

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNotif(t *testing.T) {
	tests := []struct {
		line       string
		ok         bool
		kind, name string
		ip         string
	}{
		{">STATE:1700000000,CONNECTING,,,,,,", true, "STATE", "CONNECTING", ""},
		{">STATE:1700000005,CONNECTED,SUCCESS,10.8.0.6,203.0.113.1,1194,192.0.2.1,50000,", true, "STATE", "CONNECTED", "10.8.0.6"},
		{">STATE:1,CONNECTED,SUCCESS,,203.0.113.1,1194,192.0.2.1,50000,fd00::2", true, "STATE", "CONNECTED", "fd00::2"},
		{">STATE:1,RECONNECTING,tls-error,,,,,", true, "STATE", "RECONNECTING", ""},
		{">STATE:1", false, "", "", ""},
		{">HOLD:Waiting for hold release:0", true, "HOLD", "", ""},
		{">PASSWORD:Need 'Auth' username/password", true, "PASSWORD", "", ""},
		{">FATAL:boom", true, "FATAL", "", ""},
		{">INFO:hello", false, "", "", ""},
		{"STATE:1,CONNECTED", false, "", "", ""},
		{"SUCCESS: ok", false, "", "", ""},
	}
	for _, tc := range tests {
		n, ok := parseNotif(tc.line)
		if ok != tc.ok || n.Kind != tc.kind || n.State.Name != tc.name {
			t.Errorf("%q : got %+v ok=%v", tc.line, n, ok)
			continue
		}
		if ok && tc.kind == "STATE" && n.State.LocalIP.String() != orInvalid(tc.ip) {
			t.Errorf("%q : ip %v", tc.line, n.State.LocalIP)
		}
	}
}

func orInvalid(s string) string {
	if s == "" {
		return "invalid IP"
	}
	return s
}

func TestMgmtCommand(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "m.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, _ := l.Accept()
		defer c.Close()
		c.Write([]byte(">HOLD:Waiting\r\n"))
		sc := bufio.NewScanner(c)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "bad") {
				c.Write([]byte("ERROR: nope\r\n"))
			} else {
				c.Write([]byte(">STATE:1,WAIT,,,\r\nSUCCESS: done\r\n"))
			}
		}
	}()
	m, err := dialMgmt(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if n := <-m.notifs; n.Kind != "HOLD" {
		t.Fatalf("got %+v", n)
	}
	if err := m.command("state on"); err != nil {
		t.Fatal(err)
	}
	if n := <-m.notifs; n.State.Name != "WAIT" {
		t.Fatalf("got %+v", n)
	}
	if err := m.command("bad"); err == nil {
		t.Fatal("ERROR: expected")
	}
}
