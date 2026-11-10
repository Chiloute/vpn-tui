package ovpn

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestMain : le binaire de test sert de faux openvpn quand OVPN_FAKE est défini.
func TestMain(m *testing.M) {
	if mode := os.Getenv("OVPN_FAKE"); mode != "" {
		fakeOpenVPN(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeOpenVPN(mode string) {
	args := os.Args[1:]
	arg := func(name string) string {
		if i := slices.Index(args, name); i >= 0 && i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	if mode == "fail" {
		fmt.Fprintln(os.Stderr, "fake: boom")
		os.Exit(1)
	}
	if af := arg("--auth-user-pass"); af != "" {
		st, err := os.Stat(af)
		b, _ := os.ReadFile(af)
		if err != nil || st.Mode().Perm() != 0o600 || string(b) != "alice\nS3cretPw\n" {
			os.Exit(3)
		}
		fmt.Fprintf(os.Stderr, "fake: auth %q\n", b) // doit être masqué par le logger
	}
	fmt.Fprintln(os.Stderr, "fake: started")
	os.Remove(arg("--management"))
	l, err := net.Listen("unix", arg("--management"))
	if err != nil {
		os.Exit(4)
	}
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM)
	if mode != "stubborn" {
		go func() { <-sigc; os.Exit(0) }()
	}
	c, err := l.Accept()
	if err != nil {
		os.Exit(5)
	}
	fmt.Fprint(c, ">INFO:hello\r\n>HOLD:Waiting for hold release:0\r\n")
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		switch cmd := sc.Text(); {
		case cmd == "state on":
			fmt.Fprint(c, "SUCCESS: real-time state notification set to ON\r\n")
		case cmd == "hold release":
			fmt.Fprint(c, "SUCCESS: hold release succeeded\r\n")
			switch mode {
			case "hang":
			case "password":
				fmt.Fprint(c, ">PASSWORD:Need 'Auth' username/password\r\n")
			default:
				for _, s := range []string{"CONNECTING,,,,,,", "WAIT,,,,,,", "AUTH,,,,,,", "GET_CONFIG,,,,,,", "ASSIGN_IP,,,,,,",
					"ADD_ROUTES,,,,,,", "CONNECTED,SUCCESS,10.8.0.6,203.0.113.1,1194,192.0.2.1,50000,"} {
					fmt.Fprintf(c, ">STATE:1700000000,%s\r\n", s)
				}
				if mode == "reconnect" {
					time.Sleep(200 * time.Millisecond)
					fmt.Fprint(c, ">STATE:1700000009,RECONNECTING,ping-restart,,,,,\r\n")
				}
			}
		case strings.HasPrefix(cmd, "signal") && mode != "stubborn":
			fmt.Fprint(c, "SUCCESS: signal SIGTERM thrown\r\n")
			os.Exit(0)
		}
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func testOpts(t *testing.T, mode string) StartOpts {
	testEnv = []string{"OVPN_FAKE=" + mode}
	t.Cleanup(func() { testEnv = nil })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return StartOpts{
		Bin: exe, RunDir: t.TempDir(), ID: "p1", Iface: "vpntui0", ConnectTimeout: 5 * time.Second,
		Config:  &Config{Sanitized: []byte("client\nremote vpn.example.com 1194 udp\n")},
		Remotes: []Resolved{{netip.MustParseAddr("203.0.113.1"), 1194, "udp"}},
	}
}

func assertClean(t *testing.T, dir string) {
	t.Helper()
	left, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(left) != 0 {
		t.Errorf("fichiers résiduels : %v", left)
	}
}

func TestRedact(t *testing.T) {
	tests := []struct{ in, want string }{
		{"hello alice there", "[redacted]"},
		{"pw=S3cretPw", "[redacted]"},
		{"normal line", "normal line"},
		{"PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0,auth-token SESS_ID_abc,ifconfig 10.8.0.6 10.8.0.5'",
			"PUSH: Received control message: 'PUSH_REPLY,route 10.0.0.0,auth-token [redacted],ifconfig 10.8.0.6 10.8.0.5'"},
		{"option auth-token xyz", "[redacted]"},
	}
	for _, tc := range tests {
		if got := redact(tc.in, "alice", "S3cretPw"); got != tc.want {
			t.Errorf("redact(%q) = %q", tc.in, got)
		}
	}
	if got := redact("anything", "", ""); got != "anything" {
		t.Errorf("secrets vides : %q", got)
	}
}

func TestBuildArgs(t *testing.T) {
	o := StartOpts{Iface: "vpntui0", Username: "u", Password: "p", User: "nobody", Group: "nogroup"}
	a := buildArgs(o, "/r/c.conf", "/r/s.sock", "/r/auth-x")
	if a[0] != "--config" || a[1] != "/r/c.conf" {
		t.Fatalf("--config doit venir en premier : %v", a)
	}
	j := strings.Join(a, " ")
	for _, w := range []string{"--dev vpntui0", "--dev-type tun", "--script-security 1", "--management /r/s.sock unix",
		"--management-hold", "--auth-user-pass /r/auth-x", "--auth-nocache", "--auth-retry none", "--user nobody", "--group nogroup"} {
		if !strings.Contains(j, w) {
			t.Errorf("manque %q dans %s", w, j)
		}
	}
	for _, bad := range []string{"--up", "--down", "--route-up", "--plugin", "--tls-verify", "--script-security 2", " p ", " u "} {
		if strings.Contains(j+" ", bad+" ") && bad != "--script-security 2" || strings.Contains(j, "--script-security 2") {
			t.Errorf("présent à tort : %q", bad)
		}
	}
	a = buildArgs(StartOpts{Iface: "x"}, "c", "s", "a")
	if j := strings.Join(a, " "); strings.Contains(j, "--auth-user-pass") || strings.Contains(j, "--user") {
		t.Errorf("options optionnelles présentes : %s", j)
	}
}

func TestRuntimeConf(t *testing.T) {
	san := "client\ndev tun\ndev-type tun\nremote a.example.com 1194 udp\nremote b.example.com 443 tcp\nremote-random\nverb 3\n" +
		"<ca>\n-----BEGIN CERTIFICATE-----\ndev\nremote\n-----END CERTIFICATE-----\n</ca>\n"
	got := string(runtimeConf([]byte(san), []Resolved{
		{netip.MustParseAddr("203.0.113.1"), 1194, "udp"}, {netip.MustParseAddr("2001:db8::1"), 443, "tcp"}}))
	for _, bad := range []string{"example.com", "remote-random", "dev tun", "dev-type"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q devrait être retiré :\n%s", bad, got)
		}
	}
	for _, w := range []string{"client\n", "verb 3\n", "remote 203.0.113.1 1194 udp\n", "remote 2001:db8::1 443 tcp\n", "-----\ndev\nremote\n-----END"} {
		if !strings.Contains(got, w) {
			t.Errorf("manque %q :\n%s", w, got)
		}
	}
}

func TestResolve(t *testing.T) {
	c := &Config{Remotes: []Remote{{"192.0.2.1", 1194, "udp"}, {"192.0.2.1", 1194, "udp"}, {"2001:db8::1", 443, "tcp"}}}
	got, err := Resolve(context.Background(), c)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v err=%v", got, err)
	}
	if _, err := Resolve(context.Background(), &Config{}); err == nil {
		t.Error("erreur attendue sans remote")
	}
}

func TestStartStopOK(t *testing.T) {
	var logs syncBuf
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(old)

	o := testOpts(t, "ok")
	o.Username, o.Password = "alice", "S3cretPw"
	p, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if p.LocalIP() != netip.MustParseAddr("10.8.0.6") || p.Iface() != "vpntui0" {
		t.Errorf("ip=%v iface=%s", p.LocalIP(), p.Iface())
	}
	if _, err := os.Stat(filepath.Join(o.RunDir, "auth-p1")); !os.IsNotExist(err) {
		t.Errorf("fichier auth doit avoir disparu : %v", err)
	}
	st, err := os.Stat(filepath.Join(o.RunDir, "ovpn-p1.conf"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("conf d'exécution : %v %v", st, err)
	}
	conf, _ := os.ReadFile(filepath.Join(o.RunDir, "ovpn-p1.conf"))
	if string(conf) != "client\nremote 203.0.113.1 1194 udp\n" {
		t.Errorf("conf = %q", conf)
	}
	var seen []string
	for len(p.States()) > 0 {
		seen = append(seen, <-p.States())
	}
	if len(seen) == 0 || seen[len(seen)-1] != "CONNECTED" {
		t.Errorf("états : %v", seen)
	}
	select {
	case <-p.Dead():
		t.Error("Dead ne devrait pas être fermé")
	default:
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	<-p.Dead()
	select {
	case <-p.exited:
	default:
		t.Error("processus non terminé")
	}
	assertClean(t, o.RunDir)
	out := logs.String()
	if strings.Contains(out, "S3cretPw") || strings.Contains(out, "alice") {
		t.Errorf("secret dans les logs : %s", out)
	}
	if !strings.Contains(out, "[redacted]") || !strings.Contains(out, "fake: started") {
		t.Errorf("logs inattendus : %s", out)
	}
}

func TestStartNoAuthFile(t *testing.T) {
	o := testOpts(t, "ok")
	p, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if _, err := os.Stat(filepath.Join(o.RunDir, "auth-p1")); !os.IsNotExist(err) {
		t.Errorf("auth-p1 ne doit pas exister : %v", err)
	}
}

func TestStartFailures(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"fail", "a quitté"},
		{"hang", "délai"},
		{"password", "authentification requise"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			o := testOpts(t, tc.mode)
			o.Username, o.Password = "alice", "S3cretPw"
			o.ConnectTimeout = 600 * time.Millisecond
			p, err := Start(context.Background(), o)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("p=%v err=%v", p, err)
			}
			assertClean(t, o.RunDir)
		})
	}
}

func TestDeadOnReconnecting(t *testing.T) {
	o := testOpts(t, "reconnect")
	p, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	select {
	case <-p.Dead():
	case <-time.After(3 * time.Second):
		t.Fatal("Dead non fermé sur RECONNECTING")
	}
}

func TestStopKillsStubborn(t *testing.T) {
	old := stopGrace
	stopGrace = 300 * time.Millisecond
	defer func() { stopGrace = old }()
	o := testOpts(t, "stubborn")
	p, err := Start(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.exited:
	default:
		t.Error("processus non terminé")
	}
	assertClean(t, o.RunDir)
}

func TestAdopt(t *testing.T) {
	if _, err := Adopt(os.Getpid(), "lo", t.TempDir()); err == nil {
		t.Fatal("adoption d'un processus non-openvpn acceptée")
	}
	if _, err := Adopt(0, "lo", t.TempDir()); err == nil {
		t.Fatal("pid 0 accepté")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "openvpn") // comm = nom du binaire
	if err := os.WriteFile(fake, []byte("#!"+sh+"\nwhile :; do sleep 1; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(fake)
	if err := cmd.Start(); err != nil {
		t.Skipf("binaire copié inexécutable : %v", err)
	}
	go cmd.Wait() // reap
	defer cmd.Process.Kill()
	os.WriteFile(filepath.Join(dir, "ovpn-x.conf"), nil, 0o600)
	oldPoll := adoptPoll
	adoptPoll = 20 * time.Millisecond
	defer func() { adoptPoll = oldPoll }()

	p, err := Adopt(cmd.Process.Pid, "lo", dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Pid() != cmd.Process.Pid {
		t.Fatal("pid")
	}
	select {
	case <-p.Dead():
		t.Fatal("mort trop tôt")
	case <-time.After(100 * time.Millisecond):
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.Dead():
	case <-time.After(time.Second):
		t.Fatal("Dead non déclenché")
	}
	if _, err := os.Stat(filepath.Join(dir, "ovpn-x.conf")); err == nil {
		t.Fatal("fichier de RunDir non nettoyé")
	}
}
