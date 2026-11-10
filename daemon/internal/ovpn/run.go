package ovpn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/netinfo"
)

var stopGrace = 5 * time.Second

// Resolved est une adresse de serveur déjà résolue.
type Resolved struct {
	IP    netip.Addr
	Port  int
	Proto string
}

// Resolve résout chaque remote (IPv4 et IPv6) et dédoublonne.
func Resolve(ctx context.Context, c *Config) ([]Resolved, error) {
	var out []Resolved
	seen := map[Resolved]bool{}
	var errs []error
	for _, r := range c.Remotes {
		ips := []netip.Addr{}
		if a, err := netip.ParseAddr(r.Host); err == nil {
			ips = append(ips, a)
		} else if ips, err = net.DefaultResolver.LookupNetIP(ctx, "ip", r.Host); err != nil {
			errs = append(errs, err)
			continue
		}
		for _, ip := range ips {
			x := Resolved{ip.Unmap(), r.Port, r.Proto}
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.Join(append([]error{errors.New("no server address resolved")}, errs...)...)
	}
	return out, nil
}

// StartOpts décrit le lancement d'OpenVPN.
type StartOpts struct {
	Bin                string // exec.LookPath("openvpn") si vide
	RunDir             string // ex. /run/vpn-tui (0700)
	ID                 string // id de profil déjà validé
	Iface              string
	Config             *Config
	Remotes            []Resolved // seules ces IP sont écrites dans la config d'exécution
	Username, Password string     // vides si pas d'auth-user-pass
	User, Group        string     // vides = pas de drop de privilèges
	ConnectTimeout     time.Duration
}

// Process est un OpenVPN en cours d'exécution.
type Process struct {
	o                   StartOpts
	conf, auth, sock    string
	cmd                 *exec.Cmd
	m                   *mgmt
	states              chan string
	dead, exited        chan struct{}
	connected, consumed chan struct{}
	deadOnce, connOnce  sync.Once
	stopOnce            sync.Once
	stopErr             error
	mu                  sync.Mutex
	localIP             netip.Addr
	failErr, waitErr    error
	pid                 int      // adopted process only (cmd == nil)
	files               []string // adopted process: runtime files removed by Stop
}

// Pid returns the OpenVPN process id (0 if unknown).
func (p *Process) Pid() int {
	if p.cmd != nil {
		return p.cmd.Process.Pid
	}
	return p.pid
}

func (p *Process) Dead() <-chan struct{} { return p.dead }
func (p *Process) States() <-chan string { return p.states }
func (p *Process) Iface() string         { return p.o.Iface }
func (p *Process) markDead()             { p.deadOnce.Do(func() { close(p.dead) }) }
func (p *Process) LocalIP() netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.localIP
}

func (p *Process) fail(err error) {
	p.mu.Lock()
	if p.failErr == nil {
		p.failErr = err
	}
	p.mu.Unlock()
	p.markDead()
}

// runtimeConf retire remote/remote-random/dev/dev-type (hors blocs) et ajoute les IP résolues.
func runtimeConf(san []byte, rs []Resolved) []byte {
	var out bytes.Buffer
	block := ""
	for _, l := range strings.Split(string(san), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == "":
			continue
		case block != "":
			if t == "</"+block+">" {
				block = ""
			}
		case strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">"):
			block = t[1 : len(t)-1]
		default:
			switch strings.Fields(t)[0] {
			case "remote", "remote-random", "dev", "dev-type":
				continue
			}
		}
		out.WriteString(t + "\n")
	}
	for _, r := range rs {
		fmt.Fprintf(&out, "remote %s %d %s\n", r.IP, r.Port, r.Proto)
	}
	return out.Bytes()
}

// buildArgs : jamais de shell ; les options du daemon suivent --config pour l'emporter.
func buildArgs(o StartOpts, conf, sock, auth string) []string {
	a := []string{"--config", conf, "--dev", o.Iface, "--dev-type", "tun", "--script-security", "1",
		"--management", sock, "unix", "--management-hold", "--management-query-passwords"}
	if o.Username != "" {
		a = append(a, "--auth-user-pass", auth)
	}
	a = append(a, "--auth-nocache", "--auth-retry", "none", "--verb", "3")
	if o.User != "" {
		a = append(a, "--user", o.User)
	}
	if o.Group != "" {
		a = append(a, "--group", o.Group)
	}
	return a
}

// redact masque les secrets d'une ligne de log d'OpenVPN.
func redact(line, user, pass string) string {
	for _, s := range []string{user, pass} {
		if s != "" && strings.Contains(line, s) {
			return "[redacted]"
		}
	}
	if strings.Contains(line, "PUSH_REPLY") {
		f := strings.Split(line, ",")
		for i, x := range f {
			if strings.Contains(x, "auth-token") {
				f[i] = "auth-token [redacted]"
			}
		}
		return strings.Join(f, ",")
	}
	if strings.Contains(line, "auth-token") {
		return "[redacted]"
	}
	return line
}

func writeNew(path string, data []byte) error {
	os.Remove(path) // résidu éventuel ; O_EXCL empêche de suivre un lien
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (p *Process) logLines(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		slog.Info("openvpn", "line", redact(sc.Text(), p.o.Username, p.o.Password))
	}
	io.Copy(io.Discard, r) // ne jamais bloquer OpenVPN sur un pipe plein
}

func (p *Process) consume() {
	defer close(p.consumed)
	for n := range p.m.notifs {
		switch n.Kind {
		case "STATE":
			select {
			case p.states <- n.State.Name:
			default:
			}
			switch n.State.Name {
			case "CONNECTED":
				p.mu.Lock()
				p.localIP = n.State.LocalIP
				p.mu.Unlock()
				p.connOnce.Do(func() { close(p.connected) })
			case "RECONNECTING", "EXITING":
				p.markDead()
			}
		case "PASSWORD":
			p.fail(errors.New("authentication required"))
		case "FATAL":
			p.fail(fmt.Errorf("openvpn fatal: %s", n.Text))
		}
	}
	p.markDead()
}

func (p *Process) deadErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failErr != nil {
		return p.failErr
	}
	select {
	case <-p.exited:
		return fmt.Errorf("openvpn exited before CONNECTED: %v", p.waitErr)
	default:
		return errors.New("management broken before CONNECTED")
	}
}

// Start lance OpenVPN et bloque jusqu'à CONNECTED ; en cas d'échec tout est nettoyé.
// testEnv lets tests reach the fake openvpn; always empty in the daemon.
var testEnv []string

func Start(ctx context.Context, o StartOpts) (_ *Process, err error) {
	if o.Bin == "" {
		if o.Bin, err = exec.LookPath("openvpn"); err != nil {
			return nil, err
		}
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 60 * time.Second
	}
	if o.Config == nil || len(o.Remotes) == 0 || o.RunDir == "" || o.ID == "" || o.Iface == "" {
		return nil, errors.New("incomplete launch options")
	}
	if strings.ContainsAny(o.Username+o.Password, "\n\r\x00") {
		return nil, errors.New("invalid credentials (newline)")
	}
	p := &Process{
		o: o, conf: filepath.Join(o.RunDir, "ovpn-"+o.ID+".conf"), auth: filepath.Join(o.RunDir, "auth-"+o.ID),
		sock:   filepath.Join(o.RunDir, "ovpn-mgmt.sock"),
		states: make(chan string, 16), dead: make(chan struct{}), exited: make(chan struct{}),
		connected: make(chan struct{}), consumed: make(chan struct{}),
	}
	defer func() {
		if o.Username != "" {
			os.Remove(p.auth)
		}
		if err != nil {
			p.Stop()
		}
	}()
	if err = os.MkdirAll(o.RunDir, 0o700); err != nil {
		return nil, err
	}
	if err = writeNew(p.conf, runtimeConf(o.Config.Sanitized, o.Remotes)); err != nil {
		return nil, err
	}
	if o.Username != "" {
		if err = writeNew(p.auth, []byte(o.Username+"\n"+o.Password+"\n")); err != nil {
			return nil, err
		}
	}
	os.Remove(p.sock)

	cmd := exec.Command(o.Bin, buildArgs(o, p.conf, p.sock, p.auth)...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, testEnv...) // rien d'autre ne fuit vers OpenVPN
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err = cmd.Start(); err != nil {
		return nil, err
	}
	p.cmd = cmd
	var wg sync.WaitGroup
	for _, r := range []io.Reader{stdout, stderr} {
		wg.Add(1)
		go func() { defer wg.Done(); p.logLines(r) }()
	}
	go func() {
		wg.Wait()
		werr := cmd.Wait()
		p.mu.Lock()
		p.waitErr = werr
		p.mu.Unlock()
		close(p.exited)
		p.markDead()
	}()

	dctx, cancel := context.WithTimeout(ctx, o.ConnectTimeout)
	defer cancel()
	for p.m == nil {
		m, derr := dialMgmt(p.sock)
		if derr == nil {
			p.m = m
			break
		}
		select {
		case <-dctx.Done():
			return nil, ctxErr(dctx)
		case <-p.exited:
			return nil, p.deadErr()
		case <-time.After(20 * time.Millisecond):
		}
	}
	go p.consume()
	if err = p.m.command("state on"); err == nil {
		err = p.m.command("hold release")
	}
	if err != nil {
		return nil, err
	}
	select {
	case <-p.connected:
		return p, nil
	case <-p.dead:
		select { // laisse consume() lire une éventuelle cause (>PASSWORD, >FATAL)
		case <-p.consumed:
		case <-time.After(time.Second):
		}
		return nil, p.deadErr()
	case <-dctx.Done():
		return nil, ctxErr(dctx)
	}
}

func ctxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("OpenVPN connection timeout exceeded")
	}
	return ctx.Err()
}

func (p *Process) waitExit(d time.Duration) bool {
	select {
	case <-p.exited:
		return true
	case <-time.After(d):
		return false
	}
}

// Stop arrête OpenVPN (management, puis SIGTERM, puis SIGKILL), attend sa fin et nettoie. Idempotent.
func (p *Process) Stop() error {
	p.stopOnce.Do(func() {
		defer func() {
			for _, f := range append([]string{p.conf, p.auth, p.sock}, p.files...) {
				os.Remove(f)
			}
		}()
		if p.cmd == nil {
			p.stopAdopted()
			return
		}
		if p.m != nil {
			defer p.m.Close()
			select {
			case <-p.exited:
			default:
				p.m.command("signal SIGTERM")
			}
			if p.waitExit(stopGrace) {
				return
			}
		}
		p.cmd.Process.Signal(syscall.SIGTERM)
		if p.waitExit(stopGrace) {
			return
		}
		p.cmd.Process.Kill()
		if !p.waitExit(stopGrace) {
			p.stopErr = errors.New("openvpn does not respond to SIGKILL (pid " + strconv.Itoa(p.cmd.Process.Pid) + ")")
		}
	})
	return p.stopErr
}

func isOpenVPN(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	return err == nil && strings.TrimSpace(string(b)) == "openvpn"
}

var adoptPoll = 500 * time.Millisecond

// Adopt attaches to an OpenVPN started by a previous daemon. It refuses any pid
// whose /proc/<pid>/comm is not "openvpn". Dead fires when the process or iface disappears.
func Adopt(pid int, iface, runDir string) (*Process, error) {
	if pid <= 1 || !isOpenVPN(pid) {
		return nil, fmt.Errorf("pid %d is not an openvpn process", pid)
	}
	p := &Process{o: StartOpts{Iface: iface, RunDir: runDir}, pid: pid, dead: make(chan struct{}), exited: make(chan struct{})}
	for _, g := range []string{"ovpn-*.conf", "auth-*", "ovpn-mgmt.sock"} {
		m, _ := filepath.Glob(filepath.Join(runDir, g))
		p.files = append(p.files, m...)
	}
	go func() {
		t := time.NewTicker(adoptPoll)
		defer t.Stop()
		for {
			if !isOpenVPN(pid) { // gone, or pid reused by something else
				close(p.exited)
				p.markDead()
				return
			}
			if !netinfo.Exists(iface) {
				p.markDead()
			}
			<-t.C
		}
	}()
	return p, nil
}

func (p *Process) stopAdopted() {
	if p.pid == 0 {
		return
	}
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		if !isOpenVPN(p.pid) {
			return
		}
		syscall.Kill(p.pid, sig)
		if p.waitExit(stopGrace) {
			return
		}
	}
	p.stopErr = errors.New("openvpn does not respond to SIGKILL (pid " + strconv.Itoa(p.pid) + ")")
}
