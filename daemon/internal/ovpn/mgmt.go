package ovpn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var cmdTimeout = 3 * time.Second

// stateLine is a notification >STATE:<ts>,<state>,<desc>,<local_ip>,<remote_ip>,...
type stateLine struct {
	TS, Name, Desc string
	LocalIP        netip.Addr
}

// notif is an asynchronous management notification (Kind: STATE, HOLD, PASSWORD, FATAL).
type notif struct {
	Kind  string
	State stateLine // Kind == "STATE"
	Text  string    // other Kinds: raw text after ":"
}

func parseNotif(line string) (notif, bool) {
	kind, rest, ok := strings.Cut(strings.TrimPrefix(line, ">"), ":")
	if !ok || !strings.HasPrefix(line, ">") {
		return notif{}, false
	}
	switch kind {
	case "STATE":
		f := strings.Split(rest, ",")
		if len(f) < 2 || f[1] == "" {
			return notif{}, false
		}
		st := stateLine{TS: f[0], Name: f[1]}
		if len(f) > 2 {
			st.Desc = f[2]
		}
		if len(f) > 3 {
			st.LocalIP, _ = netip.ParseAddr(f[3])
		}
		if !st.LocalIP.IsValid() && len(f) > 8 { // IPv6-only tunnel
			st.LocalIP, _ = netip.ParseAddr(f[8])
		}
		st.LocalIP = st.LocalIP.Unmap()
		return notif{Kind: kind, State: st}, true
	case "HOLD", "PASSWORD", "FATAL":
		return notif{Kind: kind, Text: rest}, true
	}
	return notif{}, false
}

// mgmt is a client of OpenVPN's management interface (unix socket).
type mgmt struct {
	conn    net.Conn
	mu      sync.Mutex // one command at a time
	replies chan string
	notifs  chan notif // closed when the connection ends
	done    chan struct{}
}

func dialMgmt(path string) (*mgmt, error) {
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return nil, err
	}
	m := &mgmt{conn: c, replies: make(chan string, 8), notifs: make(chan notif, 64), done: make(chan struct{})}
	go m.read()
	return m, nil
}

func (m *mgmt) read() {
	defer close(m.notifs)
	defer close(m.done)
	sc := bufio.NewScanner(m.conn)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "SUCCESS:") || strings.HasPrefix(line, "ERROR:") {
			select {
			case m.replies <- line:
			default:
			}
		} else if n, ok := parseNotif(line); ok {
			m.notifs <- n
		}
	}
}

// command sends cmd and waits for the SUCCESS:/ERROR: reply.
func (m *mgmt) command(cmd string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conn.SetWriteDeadline(time.Now().Add(cmdTimeout))
	if _, err := io.WriteString(m.conn, cmd+"\n"); err != nil {
		return err
	}
	select {
	case r := <-m.replies:
		if strings.HasPrefix(r, "ERROR:") {
			return fmt.Errorf("management %q: %s", cmd, r)
		}
		return nil
	case <-m.done:
		return errors.New("management closed")
	case <-time.After(cmdTimeout):
		return fmt.Errorf("management %q: no response", cmd)
	}
}

func (m *mgmt) Close() { m.conn.Close() }
