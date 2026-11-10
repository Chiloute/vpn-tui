// Package rpc implements the NDJSON JSON-RPC 2.0 server of vpn-tuid.
package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os/user"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Chiloute/vpn-tui/proto"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/sys/unix"
)

const (
	MaxMessage = 64 * 1024
	schemaBase = "https://github.com/Chiloute/vpn-tui/proto/rpc.schema.json"

	CodeParse       = -32700
	CodeInvalidReq  = -32600
	CodeInvalidPar  = -32602
	CodeForbidden   = -32001
	CodeTooLarge    = -32002
	CodeNotImplemen = -32003
)

type Server struct {
	// Member reports whether uid may use the daemon (root is always allowed).
	Member      func(uid uint32) (bool, error)
	ReadTimeout time.Duration
	IdleTimeout time.Duration
	// Busy extends the lifetime of the daemon (e.g. an active VPN).
	Busy func() bool

	request, response *jsonschema.Schema
	active            atomic.Int64
	lastActive        atomic.Int64 // unix nanos
}

func New() (*Server, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(proto.Schema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(schemaBase, doc); err != nil {
		return nil, err
	}
	s := &Server{ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, Busy: func() bool { return false }}
	if s.request, err = c.Compile(schemaBase + "#/$defs/request"); err != nil {
		return nil, err
	}
	if s.response, err = c.Compile(schemaBase + "#/$defs/response"); err != nil {
		return nil, err
	}
	return s, nil
}

// GroupMember returns a Member func based on membership of the named group.
// os/user keeps this working with CGO_ENABLED=0 (reads /etc/group).
func GroupMember(group string) func(uint32) (bool, error) {
	return func(uid uint32) (bool, error) {
		if uid == 0 {
			return true, nil
		}
		g, err := user.LookupGroup(group)
		if err != nil {
			return false, err
		}
		u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
		if err != nil {
			return false, err
		}
		gids, err := u.GroupIds()
		return slices.Contains(gids, g.Gid), err
	}
}

// Serve accepts connections until ctx is done or the daemon has been idle
// (no connection, not Busy) for IdleTimeout. It closes ln on return.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	defer ln.Close()
	s.lastActive.Store(time.Now().UnixNano())
	var idle atomic.Bool
	go func() {
		t := time.NewTicker(max(s.IdleTimeout/4, time.Millisecond))
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				ln.Close()
				return
			case <-t.C:
				quiet := time.Since(time.Unix(0, s.lastActive.Load()))
				if s.active.Load() == 0 && !s.Busy() && quiet >= s.IdleTimeout {
					idle.Store(true)
					ln.Close()
					return
				}
				if s.Busy() {
					s.lastActive.Store(time.Now().UnixNano())
				}
			}
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || idle.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.active.Add(1)
		go func() {
			defer func() { s.lastActive.Store(time.Now().UnixNano()); s.active.Add(-1) }()
			s.handle(conn)
		}()
	}
}

func peerUcred(c net.Conn) (*unix.Ucred, error) {
	rc, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var serr error
	if err := rc.Control(func(fd uintptr) { cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return nil, err
	}
	return cred, serr
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type reply struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

func send(w net.Conn, id any, result any, e *rpcError) {
	b, _ := json.Marshal(reply{"2.0", id, result, e})
	w.Write(append(b, '\n'))
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	cred, err := peerUcred(conn)
	if err != nil {
		slog.Error("SO_PEERCRED failed", "err", err)
		return
	}
	ok := cred.Uid == 0
	if !ok {
		ok, err = s.Member(cred.Uid)
		if err != nil {
			slog.Error("group lookup failed", "uid", cred.Uid, "err", err)
		}
	}
	if !ok {
		slog.Warn("connection refused", "uid", cred.Uid, "pid", cred.Pid)
		// Drain the pending request: closing with unread data sends RST and the client loses the reply.
		conn.SetReadDeadline(time.Now().Add(time.Second))
		bufio.NewScanner(conn).Scan()
		send(conn, nil, nil, &rpcError{CodeForbidden, "forbidden"})
		return
	}

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), MaxMessage+2)
	for {
		conn.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		if !sc.Scan() {
			if errors.Is(sc.Err(), bufio.ErrTooLong) {
				send(conn, nil, nil, &rpcError{CodeTooLarge, "too_large"})
			}
			return
		}
		line := sc.Bytes()
		if len(line) > MaxMessage {
			send(conn, nil, nil, &rpcError{CodeTooLarge, "too_large"})
			return
		}
		id, res, e := s.dispatch(line)
		send(conn, id, res, e)
	}
}

func (s *Server) dispatch(line []byte) (any, any, *rpcError) {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(line))
	if err != nil {
		return nil, nil, &rpcError{CodeParse, "parse error"}
	}
	if err := s.request.Validate(v); err != nil {
		// Distinguish a bad params object from a bad envelope.
		if m, ok := v.(map[string]any); ok {
			if _, has := m["params"]; has {
				delete(m, "params")
				if s.request.Validate(m) == nil {
					return nil, nil, &rpcError{CodeInvalidPar, "invalid params"}
				}
			}
		}
		return nil, nil, &rpcError{CodeInvalidReq, "invalid request"}
	}
	m := v.(map[string]any)
	if m["method"] == "status" {
		return m["id"], disarmedStatus, nil
	}
	return m["id"], nil, &rpcError{CodeNotImplemen, "not_implemented"}
}

var disarmedStatus = map[string]any{
	"state": "disarmed", "profile": nil, "killswitch": false, "lhost": nil,
	"scope": []string{}, "since": nil, "reconnect": map[string]int{"attempt": 0, "max": 0},
	"interface": nil, "rx_bytes": 0, "tx_bytes": 0,
}
