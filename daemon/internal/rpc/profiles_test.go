package rpc

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Chiloute/vpn-tui/daemon/internal/profile"
	"github.com/Chiloute/vpn-tui/proto"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func startStore(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	st := &profile.Store{Root: root}
	if err := st.Init(); err != nil {
		t.Fatal(err)
	}
	s, _ := New()
	s.Member, s.IdleTimeout, s.ReadTimeout, s.Store = allow, time.Minute, 5*time.Second, st
	return serve(t, s), root
}

func rd(t *testing.T, p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func req(t *testing.T, path, method string, params any) map[string]any {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	m, _ := call(t, path, string(b))
	return m
}

func validate(t *testing.T, m map[string]any, def string) {
	t.Helper()
	doc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(proto.Schema))
	c := jsonschema.NewCompiler()
	c.AddResource(schemaBase, doc)
	for _, d := range []string{"response", def} {
		sch, err := c.Compile(schemaBase + "#/$defs/" + d)
		if err != nil {
			t.Fatal(err)
		}
		var v any = m
		if d != "response" {
			v = m["result"]
		}
		if err := sch.Validate(v); err != nil {
			t.Errorf("%s: %v (%v)", d, err, m)
		}
	}
}

func TestProfileRPC(t *testing.T) {
	path, _ := startStore(t)
	thm := rd(t, "../ovpn/testdata/thm.ovpn")
	wgc := rd(t, "../wg/testdata/client.conf")

	m := req(t, path, "profile_import", map[string]any{"type": "openvpn", "name": "THM", "content": thm})
	validate(t, m, "result_profile_import")
	if m["result"].(map[string]any)["id"] != "thm" {
		t.Fatal(m)
	}
	m = req(t, path, "profile_import", map[string]any{"type": "wireguard", "name": "w", "id": "w", "content": wgc})
	validate(t, m, "result_profile_import")
	if m["result"].(map[string]any)["has_secrets"] != true {
		t.Fatal(m)
	}
	if m = req(t, path, "profile_import", map[string]any{"type": "wireguard", "name": "w", "id": "w", "content": wgc}); code(m) != CodeImportRejected {
		t.Fatalf("dup: %v", m)
	}
	m = req(t, path, "list", map[string]any{})
	validate(t, m, "result_list")
	if len(m["result"].(map[string]any)["profiles"].([]any)) != 2 {
		t.Fatal(m)
	}
	m = req(t, path, "profile_update", map[string]any{"id": "w", "name": "new", "tags": []string{"a"}, "color": "base0D"})
	validate(t, m, "result_profile_update")
	if m["result"].(map[string]any)["color"] != "base0D" {
		t.Fatal(m)
	}
	for _, c := range []string{"#ff0000", "base10"} {
		if req(t, path, "profile_update", map[string]any{"id": "w", "color": c})["error"] == nil {
			t.Fatalf("color %q accepted", c)
		}
	}
	if code(req(t, path, "profile_update", map[string]any{"id": "w", "scope": map[string]any{"cidrs": []string{"10.0.0.1/8"}, "exclude": []string{}, "learned": []string{}}})) != CodeImportRejected {
		t.Fatal("non canonical accepted")
	}
	if code(req(t, path, "profile_update", map[string]any{"id": "nope"})) != CodeNotFound {
		t.Fatal("want not_found")
	}
	m = req(t, path, "profile_delete", map[string]any{"id": "w"})
	validate(t, m, "result_profile_delete")
	if code(req(t, path, "profile_delete", map[string]any{"id": "w"})) != CodeNotFound {
		t.Fatal("want not_found")
	}
}

func TestImportRejectedNoSecretOnDisk(t *testing.T) {
	path, root := startStore(t)
	for _, f := range []string{"evil-up.ovpn", "thm-with-secrets.ovpn"} {
		m := req(t, path, "profile_import", map[string]any{"type": "openvpn", "name": "x", "content": rd(t, "../ovpn/testdata/"+f)})
		if code(m) != CodeImportRejected {
			t.Fatalf("%s: %v", f, m)
		}
		validate(t, m, "response")
	}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		t.Errorf("unexpected file %s", p)
		return nil
	})
}

func TestNoSecretInLogs(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	path, _ := startStore(t)
	const marker = "MARKER-s3cr3t-zzz"
	for _, c := range []string{rd(t, "../ovpn/testdata/thm.ovpn") + "\n# " + marker + "\n", "client\nauth-user-pass " + marker + "\n"} {
		req(t, path, "profile_import", map[string]any{"type": "openvpn", "name": "m", "content": c})
	}
	if buf.Len() == 0 || strings.Contains(buf.String(), marker) {
		t.Fatalf("logs empty or leaking: %q", buf.String())
	}
}
