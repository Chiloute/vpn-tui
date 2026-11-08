package profile

import (
	"bytes"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Chiloute/vpn-tui/daemon/internal/ovpn"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newStore(t *testing.T) *Store {
	s := &Store{Root: t.TempDir()}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreLifecycle(t *testing.T) {
	s := newStore(t)
	thm := read(t, "../ovpn/testdata/thm.ovpn")
	wgc := read(t, "../wg/testdata/client.conf")

	p, err := s.Import("openvpn", "THM Room 1", "", thm)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "thm-room-1" || p.Config != "client.ovpn" || p.Color != "base0D" {
		t.Fatalf("%+v", p)
	}
	w, err := s.Import("wireguard", "wg", "wg1", wgc)
	if err != nil || w.Secrets.KeyringRef != "vpn-tui/wg1" {
		t.Fatalf("%v %+v", err, w)
	}
	if _, err := s.Import("wireguard", "wg", "wg1", wgc); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}

	// permissions
	for path, want := range map[string]fs.FileMode{
		"profiles":                         0o700,
		"profiles/wg1":                     0o700,
		"profiles/wg1/profile.toml":        0o600,
		"profiles/wg1/wg.conf":             0o600,
		"profiles/thm-room-1/client.ovpn":  0o600,
		"profiles/thm-room-1/profile.toml": 0o600,
	} {
		fi, err := os.Stat(filepath.Join(s.Root, path))
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v", path, fi, err)
		}
	}

	l, err := s.List()
	if err != nil || len(l) != 2 || l[0].ID != "thm-room-1" {
		t.Fatalf("%v %v", l, err)
	}

	name, cidrs := "renamed", []string{"10.10.0.0/16"}
	u, err := s.Update("wg1", Update{Name: &name, Scope: &Scope{CIDRs: cidrs, Exclude: []string{}, Learned: []string{}}})
	if err != nil || u.Name != "renamed" || u.Type != "wireguard" || u.Secrets.KeyringRef != "vpn-tui/wg1" {
		t.Fatalf("%v %+v", err, u)
	}
	g, _ := s.Get("wg1")
	if g.Scope.CIDRs[0] != "10.10.0.0/16" {
		t.Fatal("not persisted")
	}
	bad := []string{"10.10.0.1/16"}
	if _, err := s.Update("wg1", Update{Scope: &Scope{CIDRs: bad}}); err == nil {
		t.Fatal("non canonical CIDR accepted")
	}
	for _, col := range []string{"red", "#ff0000", "base10"} {
		if _, err := s.Update("wg1", Update{Color: &col}); err == nil {
			t.Fatalf("bad color %q accepted", col)
		}
	}
	col := "base0D"
	if u, err := s.Update("wg1", Update{Color: &col}); err != nil || u.Color != "base0D" {
		t.Fatalf("base0D refused: %v", err)
	}

	if err := s.Delete("wg1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("wg1"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.Delete("wg1"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestBadIDsAndSymlink(t *testing.T) {
	s := newStore(t)
	thm := read(t, "../ovpn/testdata/thm.ovpn")
	for _, id := range []string{"../x", "A", "a/b", "-a", ""} {
		if id == "" {
			continue // empty means "derive from name"
		}
		if _, err := s.Import("openvpn", "x", id, thm); err == nil {
			t.Errorf("import id %q accepted", id)
		}
		if _, err := s.Get(id); err == nil {
			t.Errorf("get id %q accepted", id)
		}
		if err := s.Delete(id); err == nil {
			t.Errorf("delete id %q accepted", id)
		}
	}
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "profile.toml"), []byte("x"), 0o600)
	if err := os.Symlink(outside, filepath.Join(s.Root, "profiles", "evil")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("evil"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("symlink get: %v", err)
	}
	if _, err := s.Update("evil", Update{}); err == nil {
		t.Error("symlink update accepted")
	}
	if err := s.Delete("evil"); err == nil {
		t.Error("symlink delete accepted")
	}
	if _, err := s.Import("openvpn", "x", "evil", thm); !errors.Is(err, ErrExists) {
		t.Errorf("import over symlink: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "client.ovpn")); err == nil {
		t.Error("wrote through symlink")
	}
	if l, _ := s.List(); len(l) != 0 {
		t.Errorf("symlink listed: %v", l)
	}
}

func TestListSkipsAndLogsBroken(t *testing.T) {
	s := newStore(t)
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	if err := os.Mkdir(filepath.Join(s.Root, "profiles", "broken"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(s.Root, "profiles", "broken", "profile.toml"), []byte("not toml ="), 0o600)
	l, err := s.List()
	if err != nil || len(l) != 0 {
		t.Fatalf("%v %v", l, err)
	}
	if !strings.Contains(buf.String(), "broken") {
		t.Fatalf("no warning with id: %q", buf.String())
	}
}

func TestRejectedImportLeavesNothing(t *testing.T) {
	s := newStore(t)
	for _, f := range []string{"thm-with-secrets.ovpn", "evil-up.ovpn"} {
		_, err := s.Import("openvpn", "x", "", read(t, "../ovpn/testdata/"+f))
		var re *ovpn.RejectError
		if !errors.As(err, &re) {
			t.Fatalf("%s: %v", f, err)
		}
	}
	filepath.WalkDir(s.Root, func(p string, d fs.DirEntry, err error) error {
		if !d.IsDir() {
			t.Errorf("unexpected file %s", p)
		}
		return nil
	})
	if strings.Contains(Slug("  Été  --Box!! "), "--") || Slug("!!!") != "" {
		t.Error("slug")
	}
}

func TestReadConfig(t *testing.T) {
	s := newStore(t)
	if _, err := s.Import("wireguard", "wg", "wg1", read(t, "../wg/testdata/client.conf")); err != nil {
		t.Fatal(err)
	}
	b, err := s.ReadConfig("wg1")
	if err != nil || !strings.Contains(string(b), "[Peer]") {
		t.Fatalf("%v %q", err, b)
	}
	if _, err := s.ReadConfig("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	cfg := filepath.Join(s.Root, "profiles", "wg1", "wg.conf")
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("x"), 0o600)
	os.Remove(cfg)
	if err := os.Symlink(secret, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadConfig("wg1"); err == nil {
		t.Fatal("lien symbolique accepté")
	}
}
