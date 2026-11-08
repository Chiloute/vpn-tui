// Package profile stores VPN profiles as <root>/profiles/<id>/{profile.toml,<config>}.
// Every filesystem access goes through os.Root so nothing can leave <root>/profiles.
package profile

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"github.com/Chiloute/vpn-tui/daemon/internal/ovpn"
	"github.com/Chiloute/vpn-tui/daemon/internal/wg"
)

const (
	TypeOpenVPN   = "openvpn"
	TypeWireGuard = "wireguard"
	DefaultColor  = "base0D"
	tomlName      = "profile.toml"
)

var (
	ErrNotFound = errors.New("profil introuvable")
	ErrExists   = errors.New("un profil avec cet identifiant existe déjà")

	idRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	tagRe   = regexp.MustCompile(`^[a-z0-9-]{1,16}$`)
	colorRe = regexp.MustCompile(`^base0[0-9A-F]$`)
)

// InvalidError is a validation failure (message in French, safe to show).
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(f string, a ...any) error { return &InvalidError{fmt.Sprintf(f, a...)} }

type Scope struct {
	CIDRs   []string `toml:"cidrs"`
	Exclude []string `toml:"exclude"`
	Learned []string `toml:"learned"`
}

type Killswitch struct {
	Enabled       bool `toml:"enabled"`
	AllowInternet bool `toml:"allow_internet"`
	BlockIPv6     bool `toml:"block_ipv6"`
}

type DNS struct {
	Servers []string `toml:"servers"`
	Force   bool     `toml:"force"`
}

type Secrets struct {
	KeyringRef string `toml:"keyring_ref"`
}

type Profile struct {
	ID         string     `toml:"id"`
	Name       string     `toml:"name"`
	Type       string     `toml:"type"`
	Config     string     `toml:"config"`
	Tags       []string   `toml:"tags"`
	Color      string     `toml:"color"`
	Scope      Scope      `toml:"scope"`
	Killswitch Killswitch `toml:"killswitch"`
	DNS        DNS        `toml:"dns"`
	Secrets    Secrets    `toml:"secrets"`
}

// Update holds the editable fields; nil means unchanged.
type Update struct {
	Name       *string
	Tags       *[]string
	Color      *string
	Scope      *Scope
	Killswitch *Killswitch
	DNS        *DNS
}

type Store struct {
	Root string
	mu   sync.Mutex
}

// Init creates <root>/profiles (0700).
func (s *Store) Init() error {
	return os.MkdirAll(filepath.Join(s.Root, "profiles"), 0o700)
}

func (s *Store) open() (*os.Root, error) {
	return os.OpenRoot(filepath.Join(s.Root, "profiles"))
}

// ValidID reports whether id is a legal profile identifier.
func ValidID(id string) bool { return idRe.MatchString(id) }

// Slug derives an id from a display name.
func Slug(name string) string {
	var b strings.Builder
	dash := true
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	out := b.String()
	if len(out) > 32 {
		out = out[:32]
	}
	return strings.Trim(out, "-")
}

func checkCIDRs(what string, l []string) error {
	if len(l) > 1024 {
		return invalid("%s : trop d'entrées (max 1024)", what)
	}
	for _, c := range l {
		p, err := netip.ParsePrefix(c)
		if err != nil || p != p.Masked() || p.Addr().Zone() != "" {
			return invalid("%s : CIDR invalide ou non canonique %q", what, c)
		}
	}
	return nil
}

func (p *Profile) validate() error {
	if !ValidID(p.ID) {
		return invalid("identifiant invalide (attendu ^[a-z0-9][a-z0-9-]{0,31}$)")
	}
	if n := utf8.RuneCountInString(p.Name); n < 1 || n > 64 {
		return invalid("nom invalide (1 à 64 caractères)")
	}
	if len(p.Tags) > 8 {
		return invalid("trop de tags (max 8)")
	}
	for _, t := range p.Tags {
		if !tagRe.MatchString(t) {
			return invalid("tag invalide %q", t)
		}
	}
	if !colorRe.MatchString(p.Color) {
		return invalid("couleur invalide %q (base00..base0F)", p.Color)
	}
	for what, l := range map[string][]string{"scope.cidrs": p.Scope.CIDRs, "scope.exclude": p.Scope.Exclude, "scope.learned": p.Scope.Learned} {
		if err := checkCIDRs(what, l); err != nil {
			return err
		}
	}
	if len(p.DNS.Servers) > 8 {
		return invalid("trop de serveurs DNS (max 8)")
	}
	for _, d := range p.DNS.Servers {
		if a, err := netip.ParseAddr(d); err != nil || a.Zone() != "" {
			return invalid("serveur DNS invalide %q", d)
		}
	}
	switch {
	case p.Type == TypeOpenVPN && p.Config == "client.ovpn", p.Type == TypeWireGuard && p.Config == "wg.conf":
	default:
		return invalid("type/config invalide")
	}
	return nil
}

// regularDir returns a sub-root for id, refusing symlinks and non-directories.
func regularDir(rt *os.Root, id string) (*os.Root, error) {
	if !ValidID(id) {
		return nil, invalid("identifiant invalide")
	}
	fi, err := rt.Lstat(id)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, invalid("entrée de profil invalide (lien symbolique ou fichier)")
	}
	return rt.OpenRoot(id)
}

func writeAtomic(d *os.Root, name string, data []byte) error {
	tmp := name + ".tmp"
	f, err := d.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0o600)
	if err != nil {
		d.Remove(tmp) // stale tmp from a crash
		if f, err = d.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil {
			return err
		}
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = d.Rename(tmp, name)
	}
	if err != nil {
		d.Remove(tmp)
	}
	return err
}

func encode(p *Profile) ([]byte, error) {
	var b bytes.Buffer
	err := toml.NewEncoder(&b).Encode(p)
	return b.Bytes(), err
}

func load(d *os.Root) (*Profile, error) {
	fi, err := d.Lstat(tomlName)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, invalid("%s n'est pas un fichier régulier", tomlName)
	}
	data, err := d.ReadFile(tomlName)
	if err != nil {
		return nil, err
	}
	var p Profile
	if _, err := toml.Decode(string(data), &p); err != nil {
		return nil, invalid("profile.toml illisible")
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) Get(id string) (*Profile, error) {
	rt, err := s.open()
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	d, err := regularDir(rt, id)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	p, err := load(d)
	if err == nil && p.ID != id {
		return nil, invalid("identifiant incohérent dans profile.toml")
	}
	return p, err
}

// ReadConfig returns the stored (sanitized) config file of the profile.
// Same confinement as Get: os.Root, symlinks refused.
func (s *Store) ReadConfig(id string) ([]byte, error) {
	rt, err := s.open()
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	d, err := regularDir(rt, id)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	p, err := load(d)
	if err != nil {
		return nil, err
	}
	fi, err := d.Lstat(p.Config)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, invalid("%s n'est pas un fichier régulier", p.Config)
	}
	return d.ReadFile(p.Config)
}

// List returns all valid profiles sorted by id; broken entries are logged by id and skipped.
func (s *Store) List() ([]*Profile, error) {
	rt, err := s.open()
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	dir, err := rt.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	ents, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := []*Profile{}
	for _, e := range ents {
		p, err := s.Get(e.Name())
		if err != nil {
			slog.Warn("profil ignoré", "id", e.Name())
			continue
		}
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *Profile) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// Import parses and sanitizes content, then stores the profile. An empty id
// is derived from the name.
func (s *Store) Import(typ, name, id, content string) (*Profile, error) {
	p := &Profile{
		ID: id, Name: name, Type: typ, Color: DefaultColor,
		Killswitch: Killswitch{true, true, true},
		Tags:       []string{}, Scope: Scope{[]string{}, []string{}, []string{}}, DNS: DNS{Servers: []string{}},
	}
	if p.ID == "" {
		p.ID = Slug(name)
	}
	var clean []byte
	switch typ {
	case TypeOpenVPN:
		p.Config = "client.ovpn"
		c, err := ovpn.Parse([]byte(content))
		if err != nil {
			return nil, err
		}
		clean = c.Sanitized
		for _, l := range strings.Split(string(clean), "\n") {
			if f := strings.Fields(l); len(f) > 0 && f[0] == "auth-user-pass" {
				p.Secrets.KeyringRef = "vpn-tui/" + p.ID
			}
		}
	case TypeWireGuard:
		p.Config = "wg.conf"
		c, err := wg.Parse([]byte(content))
		if err != nil {
			return nil, err
		}
		clean = c.Sanitized
		p.Secrets.KeyringRef = "vpn-tui/" + p.ID
	default:
		return nil, invalid("type inconnu")
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	data, err := encode(p)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	rt, err := s.open()
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	if err := rt.Mkdir(p.ID, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrExists
		}
		return nil, err
	}
	err = func() error {
		d, err := rt.OpenRoot(p.ID)
		if err != nil {
			return err
		}
		defer d.Close()
		if err := writeAtomic(d, p.Config, clean); err != nil {
			return err
		}
		return writeAtomic(d, tomlName, data)
	}()
	if err != nil {
		rt.RemoveAll(p.ID)
		return nil, err
	}
	return p, nil
}

// Update applies the editable fields; id, type, config and keyring_ref are immutable.
func (s *Store) Update(id string, u Update) (*Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, err := s.open()
	if err != nil {
		return nil, err
	}
	defer rt.Close()
	d, err := regularDir(rt, id)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	p, err := load(d)
	if err != nil {
		return nil, err
	}
	if u.Name != nil {
		p.Name = *u.Name
	}
	if u.Tags != nil {
		p.Tags = *u.Tags
	}
	if u.Color != nil {
		p.Color = *u.Color
	}
	if u.Scope != nil {
		p.Scope = *u.Scope
	}
	if u.Killswitch != nil {
		p.Killswitch = *u.Killswitch
	}
	if u.DNS != nil {
		p.DNS = *u.DNS
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	data, err := encode(p)
	if err != nil {
		return nil, err
	}
	return p, writeAtomic(d, tomlName, data)
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, err := s.open()
	if err != nil {
		return err
	}
	defer rt.Close()
	d, err := regularDir(rt, id)
	if err != nil {
		return err
	}
	d.Close()
	return rt.RemoveAll(id)
}
