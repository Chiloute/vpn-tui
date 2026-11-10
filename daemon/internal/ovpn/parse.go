// Package ovpn parse les configurations OpenVPN importées avec une liste
// blanche stricte. Le résultat est exécuté par OpenVPN en root : toute
// directive inconnue est refusée.
//
// Choix : une directive préfixée de "--" est refusée (pas de normalisation).
// La sensibilité à la casse est celle d'OpenVPN. Les commentaires (# ou ;)
// ne sont reconnus qu'en début de ligne, comme dans OpenVPN.
package ovpn

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxSize est la taille maximale acceptée d'un fichier .ovpn.
const MaxSize = 48 * 1024

// Remote est un serveur extrait d'une directive remote.
type Remote struct {
	Host  string
	Port  int
	Proto string // "udp" ou "tcp"
}

// Config est le résultat d'un Parse réussi.
type Config struct {
	Remotes   []Remote
	Sanitized []byte
}

// RejectError décrit le refus d'une config.
type RejectError struct {
	Line      int
	Directive string
	Reason    string
}

func (e *RejectError) Error() string {
	if e.Line == 0 {
		return e.Reason
	}
	return fmt.Sprintf("ligne %d : directive « %s » %s", e.Line, e.Directive, e.Reason)
}

const (
	reasonNotAllowed = "non autorisée"
	reasonFile       = "interdite (référence un fichier externe : seuls les blocs intégrés sont acceptés)"
	reasonSecret     = "secret en clair : le client doit l'extraire vers le keyring"
)

var dangerous = map[string]string{
	"up":                    "interdite (exécute un script)",
	"down":                  "interdite (exécute un script)",
	"route-up":              "interdite (exécute un script)",
	"route-pre-down":        "interdite (exécute un script)",
	"ipchange":              "interdite (exécute une commande)",
	"tls-verify":            "interdite (exécute un script)",
	"learn-address":         "interdite (exécute un script)",
	"client-connect":        "interdite (exécute un script)",
	"client-disconnect":     "interdite (exécute un script)",
	"auth-user-pass-verify": "interdite (exécute un script)",
	"script-security":       "interdite (autorise l'exécution de scripts)",
	"plugin":                "interdite (charge du code natif)",
	"iproute":               "interdite (exécute un programme arbitraire)",
	"config":                "interdite (inclut un fichier externe)",
	"cd":                    "interdite (change de répertoire)",
	"chroot":                "interdite (change la racine)",
	"writepid":              "interdite (écrit un fichier arbitraire)",
	"log":                   "interdite (écrit un fichier arbitraire)",
	"log-append":            "interdite (écrit un fichier arbitraire)",
	"status":                "interdite (écrit un fichier arbitraire)",
	"daemon":                "interdite (change le mode d'exécution)",
	"ca":                    reasonFile,
	"cert":                  reasonFile,
	"key":                   reasonFile,
	"tls-auth":              reasonFile,
	"tls-crypt":             reasonFile,
	"tls-crypt-v2":          reasonFile,
	"askpass":               reasonFile,
}

var dangerousPrefix = map[string]string{
	"management": "interdite (ouvre une interface de contrôle)",
	"setenv":     "interdite (modifie l'environnement)",
	"pkcs11-":    "interdite (charge une bibliothèque externe)",
}

// kinds de validation d'arguments.
type argSpec func(args []string) string // renvoie "" si OK, sinon le détail

var (
	none    = func(a []string) string { return exact(a, 0) }
	oneInt  = func(a []string) string { return ints(a, 1, 1) }
	oneName = func(a []string) string { return names(a, 1, 1) }
	// cipher/auth "none" would send the tunnel in clear text.
	cryptoName = func(a []string) string {
		if len(a) == 1 && strings.EqualFold(a[0], "none") {
			return "« none » interdit (trafic en clair)"
		}
		return oneName(a)
	}
)

var allowed = map[string]argSpec{
	"client": none, "nobind": none, "persist-key": none, "persist-tun": none,
	"remote-random": none, "auth-nocache": none, "pull": none,
	"route-nopull": none, "block-outside-dns": none, "auth-user-pass": none,
	"dev":      lit("tun"),
	"dev-type": lit("tun"),
	"proto": func(a []string) string {
		if exact(a, 1) != "" {
			return exact(a, 1)
		}
		if _, ok := normProto(a[0]); !ok {
			return "protocole inconnu"
		}
		return ""
	},
	"resolv-retry": func(a []string) string {
		if len(a) == 1 && a[0] == "infinite" {
			return ""
		}
		return oneInt(a)
	},
	"remote-cert-tls":       func(a []string) string { return oneOf(a, "server", "client") },
	"key-direction":         func(a []string) string { return oneOf(a, "0", "1") },
	"comp-lzo":              lit("no"),
	"allow-compression":     lit("no"),
	"verify-x509-name":      verifyName,
	"cipher":                cryptoName,
	"data-ciphers":          oneName,
	"data-ciphers-fallback": oneName,
	"auth":                  cryptoName,
	"tls-cipher":            oneName,
	"tls-version-min": func(a []string) string {
		if len(a) == 2 && a[1] != "or-highest" {
			return "second argument attendu : or-highest"
		}
		if len(a) == 0 || len(a) > 2 {
			return "1 ou 2 arguments attendus"
		}
		return names(a, 1, 2)
	},
	"explicit-exit-notify": func(a []string) string { return ints(a, 0, 1) },
	"verb":                 oneInt, "mute": oneInt, "ping": oneInt, "ping-restart": oneInt,
	"connect-timeout": oneInt, "server-poll-timeout": oneInt,
	"connect-retry":    func(a []string) string { return ints(a, 1, 2) },
	"redirect-gateway": redirectGW,
	"route":            routeArgs,
}

func lit(v string) argSpec {
	return func(a []string) string {
		if len(a) != 1 || a[0] != v {
			return "seule la valeur « " + v + " » est acceptée"
		}
		return ""
	}
}

func oneOf(a []string, vals ...string) string {
	if len(a) == 1 {
		for _, v := range vals {
			if a[0] == v {
				return ""
			}
		}
	}
	return "valeur attendue : " + strings.Join(vals, "|")
}

func exact(a []string, n int) string {
	if len(a) != n {
		return fmt.Sprintf("%d argument(s) attendu(s)", n)
	}
	return ""
}

func isInt(s string) bool {
	if s == "" || len(s) > 9 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ints(a []string, min, max int) string {
	if len(a) < min || len(a) > max {
		return "nombre d'arguments incorrect"
	}
	for _, s := range a {
		if !isInt(s) {
			return "entier attendu"
		}
	}
	return ""
}

// isName : jeton sûr (algorithmes, noms de certificat...), sans espace ni métacaractère.
func isName(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_.:+!@=/", r):
		default:
			return false
		}
	}
	return true
}

func names(a []string, min, max int) string {
	if len(a) < min || len(a) > max {
		return "nombre d'arguments incorrect"
	}
	for _, s := range a {
		if !isName(s) {
			return "caractères non autorisés"
		}
	}
	return ""
}

func verifyName(a []string) string {
	if len(a) < 1 || len(a) > 2 {
		return "1 ou 2 arguments attendus"
	}
	if len(a) == 2 && a[1] != "name" && a[1] != "name-prefix" && a[1] != "subject" {
		return "type inconnu"
	}
	return names(a[:1], 1, 1)
}

func redirectGW(a []string) string {
	for _, s := range a {
		switch s {
		case "local", "autolocal", "def1", "bypass-dhcp", "bypass-dns", "block-local", "ipv6", "!ipv4":
		default:
			return "option inconnue « " + s + " »"
		}
	}
	return ""
}

func routeArgs(a []string) string {
	if len(a) < 1 || len(a) > 4 {
		return "1 à 4 arguments attendus"
	}
	for i, s := range a {
		if s == "vpn_gateway" || s == "net_gateway" || s == "remote_host" || s == "default" || isInt(s) {
			continue
		}
		if _, err := netip.ParseAddr(s); err == nil && !strings.Contains(s, "%") {
			continue
		}
		return fmt.Sprintf("argument %d invalide", i+1)
	}
	return ""
}

func normProto(p string) (string, bool) {
	switch p {
	case "udp", "udp4", "udp6":
		return "udp", true
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return "tcp", true
	}
	return "", false
}

func validHost(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return !strings.Contains(h, "%")
	}
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	// un dernier label numérique évite les formes IPv4 exotiques (127.1, 0x7f...).
	return !isInt(labels[len(labels)-1])
}

// tokenize découpe une ligne : espaces, guillemets simples ou doubles.
func tokenize(line string) ([]string, error) {
	var toks []string
	var cur strings.Builder
	in, quote := false, rune(0)
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, in = r, true
		case r == ' ' || r == '\t':
			if in {
				toks = append(toks, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
			in = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("guillemet non fermé")
	}
	if in {
		toks = append(toks, cur.String())
	}
	return toks, nil
}

var blocks = map[string]bool{"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true}

// checkPEM vérifie que le contenu est une suite de blocs PEM (ou clé statique OpenVPN).
func checkPEM(lines []string) string {
	label, n := "", 0
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "-----BEGIN ") && strings.HasSuffix(l, "-----"):
			if label != "" {
				return "BEGIN imbriqué"
			}
			label = strings.TrimSuffix(strings.TrimPrefix(l, "-----BEGIN "), "-----")
		case strings.HasPrefix(l, "-----END ") && strings.HasSuffix(l, "-----"):
			if label == "" || strings.TrimSuffix(strings.TrimPrefix(l, "-----END "), "-----") != label {
				return "END sans BEGIN correspondant"
			}
			label = ""
			n++
		case label == "":
			return "contenu hors PEM"
		default:
			if i := strings.Index(l, ": "); i > 0 { // en-tête PEM
				continue
			}
			for _, r := range l {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '/' || r == '=') {
					return "caractère invalide dans le PEM"
				}
			}
		}
	}
	if label != "" {
		return "PEM non terminé"
	}
	if n == 0 {
		return "aucun PEM"
	}
	return ""
}

// Parse valide content et renvoie la config assainie.
func Parse(content []byte) (*Config, error) {
	g := func(r string) error { return &RejectError{Reason: r} }
	if len(content) > MaxSize {
		return nil, g(fmt.Sprintf("fichier trop gros (max %d octets)", MaxSize))
	}
	if bytes.IndexByte(content, 0) >= 0 {
		return nil, g("octet NUL interdit")
	}
	if !utf8.Valid(content) {
		return nil, g("UTF-8 invalide")
	}
	for _, b := range content {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return nil, g("caractère de contrôle interdit")
		}
	}

	var out bytes.Buffer
	cfg := &Config{}
	var remoteHasProto []bool
	globalProto := "udp"
	var blockName string
	var blockLine int
	var blockLines []string

	for i, raw := range strings.Split(string(content), "\n") {
		ln := i + 1
		line := strings.TrimSpace(raw)
		rej := func(d, r string) error { return &RejectError{ln, d, r} }

		if blockName != "" {
			if line == "</"+blockName+">" {
				if r := checkPEM(blockLines); r != "" {
					return nil, &RejectError{blockLine, blockName, "bloc invalide (" + r + ")"}
				}
				out.WriteString("<" + blockName + ">\n")
				for _, l := range blockLines {
					out.WriteString(l + "\n")
				}
				out.WriteString("</" + blockName + ">\n")
				blockName = ""
			} else if strings.HasPrefix(line, "<") {
				return nil, rej(blockName, "bloc imbriqué ou mal fermé")
			} else if line != "" {
				blockLines = append(blockLines, line)
			}
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '<' {
			name := strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">")
			switch {
			case !strings.HasSuffix(line, ">") || strings.HasPrefix(line, "</"):
				return nil, rej(line, "balise de bloc invalide")
			case name == "auth-user-pass":
				return nil, rej(name, reasonSecret)
			case !blocks[name]:
				return nil, rej(name, "bloc inconnu")
			}
			blockName, blockLine, blockLines = name, ln, nil
			continue
		}

		toks, err := tokenize(line)
		if err != nil {
			return nil, rej(line, err.Error())
		}
		d, args := toks[0], toks[1:]
		if strings.HasPrefix(d, "--") {
			return nil, rej(d, "interdite (préfixe « -- » non accepté)")
		}
		if r, ok := dangerous[d]; ok {
			return nil, rej(d, r)
		}
		for p, r := range dangerousPrefix {
			if strings.HasPrefix(d, p) {
				return nil, rej(d, r)
			}
		}
		if d == "auth-user-pass" && len(args) > 0 {
			return nil, rej(d, reasonFile)
		}
		if d == "remote" {
			rm, hasProto, r := parseRemote(args)
			if r != "" {
				return nil, rej(d, "argument invalide ("+r+")")
			}
			cfg.Remotes = append(cfg.Remotes, rm)
			remoteHasProto = append(remoteHasProto, hasProto)
			line := fmt.Sprintf("remote %s %d", rm.Host, rm.Port)
			if hasProto {
				line += " " + rm.Proto
			}
			out.WriteString(line + "\n")
			continue
		}
		spec, ok := allowed[d]
		if !ok {
			return nil, rej(d, reasonNotAllowed)
		}
		if r := spec(args); r != "" {
			return nil, rej(d, "argument invalide ("+r+")")
		}
		if d == "proto" {
			globalProto, _ = normProto(args[0])
			args = []string{globalProto}
		}
		out.WriteString(strings.Join(append([]string{d}, args...), " ") + "\n")
	}
	if blockName != "" {
		return nil, &RejectError{blockLine, blockName, "bloc non fermé"}
	}
	if len(cfg.Remotes) == 0 {
		return nil, g("aucune directive remote")
	}
	for i := range cfg.Remotes {
		if !remoteHasProto[i] {
			cfg.Remotes[i].Proto = globalProto
		}
	}
	cfg.Sanitized = out.Bytes()
	return cfg, nil
}

func parseRemote(a []string) (rm Remote, hasProto bool, reason string) {
	if len(a) < 1 || len(a) > 3 {
		return rm, false, "host [port] [proto] attendu"
	}
	if !validHost(a[0]) {
		return rm, false, "hôte invalide"
	}
	rm = Remote{Host: a[0], Port: 1194}
	if len(a) > 1 {
		if !isInt(a[1]) {
			return rm, false, "port invalide"
		}
		p, _ := strconv.Atoi(a[1])
		if p < 1 || p > 65535 {
			return rm, false, "port hors de 1-65535"
		}
		rm.Port = p
	}
	if len(a) > 2 {
		p, ok := normProto(a[2])
		if !ok {
			return rm, false, "protocole inconnu"
		}
		rm.Proto, hasProto = p, true
	}
	return rm, hasProto, ""
}
