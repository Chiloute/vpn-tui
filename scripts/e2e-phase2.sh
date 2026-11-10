#!/usr/bin/env bash
# Test e2e phase 2 : import THM avec secrets, refus d'une config malveillante, aucun secret sur disque côté daemon. Lancer depuis la racine : nix develop -c scripts/e2e-phase2.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
BIN="$TMP/vpn-tuid"
SOCK="$TMP/vpn-tuid.sock"
STATE="$TMP/state"
KEYRING_DIR="$TMP/keyring"
DPID=""
RC=0
OUT=""
ERR=""

cleanup() {
  if [[ -n $DPID ]]; then
    kill "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  if [[ -f $TMP/daemon.log ]]; then sed 's/^/  daemon: /' "$TMP/daemon.log" >&2; fi
  exit 1
}

# Lance le vrai CLI (bun via nix develop) ; code de sortie dans RC, stdout dans OUT, stderr dans ERR.
cli() {
  local sock=$1
  shift
  RC=0
  OUT=$(cd "$ROOT" && VPN_TUI_SOCKET="$sock" bun run app/src/index.ts "$@" 2>"$TMP/cli.err") || RC=$?
  ERR=$(cat "$TMP/cli.err")
}

# Faux secret-tool : store écrit stdin dans $KEYRING_DIR/<id>, lookup le relit, clear le supprime (id = dernier argument).
mkdir -p "$KEYRING_DIR"
export KEYRING_DIR
cat >"$TMP/secret-tool" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
id=${*: -1}
case $1 in
  store) cat >"$KEYRING_DIR/$id" ;;
  lookup) cat "$KEYRING_DIR/$id" ;;
  clear) rm -f "$KEYRING_DIR/$id" ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$TMP/secret-tool"
export VPN_TUI_SECRET_TOOL="$TMP/secret-tool"

# Fixture THM avec bloc secret, inséré après la ligne auth-user-pass.
awk '{ print } $0 == "auth-user-pass" { print "<auth-user-pass>"; print "00000000000000000000dead"; print "0000000000000000000000000000beef"; print "</auth-user-pass>" }' \
  "$ROOT/daemon/internal/ovpn/testdata/thm.ovpn" >"$TMP/thm.ovpn"

echo "Build du daemon..."
(cd "$ROOT" && go build -o "$BIN" ./daemon/cmd/vpn-tuid) || fail "go build du daemon"

rm -f "$SOCK"
"$BIN" --socket "$SOCK" --group "$(id -gn)" --state-dir "$STATE" >"$TMP/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 50); do
  [[ -S $SOCK ]] && break
  kill -0 "$DPID" 2>/dev/null || fail "le daemon s'est arrêté au démarrage"
  sleep 0.1
done
[[ -S $SOCK ]] || fail "socket absent après 5 s"

# Cas 1 : import THM avec secrets -> secrets dans le keyring, rien dans le state du daemon.
cli "$SOCK" import "$TMP/thm.ovpn" --name "TryHackMe EU-West" --id thm
[[ $RC -eq 0 ]] || fail "cas 1 : import exit $RC (attendu 0) : $ERR"
cli "$SOCK" list --json
[[ $RC -eq 0 ]] || fail "cas 1 : list --json exit $RC (attendu 0) : $ERR"
[[ $OUT == *'"id":"thm"'* ]] || fail "cas 1 : list --json sans thm : $OUT"
[[ $OUT == *'"has_secrets":true'* ]] || fail "cas 1 : list --json sans has_secrets:true : $OUT"
for s in dead beef; do
  grep -q "$s" "$KEYRING_DIR/thm" || fail "cas 1 : faux keyring sans $s"
done
rc=0
grep -rl -e dead -e beef "$STATE" || rc=$?
[[ $rc -eq 1 ]] || fail "cas 1 : secret trouvé dans le state du daemon (grep rc=$rc, fichiers listés ci-dessus)"
[[ $(stat -c %a "$STATE/profiles/thm") == 700 ]] || fail "cas 1 : profiles/thm n'est pas en 700"
n=0
while read -r m; do
  n=$((n + 1))
  [[ $m == 600 ]] || fail "cas 1 : fichier de profiles/thm en $m (attendu 600)"
done < <(find "$STATE/profiles/thm" -type f -exec stat -c %a {} +)
[[ $n -gt 0 ]] || fail "cas 1 : aucun fichier dans profiles/thm"
echo "OK cas 1 : import thm exit 0 ; list has_secrets true ; secrets dans le keyring, absents du state ; 700/600"

# Cas 2 : config avec 'up /bin/sh' -> refus, rien enregistré.
cp "$TMP/thm.ovpn" "$TMP/evil.ovpn"
echo "up /bin/sh" >>"$TMP/evil.ovpn"
cli "$SOCK" import "$TMP/evil.ovpn" --id evil
[[ $RC -eq 1 ]] || fail "cas 2 : import exit $RC (attendu 1)"
re='(^|[^[:alnum:]])up([^[:alnum:]]|$)'
[[ $ERR =~ $re ]] || fail "cas 2 : stderr sans 'up' : $ERR"
cli "$SOCK" list --json
[[ $OUT != *evil* ]] || fail "cas 2 : list --json contient evil : $OUT"
[[ ! -e $STATE/profiles/evil ]] || fail "cas 2 : dossier profiles/evil présent"
echo "OK cas 2 : import evil (up /bin/sh) exit 1 + 'up' ; absent de list ; pas de dossier"

# Cas 3 : fixture evil-up.ovpn -> refus.
cli "$SOCK" import "$ROOT/daemon/internal/ovpn/testdata/evil-up.ovpn"
[[ $RC -eq 1 ]] || fail "cas 3 : import evil-up.ovpn exit $RC (attendu 1)"
echo "OK cas 3 : import evil-up.ovpn exit 1"

# Cas 4 : réimport du même id thm -> refus (déjà existant).
cli "$SOCK" import "$TMP/thm.ovpn" --name "TryHackMe EU-West" --id thm
[[ $RC -eq 1 ]] || fail "cas 4 : réimport thm exit $RC (attendu 1)"
echo "OK cas 4 : réimport thm exit 1"

echo "PASS"
