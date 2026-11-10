#!/usr/bin/env bash
# Phase 2 e2e test: THM import with secrets, rejection of a malicious config, no secret on disk on the daemon side. Run from the repo root: nix develop -c scripts/e2e-phase2.sh
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

# Runs the real CLI (bun via nix develop); exit code in RC, stdout in OUT, stderr in ERR.
cli() {
  local sock=$1
  shift
  RC=0
  OUT=$(cd "$ROOT" && VPN_TUI_SOCKET="$sock" bun run app/src/index.ts "$@" 2>"$TMP/cli.err") || RC=$?
  ERR=$(cat "$TMP/cli.err")
}

# Fake secret-tool: store writes stdin to $KEYRING_DIR/<id>, lookup reads it back, clear removes it (id = last argument).
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

# THM fixture with a secret block, inserted after the auth-user-pass line.
awk '{ print } $0 == "auth-user-pass" { print "<auth-user-pass>"; print "00000000000000000000dead"; print "0000000000000000000000000000beef"; print "</auth-user-pass>" }' \
  "$ROOT/daemon/internal/ovpn/testdata/thm.ovpn" >"$TMP/thm.ovpn"

echo "Building daemon..."
(cd "$ROOT" && go build -o "$BIN" ./daemon/cmd/vpn-tuid) || fail "go build of the daemon"

rm -f "$SOCK"
"$BIN" --socket "$SOCK" --group "$(id -gn)" --state-dir "$STATE" >"$TMP/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 50); do
  [[ -S $SOCK ]] && break
  kill -0 "$DPID" 2>/dev/null || fail "the daemon stopped at startup"
  sleep 0.1
done
[[ -S $SOCK ]] || fail "socket missing after 5 s"

# Case 1: THM import with secrets -> secrets in the keyring, nothing in the daemon state.
cli "$SOCK" import "$TMP/thm.ovpn" --name "TryHackMe EU-West" --id thm
[[ $RC -eq 0 ]] || fail "case 1: import exit $RC (expected 0): $ERR"
cli "$SOCK" list --json
[[ $RC -eq 0 ]] || fail "case 1: list --json exit $RC (expected 0): $ERR"
[[ $OUT == *'"id":"thm"'* ]] || fail "case 1: list --json without thm: $OUT"
[[ $OUT == *'"has_secrets":true'* ]] || fail "case 1: list --json without has_secrets:true: $OUT"
for s in dead beef; do
  grep -q "$s" "$KEYRING_DIR/thm" || fail "case 1: fake keyring without $s"
done
rc=0
grep -rl -e dead -e beef "$STATE" || rc=$?
[[ $rc -eq 1 ]] || fail "case 1: secret found in the daemon state (grep rc=$rc, files listed above)"
[[ $(stat -c %a "$STATE/profiles/thm") == 700 ]] || fail "case 1: profiles/thm is not 700"
n=0
while read -r m; do
  n=$((n + 1))
  [[ $m == 600 ]] || fail "case 1: file in profiles/thm is $m (expected 600)"
done < <(find "$STATE/profiles/thm" -type f -exec stat -c %a {} +)
[[ $n -gt 0 ]] || fail "case 1: no file in profiles/thm"
echo "OK case 1: import thm exit 0; list has_secrets true; secrets in the keyring, absent from the state; 700/600"

# Case 2: config with 'up /bin/sh' -> rejected, nothing recorded.
cp "$TMP/thm.ovpn" "$TMP/evil.ovpn"
echo "up /bin/sh" >>"$TMP/evil.ovpn"
cli "$SOCK" import "$TMP/evil.ovpn" --id evil
[[ $RC -eq 1 ]] || fail "case 2: import exit $RC (expected 1)"
re='(^|[^[:alnum:]])up([^[:alnum:]]|$)'
[[ $ERR =~ $re ]] || fail "case 2: stderr without 'up': $ERR"
cli "$SOCK" list --json
[[ $OUT != *evil* ]] || fail "case 2: list --json contains evil: $OUT"
[[ ! -e $STATE/profiles/evil ]] || fail "case 2: profiles/evil directory present"
echo "OK case 2: import evil (up /bin/sh) exit 1 + 'up'; absent from list; no directory"

# Case 3: evil-up.ovpn fixture -> rejected.
cli "$SOCK" import "$ROOT/daemon/internal/ovpn/testdata/evil-up.ovpn"
[[ $RC -eq 1 ]] || fail "case 3: import evil-up.ovpn exit $RC (expected 1)"
echo "OK case 3: import evil-up.ovpn exit 1"

# Case 4: re-import of the same thm id -> rejected (already exists).
cli "$SOCK" import "$TMP/thm.ovpn" --name "TryHackMe EU-West" --id thm
[[ $RC -eq 1 ]] || fail "case 4: thm re-import exit $RC (expected 1)"
echo "OK case 4: thm re-import exit 1"

echo "PASS"
