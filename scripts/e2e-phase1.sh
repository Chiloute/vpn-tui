#!/usr/bin/env bash
# Test e2e phase 1 : daemon vpn-tuid réel + CLI réel, sans root. Lancer depuis la racine : nix develop -c scripts/e2e-phase1.sh
# Cas 1 dans un user namespace (uid 0 : autorisé par --group root). Cas 2 et 3 hors userns.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
BIN="$WORK/vpn-tuid"
SOCK="$WORK/vpn-tuid.sock"
DPID=""
RC=0
OUT=""
ERR=""
export ROOT WORK BIN SOCK

cleanup() {
  if [[ -n $DPID ]]; then
    kill "$DPID" 2>/dev/null || true
    wait "$DPID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  if [[ -f $WORK/daemon.log ]]; then sed 's/^/  daemon: /' "$WORK/daemon.log" >&2; fi
  exit 1
}

# Lance le vrai CLI (bun via nix develop) ; code de sortie dans RC, stdout dans OUT, stderr dans ERR.
cli() {
  local sock=$1
  shift
  RC=0
  OUT=$(cd "$ROOT" && VPN_TUI_SOCKET="$sock" bun run app/src/index.ts "$@" 2>"$WORK/cli.err") || RC=$?
  ERR=$(cat "$WORK/cli.err")
}

# Daemon confiné dans $WORK (state, run, cache, marker) : jamais /run ni /var.
start_daemon() {
  local group=$1
  rm -f "$SOCK"
  "$BIN" --socket "$SOCK" --group "$group" --state-dir "$WORK/state" --run-dir "$WORK/run" \
    --cache-dir "$WORK/cache" --marker "$WORK/armed.json" >"$WORK/daemon.log" 2>&1 &
  DPID=$!
  for _ in $(seq 1 50); do
    [[ -S $SOCK ]] && return 0
    kill -0 "$DPID" 2>/dev/null || fail "le daemon s'est arrêté au démarrage (group=$group)"
    sleep 0.1
  done
  fail "socket absent après 5 s (group=$group)"
}

stop_daemon() {
  kill "$DPID" 2>/dev/null || true
  wait "$DPID" 2>/dev/null || true
  DPID=""
}

# Premier groupe existant (getent) dont l'utilisateur courant n'est membre ni en principal ni en supplémentaire.
pick_foreign_group() {
  local mine name
  mine=" $(id -Gn) "
  while IFS=: read -r name _; do
    if [[ -n $name && $mine != *" $name "* ]]; then
      echo "$name"
      return 0
    fi
  done < <(getent group)
  return 1
}

# Cas 1, exécuté dans le userns : daemon et CLI dans le même namespace, uid 0 -> disarmed.
case1() {
  trap stop_daemon EXIT
  start_daemon root
  cli "$SOCK" status --json
  [[ $RC -eq 1 ]] || fail "cas 1 : status --json exit $RC (attendu 1)"
  [[ $OUT == *'"state":"disarmed"'* ]] || fail "cas 1 : JSON sans \"state\":\"disarmed\" : $OUT"
  cli "$SOCK" status
  [[ $RC -eq 1 ]] || fail "cas 1 : status exit $RC (attendu 1)"
  [[ $OUT == *"DÉCONNECTÉ"* ]] || fail "cas 1 : sortie sans DÉCONNECTÉ : $OUT"
  echo "OK cas 1 : status --json exit 1 + state disarmed ; status exit 1 + DÉCONNECTÉ"
}

echo "Build du daemon..."
(cd "$ROOT" && go build -o "$BIN" ./daemon/cmd/vpn-tuid) || fail "go build du daemon"

# Cas 1 : daemon et CLI dans un seul user namespace (uid 0 -> accès autorisé).
export -f fail cli start_daemon stop_daemon case1
unshare -Urn bash -c 'set -euo pipefail; case1' || fail "cas 1 (user namespace)"

# Cas 2 : daemon avec un groupe dont l'utilisateur n'est pas membre -> accès refusé (exit 3).
FOREIGN="$(pick_foreign_group)" || fail "cas 2 : aucun groupe existant dont $(id -un) n'est pas membre"
start_daemon "$FOREIGN"
cli "$SOCK" status
[[ $RC -eq 3 ]] || fail "cas 2 : status exit $RC (attendu 3) avec --group $FOREIGN"
[[ $ERR == *"refusé"* ]] || fail "cas 2 : stderr sans 'refusé' : $ERR"
echo "OK cas 2 : --group $FOREIGN (non membre) -> status exit 3 + 'refusé'"

# Cas 3 : socket inexistant -> exit 3.
stop_daemon
cli "$WORK/absent.sock" status
[[ $RC -eq 3 ]] || fail "cas 3 : status exit $RC (attendu 3) sur socket inexistant"
echo "OK cas 3 : socket inexistant -> status exit 3"

echo "PASS"
