#!/usr/bin/env bash
# Phase 1 e2e test: real vpn-tuid daemon + real CLI, without root. Run from the repo root: nix develop -c scripts/e2e-phase1.sh
# Case 1 in a user namespace (uid 0: allowed by --group root). Cases 2 and 3 outside the userns.
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

# Runs the real CLI (bun via nix develop); exit code in RC, stdout in OUT, stderr in ERR.
cli() {
  local sock=$1
  shift
  RC=0
  OUT=$(cd "$ROOT" && VPN_TUI_SOCKET="$sock" bun run app/src/index.ts "$@" 2>"$WORK/cli.err") || RC=$?
  ERR=$(cat "$WORK/cli.err")
}

# Daemon confined to $WORK (state, run, cache, marker): never /run or /var.
start_daemon() {
  local group=$1
  rm -f "$SOCK"
  "$BIN" --socket "$SOCK" --group "$group" --state-dir "$WORK/state" --run-dir "$WORK/run" \
    --cache-dir "$WORK/cache" --marker "$WORK/armed.json" >"$WORK/daemon.log" 2>&1 &
  DPID=$!
  for _ in $(seq 1 50); do
    [[ -S $SOCK ]] && return 0
    kill -0 "$DPID" 2>/dev/null || fail "the daemon stopped at startup (group=$group)"
    sleep 0.1
  done
  fail "socket missing after 5 s (group=$group)"
}

stop_daemon() {
  kill "$DPID" 2>/dev/null || true
  wait "$DPID" 2>/dev/null || true
  DPID=""
}

# First existing group (getent) the current user is not a member of, neither as primary nor as supplementary group.
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

# Case 1, run inside the userns: daemon and CLI in the same namespace, uid 0 -> disarmed.
case1() {
  trap stop_daemon EXIT
  start_daemon root
  cli "$SOCK" status --json
  [[ $RC -eq 1 ]] || fail "case 1: status --json exit $RC (expected 1)"
  [[ $OUT == *'"state":"disarmed"'* ]] || fail "case 1: JSON without \"state\":\"disarmed\": $OUT"
  cli "$SOCK" status
  [[ $RC -eq 1 ]] || fail "case 1: status exit $RC (expected 1)"
  [[ $OUT == *"DISCONNECTED"* ]] || fail "case 1: output without DISCONNECTED: $OUT"
  echo "OK case 1: status --json exit 1 + state disarmed; status exit 1 + DISCONNECTED"
}

echo "Building daemon..."
(cd "$ROOT" && go build -o "$BIN" ./daemon/cmd/vpn-tuid) || fail "go build of the daemon"

# Case 1: daemon and CLI in a single user namespace (uid 0 -> access allowed).
export -f fail cli start_daemon stop_daemon case1
unshare -Urn bash -c 'set -euo pipefail; case1' || fail "case 1 (user namespace)"

# Case 2: daemon with a group the user is not a member of -> access denied (exit 3).
FOREIGN="$(pick_foreign_group)" || fail "case 2: no existing group that $(id -un) is not a member of"
start_daemon "$FOREIGN"
cli "$SOCK" status
[[ $RC -eq 3 ]] || fail "case 2: status exit $RC (expected 3) with --group $FOREIGN"
[[ $ERR == *"denied"* ]] || fail "case 2: stderr without 'denied': $ERR"
echo "OK case 2: --group $FOREIGN (non-member) -> status exit 3 + 'denied'"

# Case 3: nonexistent socket -> exit 3.
stop_daemon
cli "$WORK/absent.sock" status
[[ $RC -eq 3 ]] || fail "case 3: status exit $RC (expected 3) on nonexistent socket"
echo "OK case 3: nonexistent socket -> status exit 3"

echo "PASS"
