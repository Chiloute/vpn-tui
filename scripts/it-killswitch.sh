#!/usr/bin/env bash
# Kill switch integration test in rootless netns (no sudo). Run from the repo root: nix develop -c scripts/it-killswitch.sh
# Builds the daemon outside the userns, then re-runs itself in `unshare -Urn` (IT_INNER sentinel).
# Topology: client (= userns) <-veth 192.168.77.0/24, fd77::/64-> srv (wg0 10.10.1.1); client <-veth 172.31.0.0/24-> container.
# Simulated leak: 10.10.1.1 and 10.10.9.9 on lo of srv + route 10.10.0.0/16 via the LAN: the scope is reachable outside the tunnel without the kill switch.
set -euo pipefail
# shellcheck source=scripts/it-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/it-lib.sh"
it_bootstrap "$0" "$@"

it_server_netns
CPID=""
unshare -n sleep infinity &
CPID=$!
trap 'kill "$CPID" 2>/dev/null || true; it_cleanup' EXIT
for _ in $(seq 1 50); do
  [[ $(readlink "/proc/$CPID/ns/net") != "$(readlink /proc/self/ns/net)" ]] && break
  sleep 0.1
done
[[ $(readlink "/proc/$CPID/ns/net") != "$(readlink /proc/self/ns/net)" ]] || fail "container netns not created"
ctr() { nsenter -t "$CPID" -n "$@"; }

# --- Network ---
ip addr add fd77::2/64 dev vc nodad
srv ip addr add fd77::1/64 dev vs nodad
srv ip addr add 10.10.1.1/32 dev lo # NB: also bound on wg0 (/24), the leak goes via lo
srv ip addr add 10.10.9.9/32 dev lo
ip route add 10.10.0.0/16 via 192.168.77.1 dev vc
srv ip route add 172.31.0.0/24 via 192.168.77.2
ip link add cc type veth peer name ct
ip link set ct netns "$CPID"
ip addr add 172.31.0.1/24 dev cc
ip link set cc up
ctr ip link set lo up
ctr ip addr add 172.31.0.2/24 dev ct
ctr ip link set ct up
ctr ip route add default via 172.31.0.1
sysctl -qw net.ipv4.ip_forward=1
# Server-side counter: packets received on vs destined for 10.10.9.9 (the leak target).
srv nft -f - <<'EON'
table inet cnt {
	chain input {
		type filter hook input priority 0; policy accept;
		ip daddr 10.10.9.9 counter
	}
}
EON
leak_pkts() { srv nft list chain inet cnt input | sed -n 's/.*counter packets \([0-9]*\).*/\1/p'; }

# --- WireGuard ---
K="$TMP/keys"
mkdir -p "$K"
for n in srv cli; do
  wg genkey >"$K/$n.key"
  wg pubkey <"$K/$n.key" >"$K/$n.pub"
done
CPUB=$(<"$K/cli.pub")
srv ip link add wg0 type wireguard
srv wg set wg0 listen-port 51820 private-key "$K/srv.key" peer "$CPUB" allowed-ips 10.10.1.2/32
srv ip addr add 10.10.1.1/24 dev wg0
srv ip link set wg0 up
peer_remove() { srv wg set wg0 peer "$CPUB" remove; }
peer_add() { srv wg set wg0 peer "$CPUB" allowed-ips 10.10.1.2/32; }

cat >"$TMP/a.conf" <<EOC
[Interface]
PrivateKey = $(<"$K/cli.key")
Address = 10.10.1.2/32

[Peer]
PublicKey = $(<"$K/srv.pub")
Endpoint = 192.168.77.1:51820
AllowedIPs = 10.10.1.0/24
EOC

DARGS=(--handshake-timeout 3s --reconnect-max-attempts 3 --reconnect-max-backoff 2s --marker "$TMP/armed.json" --idle-timeout 10m)

# --- Helpers ---
nofail() { if "$@" >/dev/null 2>&1; then fail "$DESC : '$*' should have failed"; fi; }
# blocked <desc> <cmd...>: the command must fail and the server counter must not move.
blocked() {
  DESC=$1
  shift
  local before after
  before=$(leak_pkts)
  nofail "$@"
  after=$(leak_pkts)
  [[ $before == "$after" ]] || fail "$DESC : server received traffic to 10.10.9.9 ($before -> $after)"
}
nmap_none() { nmap -sn -n -PE -PS80 --max-retries 1 --host-timeout 5s 10.10.9.9 2>&1 | grep -q '0 hosts up'; }
table_has() { nft list table inet vpn_tui 2>/dev/null | grep -qF "$1"; }
table_absent() { ! nft list table inet vpn_tui >/dev/null 2>&1; }
table_locked() { table_has drop && ! table_has 'oifname "vpntui0" accept'; }
# locked_blocked <desc> <cmd...>: the table must be locked (max wait 50 s) and the command must fail.
locked_blocked() {
  DESC=$1
  shift
  for _ in $(seq 1 500); do table_locked && break; sleep 0.1; done
  table_locked || fail "$DESC : table never locked"
  if "$@" >/dev/null 2>&1; then fail "$DESC : '$*' succeeded while the table is locked"; fi
}
state_is() { cli status --json; [[ $OUT =~ \"state\":\"($1)\" ]]; }
# wait_state <regex> <timeout s> [traffic]: waits for the state; with "traffic", generates traffic to 10.10.1.1.
wait_state() {
  local end=$((SECONDS + $2))
  while ((SECONDS < end)); do
    [[ ${3:-} == traffic ]] && { ping -c1 -W1 10.10.1.1 >/dev/null 2>&1 || true; }
    state_is "$1" && return 0
    sleep 0.3
  done
  return 1
}
TPID=""
start_traffic() { (while :; do ping -c1 -W1 10.10.1.1 >/dev/null 2>&1 || true; sleep 0.3; done) & TPID=$!; }
stop_traffic() { [[ -z $TPID ]] || { kill "$TPID" 2>/dev/null || true; wait "$TPID" 2>/dev/null || true; TPID=""; }; }
stop_daemon() { # kill -9 if $1 = KILL, otherwise SIGTERM
  kill "-${1:-TERM}" "$DPID"
  wait "$DPID" 2>/dev/null || true
}
dump_on_fail() {
  local rc=$?
  if ((rc != 0)); then
    echo "--- nft list ruleset" >&2
    nft list ruleset >&2 || true
    echo "--- ip addr/route" >&2
    ip -br addr >&2 || true
    ip route >&2 || true
  fi
}
trap 'dump_on_fail; stop_traffic; kill "$CPID" 2>/dev/null || true; it_cleanup' EXIT

# 0. Control without daemon: the leak path exists.
b=$(leak_pkts)
ping -c1 -W1 10.10.9.9 >/dev/null || fail "step 0: control, 10.10.9.9 unreachable without kill switch"
[[ $(leak_pkts) -gt $b ]] || fail "step 0: server counter did not move"
ping6 -c1 -w1 fd77::1 >/dev/null || fail "step 0: IPv6 control"
ok "step 0: without daemon, 10.10.9.9 and fd77::1 reachable, server counter working"

it_daemon "${DARGS[@]}"
cli import "$TMP/a.conf" --id a
expect_rc 0 "import a"
RPC='{"jsonrpc":"2.0","id":1,"method":"profile_update","params":{"id":"a","scope":{"cidrs":["10.10.0.0/16"],"exclude":[],"learned":[]},"killswitch":{"enabled":true,"allow_internet":true,"block_ipv6":true}}}'
RES=$(echo "$RPC" | socat -t2 - "UNIX-CONNECT:$SOCK")
[[ $RES == *'"result"'* ]] || fail "profile_update: $RES"

# 1. up: armed
cli up a
expect_rc 0 "step 1: up a"
state_is armed || fail "step 1: not armed: $OUT"
table_has 'oifname "vpntui0" accept' || fail "step 1: vpn_tui table missing or without tunnel rule"
rx_pkts() { ip -s link show vpntui0 | awk '/RX:/{getline; print $2}'; }
rx0=$(rx_pkts)
ping -c1 -W2 10.10.1.1 >/dev/null || fail "step 1: ping 10.10.1.1"
[[ $(ip route get 10.10.1.1) == *"dev vpntui0"* ]] || fail "step 1: 10.10.1.1 does not go through vpntui0"
[[ $(rx_pkts) -gt $rx0 ]] || fail "step 1: vpntui0 rx unchanged"
blocked "step 1: ping 10.10.9.9" ping -c1 -W1 10.10.9.9
nmap_none || fail "step 1: nmap finds 10.10.9.9"
blocked "step 1: nmap 10.10.9.9" false
blocked "step 1: IPv6 ping fd77::1" ping6 -c1 -w1 fd77::1
ctr ping -c1 -W2 192.168.77.1 >/dev/null || fail "step 1: container -> 192.168.77.1 must succeed"
blocked "step 1: container -> 10.10.9.9" ctr ping -c1 -W1 10.10.9.9
ok "step 1: armed, tunnel used, off-tunnel scope/IPv6/forward blocked, simulated Internet open"

# 2. drop: peer removed on server side
peer_remove
start_traffic
wait_state 'reconnecting|locked' 30 traffic || fail "step 2: no drop detected in 30 s ($OUT)"
blocked "step 2: ping 10.10.1.1" ping -c1 -W1 10.10.1.1
blocked "step 2: ping 10.10.9.9" ping -c1 -W1 10.10.9.9
nmap_none || fail "step 2: nmap finds 10.10.9.9"
locked_blocked "step 2: ping 192.168.77.1 (locked)" ping -c1 -W1 192.168.77.1
for _ in $(seq 1 10); do # no more intermittent armed window while the peer is absent
  state_is 'reconnecting|locked' || fail "step 2: state $OUT while the peer is absent"
  table_locked || fail "step 2: table not locked while the peer is absent"
  sleep 0.3
done
blocked "step 2: container -> 10.10.9.9" ctr ping -c1 -W1 10.10.9.9
ok "step 2: tunnel down, all blocked except endpoint"

# 3. reconnection: peer restored before attempts are exhausted
peer_add
wait_state armed 20 || fail "step 3: no return to armed ($OUT)"
for _ in 1 2 3 4 5; do ping -c1 -W2 10.10.1.1 >/dev/null 2>&1 && break; done
ping -c1 -W2 10.10.1.1 >/dev/null || fail "step 3: ping 10.10.1.1 after reconnection"
table_has 'oifname "vpntui0" accept' || fail "step 3: tunnel rule missing"
stop_traffic
ok "step 3: reconnection, armed, ping OK"

# 3b. peer removed on server side: attempts exhausted -> durable locked, then down.
peer_remove
start_traffic
wait_state 'reconnecting|locked' 30 traffic || fail "step 3b: no drop"
wait_state locked 90 || fail "step 3b: not locked after exhaustion ($OUT)"
stop_traffic
for _ in $(seq 1 25); do # ~7.5 s: stable locked, no armed back-and-forth
  state_is locked || fail "step 3b: locked not durable ($OUT)"
  table_locked || fail "step 3b: table not locked"
  sleep 0.3
done
blocked "step 3b: ping 10.10.9.9" ping -c1 -W1 10.10.9.9
cli down
expect_rc 0 "step 3b: down"
state_is disarmed || fail "step 3b: not disarmed ($OUT)"
table_absent || fail "step 3b: table still present"
ping -c1 -W1 10.10.9.9 >/dev/null || fail "step 3b: control, 10.10.9.9 should succeed after down"
peer_add
ok "step 3b: exhaustion -> durable locked, down -> disarmed, table absent, control OK"

# 4. panic_off (CLI then binary)
cli up a
expect_rc 0 "step 4: up"
cli panic-off --yes
expect_rc 0 "step 4: panic-off"
table_absent || fail "step 4: table present after panic-off"
! ip link show vpntui0 >/dev/null 2>&1 || fail "step 4: vpntui0 present after panic-off"
state_is disarmed || fail "step 4: not disarmed ($OUT)"
cli up a
expect_rc 0 "step 4: up again"
stop_daemon KILL # otherwise the live daemon re-locks as soon as the interface disappears
"$BIN" --panic-off --run-dir "$TMP/run" --state-dir "$TMP/state" --cache-dir "$TMP/cache" --marker "$TMP/armed.json" >"$TMP/panic.out" 2>&1 || fail "step 4: vpn-tuid --panic-off: $(<"$TMP/panic.out")"
table_absent || fail "step 4: table present after vpn-tuid --panic-off"
! ip link show vpntui0 >/dev/null 2>&1 || fail "step 4: vpntui0 present after vpn-tuid --panic-off"
ok "step 4: panic_off via RPC and via binary"

# 5. daemon crash (already stopped in step 4)
it_daemon "${DARGS[@]}"
cli up a
expect_rc 0 "step 5: up"
state_is armed || fail "step 5: not armed ($OUT)"
stop_daemon KILL
table_has 'oifname "vpntui0" accept' || fail "step 5: table gone after kill -9"
blocked "step 5: ping 10.10.9.9 daemon dead" ping -c1 -W1 10.10.9.9
it_daemon "${DARGS[@]}"
state_is 'armed|locked' || fail "step 5: state after restart: $OUT"
grep -qE '"kind":"reconcile","detail":"(resumed|locked)"' "$TMP/cache/events.jsonl" || fail "step 5: reconcile resumed/locked event missing"
table_has drop || fail "step 5: table missing after restart"
blocked "step 5: ping 10.10.9.9 after restart" ping -c1 -W1 10.10.9.9
# case 2: interface gone while the daemon is dead
stop_daemon KILL
ip link del vpntui0
it_daemon "${DARGS[@]}"
wait_state locked 10 || fail "step 5: not locked, interface lost ($OUT)"
table_has drop || fail "step 5: table missing (case 2)"
! table_has 'oifname "vpntui0" accept' || fail "step 5: table not locked (case 2)"
blocked "step 5: ping 10.10.9.9 (case 2)" ping -c1 -W1 10.10.9.9
blocked "step 5: ping 192.168.77.1 (case 2)" ping -c1 -W1 192.168.77.1
ok "step 5: crash -> table kept, reconcile armed/locked, interface lost -> locked"

# 6. SIGTERM does not disarm
cli down
expect_rc 0 "step 6: down"
cli up a
expect_rc 0 "step 6: up"
stop_daemon TERM
table_has drop || fail "step 6: table gone after SIGTERM"
blocked "step 6: ping 10.10.9.9" ping -c1 -W1 10.10.9.9
ok "step 6: SIGTERM does not disarm"

# 7. journal
it_daemon "${DARGS[@]}"
cli panic-off --yes
expect_rc 0 "step 7: panic-off"
cli logs --json
expect_rc 0 "step 7: logs --json"
for k in up 'drop|lock' reconnect panic_off reconcile; do
  [[ $OUT =~ \"kind\":\"($k)\" ]] || fail "step 7: event $k missing from journal"
done
ok "step 7: journal complete"

echo "PASS"
