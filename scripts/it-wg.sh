#!/usr/bin/env bash
# WireGuard integration test in rootless netns (no sudo). Run from the repo root: nix develop -c scripts/it-wg.sh
# Builds the daemon outside the userns, then re-runs itself in `unshare -Urn` (IT_INNER sentinel).
set -euo pipefail
# shellcheck source=scripts/it-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/it-lib.sh"
it_bootstrap "$0" "$@"

# --- WireGuard servers in the server netns ---
it_server_netns
K="$TMP/keys"
mkdir -p "$K"
chmod 700 "$K"
for n in srv0 srv1 cli0 cli1; do
  wg genkey >"$K/$n.key"
  wg pubkey <"$K/$n.key" >"$K/$n.pub"
done
wg genpsk >"$K/psk"
PSK=$(<"$K/psk")
PRIV_A=$(<"$K/cli0.key")
PRIV_B=$(<"$K/cli1.key")

# server_wg <iface> <address> <port> <server key> <client pub> <client ip> [psk]
server_wg() {
  local ifc=$1 addr=$2 port=$3 key=$4 cpub=$5 cip=$6 psk=${7:-}
  srv ip link add "$ifc" type wireguard
  local args=(peer "$cpub" allowed-ips "$cip/32")
  [[ -n $psk ]] && args+=(preshared-key "$psk")
  srv wg set "$ifc" listen-port "$port" private-key "$key" "${args[@]}"
  srv ip addr add "$addr" dev "$ifc"
  srv ip link set "$ifc" up
}
server_wg wg0 10.10.1.1/24 51820 "$K/srv0.key" "$(<"$K/cli0.pub")" 10.10.1.2
server_wg wg1 10.10.2.1/24 51821 "$K/srv1.key" "$(<"$K/cli1.pub")" 10.10.2.2 "$K/psk"
# Services: the address on wg0/wg1 answers ping (kernel); no TCP listener (shortcut: ping is enough to prove routing).

cat >"$TMP/a.conf" <<EOC
[Interface]
PrivateKey = $PRIV_A
Address = 10.10.1.2/32

[Peer]
PublicKey = $(<"$K/srv0.pub")
Endpoint = 192.168.77.1:51820
AllowedIPs = 10.10.1.0/24
PersistentKeepalive = 25
EOC
cat >"$TMP/b.conf" <<EOC
[Interface]
PrivateKey = $PRIV_B
Address = 10.10.2.2/32

[Peer]
PublicKey = $(<"$K/srv1.pub")
PresharedKey = $PSK
Endpoint = 192.168.77.1:51821
AllowedIPs = 10.10.2.0/24
PersistentKeepalive = 25
EOC

it_daemon "$@"

# 1. import
cli import "$TMP/a.conf" --id a
expect_rc 0 "step 1: import a"
cli import "$TMP/b.conf" --id b
expect_rc 0 "step 1: import b"
grep -qF "$PRIV_A" "$KEYRING_DIR/a" || fail "step 1: key of a missing from the fake keyring"
grep -qF "$PSK" "$KEYRING_DIR/b" || fail "step 1: PSK of b missing from the fake keyring"
no_secret_in "$PRIV_A" "$TMP/state"
no_secret_in "$PRIV_B" "$TMP/state"
no_secret_in "$PSK" "$TMP/state"
ok "step 1: import a and b, secrets in the keyring, absent from the state"

# 2. up a
cli up a
expect_rc 0 "step 2: up a"
cli status --json
expect_rc 0 "step 2: status"
status_has '"state":"armed"'
status_has '"profile":"a"'
ip link show vpntui0 >/dev/null 2>&1 || fail "step 2: vpntui0 missing"
ping -c1 -W2 10.10.1.1 >/dev/null || fail "step 2: ping 10.10.1.1"
[[ $(<"$LHOST_FILE") == 10.10.1.* ]] || fail "step 2: lhost = $(<"$LHOST_FILE")"
grep -F '"scope_learned"' "$TMP/cache/events.jsonl" | grep -qF '10.10.1.0/24' || fail "step 2: scope_learned 10.10.1.0/24 missing"
ok "step 2: up a, armed, vpntui0, ping, lhost, scope_learned"

# 3. switch to b
cli up b
expect_rc 0 "step 3: up b"
cli status --json
status_has '"profile":"b"'
ping -c1 -W2 10.10.2.1 >/dev/null || fail "step 3: ping 10.10.2.1"
if ping -c1 -W2 10.10.1.1 >/dev/null 2>&1; then fail "step 3: 10.10.1.1 still reachable"; fi
la=$(grep -n '"kind":"up".*"profile":"a"\|"profile":"a".*"kind":"up"' "$TMP/cache/events.jsonl" | head -1 | cut -d: -f1)
lb=$(grep -n '"kind":"up".*"profile":"b"\|"profile":"b".*"kind":"up"' "$TMP/cache/events.jsonl" | head -1 | cut -d: -f1)
[[ -n $la && -n $lb && $lb -gt $la ]] || fail "step 3: up b not after up a in events.jsonl (a=$la b=$lb)"
ok "step 3: switch a -> b, route of a removed"

# 4. down
cli down
expect_rc 0 "step 4: down"
cli status --json
status_has '"state":"disarmed"'
if ip link show vpntui0 >/dev/null 2>&1; then fail "step 4: vpntui0 still present"; fi
[[ ! -s $LHOST_FILE ]] || fail "step 4: lhost not empty"
ok "step 4: down, disarmed, interface missing, lhost empty"

# 5. secrets absent from the keyring
rm -f "$KEYRING_DIR/a"
cli up a
expect_rc 1 "step 5: up a without secrets"
if ip link show vpntui0 >/dev/null 2>&1; then fail "step 5: vpntui0 present"; fi
ok "step 5: up without secrets rejected (exit 1), no interface"

# 6. no secret on disk on the daemon side
for s in "$PRIV_A" "$PRIV_B" "$PSK"; do
  no_secret_in "$s" "$TMP/state" "$TMP/run" "$TMP/cache" "$TMP/daemon.log"
done
ok "step 6: no secret in state, run, cache, or daemon log"

echo "PASS"
