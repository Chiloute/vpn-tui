#!/usr/bin/env bash
# Test d'intégration WireGuard en netns rootless (aucun sudo). Lancer depuis la racine : nix develop -c scripts/it-wg.sh
# Compile le daemon hors userns, puis se ré-exécute dans `unshare -Urn` (sentinelle IT_INNER).
set -euo pipefail
# shellcheck source=scripts/it-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/it-lib.sh"
it_bootstrap "$0" "$@"

# --- Serveurs WireGuard dans le netns serveur ---
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

# server_wg <iface> <adresse> <port> <clé serveur> <pub client> <ip client> [psk]
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
# Services : l'adresse sur wg0/wg1 répond au ping (kernel) ; pas de listener TCP (shortcut: ping suffit à prouver le routage).

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
expect_rc 0 "étape 1 : import a"
cli import "$TMP/b.conf" --id b
expect_rc 0 "étape 1 : import b"
grep -qF "$PRIV_A" "$KEYRING_DIR/a" || fail "étape 1 : clé de a absente du faux keyring"
grep -qF "$PSK" "$KEYRING_DIR/b" || fail "étape 1 : PSK de b absent du faux keyring"
no_secret_in "$PRIV_A" "$TMP/state"
no_secret_in "$PRIV_B" "$TMP/state"
no_secret_in "$PSK" "$TMP/state"
ok "étape 1 : import a et b, secrets dans le keyring, absents du state"

# 2. up a
cli up a
expect_rc 0 "étape 2 : up a"
cli status --json
expect_rc 0 "étape 2 : status"
status_has '"state":"armed"'
status_has '"profile":"a"'
ip link show vpntui0 >/dev/null 2>&1 || fail "étape 2 : vpntui0 absente"
ping -c1 -W2 10.10.1.1 >/dev/null || fail "étape 2 : ping 10.10.1.1"
[[ $(<"$LHOST_FILE") == 10.10.1.* ]] || fail "étape 2 : lhost = $(<"$LHOST_FILE")"
grep -F '"scope_learned"' "$TMP/cache/events.jsonl" | grep -qF '10.10.1.0/24' || fail "étape 2 : scope_learned 10.10.1.0/24 absent"
ok "étape 2 : up a, armed, vpntui0, ping, lhost, scope_learned"

# 3. bascule vers b
cli up b
expect_rc 0 "étape 3 : up b"
cli status --json
status_has '"profile":"b"'
ping -c1 -W2 10.10.2.1 >/dev/null || fail "étape 3 : ping 10.10.2.1"
if ping -c1 -W2 10.10.1.1 >/dev/null 2>&1; then fail "étape 3 : 10.10.1.1 encore joignable"; fi
la=$(grep -n '"kind":"up".*"profile":"a"\|"profile":"a".*"kind":"up"' "$TMP/cache/events.jsonl" | head -1 | cut -d: -f1)
lb=$(grep -n '"kind":"up".*"profile":"b"\|"profile":"b".*"kind":"up"' "$TMP/cache/events.jsonl" | head -1 | cut -d: -f1)
[[ -n $la && -n $lb && $lb -gt $la ]] || fail "étape 3 : up b pas après up a dans events.jsonl (a=$la b=$lb)"
ok "étape 3 : bascule a -> b, route de a partie"

# 4. down
cli down
expect_rc 0 "étape 4 : down"
cli status --json
status_has '"state":"disarmed"'
if ip link show vpntui0 >/dev/null 2>&1; then fail "étape 4 : vpntui0 encore présente"; fi
[[ ! -s $LHOST_FILE ]] || fail "étape 4 : lhost non vide"
ok "étape 4 : down, disarmed, interface absente, lhost vide"

# 5. secrets absents du keyring
rm -f "$KEYRING_DIR/a"
cli up a
expect_rc 1 "étape 5 : up a sans secrets"
if ip link show vpntui0 >/dev/null 2>&1; then fail "étape 5 : vpntui0 présente"; fi
ok "étape 5 : up sans secrets refusé (exit 1), pas d'interface"

# 6. aucun secret sur disque côté daemon
for s in "$PRIV_A" "$PRIV_B" "$PSK"; do
  no_secret_in "$s" "$TMP/state" "$TMP/run" "$TMP/cache" "$TMP/daemon.log"
done
ok "étape 6 : aucun secret dans state, run, cache, log du daemon"

echo "PASS"
