#!/usr/bin/env bash
# Test d'intégration du kill switch en netns rootless (aucun sudo). Lancer depuis la racine : nix develop -c scripts/it-killswitch.sh
# Compile le daemon hors userns, puis se ré-exécute dans `unshare -Urn` (sentinelle IT_INNER).
# Topologie : client (= userns) <-veth 192.168.77.0/24, fd77::/64-> srv (wg0 10.10.1.1) ; client <-veth 172.31.0.0/24-> conteneur.
# Fuite simulée : 10.10.1.1 et 10.10.9.9 sur lo de srv + route 10.10.0.0/16 via le LAN : le scope est joignable hors tunnel sans kill switch.
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
[[ $(readlink "/proc/$CPID/ns/net") != "$(readlink /proc/self/ns/net)" ]] || fail "netns conteneur non créé"
ctr() { nsenter -t "$CPID" -n "$@"; }

# --- Réseau ---
ip addr add fd77::2/64 dev vc nodad
srv ip addr add fd77::1/64 dev vs nodad
srv ip addr add 10.10.1.1/32 dev lo # NB : porté aussi par wg0 (/24), la fuite passe par lo
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
# Compteur côté serveur : paquets reçus sur vs à destination de 10.10.9.9 (la cible de fuite).
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
nofail() { if "$@" >/dev/null 2>&1; then fail "$DESC : '$*' aurait dû échouer"; fi; }
# blocked <desc> <cmd...> : la commande doit échouer et le compteur serveur ne doit pas bouger.
blocked() {
  DESC=$1
  shift
  local before after
  before=$(leak_pkts)
  nofail "$@"
  after=$(leak_pkts)
  [[ $before == "$after" ]] || fail "$DESC : le serveur a reçu du trafic vers 10.10.9.9 ($before -> $after)"
}
nmap_none() { nmap -sn -n -PE -PS80 --max-retries 1 --host-timeout 5s 10.10.9.9 2>&1 | grep -q '0 hosts up'; }
table_has() { nft list table inet vpn_tui 2>/dev/null | grep -qF "$1"; }
table_absent() { ! nft list table inet vpn_tui >/dev/null 2>&1; }
table_locked() { table_has drop && ! table_has 'oifname "vpntui0" accept'; }
# locked_blocked <desc> <cmd...> : la table doit être verrouillée (attente max 50 s) et la commande doit échouer.
locked_blocked() {
  DESC=$1
  shift
  for _ in $(seq 1 500); do table_locked && break; sleep 0.1; done
  table_locked || fail "$DESC : table jamais verrouillée"
  if "$@" >/dev/null 2>&1; then fail "$DESC : '$*' a réussi alors que la table est verrouillée"; fi
}
state_is() { cli status --json; [[ $OUT =~ \"state\":\"($1)\" ]]; }
# wait_state <regex> <timeout s> [traffic] : attend l'état ; avec "traffic", génère du trafic vers 10.10.1.1.
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
stop_daemon() { # kill -9 si $1 = KILL, sinon SIGTERM
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

# 0. Témoin sans daemon : le chemin de fuite existe.
b=$(leak_pkts)
ping -c1 -W1 10.10.9.9 >/dev/null || fail "étape 0 : témoin, 10.10.9.9 injoignable sans kill switch"
[[ $(leak_pkts) -gt $b ]] || fail "étape 0 : le compteur serveur n'a pas bougé"
ping6 -c1 -w1 fd77::1 >/dev/null || fail "étape 0 : témoin IPv6"
ok "étape 0 : sans daemon, 10.10.9.9 et fd77::1 joignables, compteur serveur opérationnel"

it_daemon "${DARGS[@]}"
cli import "$TMP/a.conf" --id a
expect_rc 0 "import a"
RPC='{"jsonrpc":"2.0","id":1,"method":"profile_update","params":{"id":"a","scope":{"cidrs":["10.10.0.0/16"],"exclude":[],"learned":[]},"killswitch":{"enabled":true,"allow_internet":true,"block_ipv6":true}}}'
RES=$(echo "$RPC" | socat -t2 - "UNIX-CONNECT:$SOCK")
[[ $RES == *'"result"'* ]] || fail "profile_update : $RES"

# 1. up : armé
cli up a
expect_rc 0 "étape 1 : up a"
state_is armed || fail "étape 1 : pas armed : $OUT"
table_has 'oifname "vpntui0" accept' || fail "étape 1 : table vpn_tui absente ou sans règle tunnel"
rx_pkts() { ip -s link show vpntui0 | awk '/RX:/{getline; print $2}'; }
rx0=$(rx_pkts)
ping -c1 -W2 10.10.1.1 >/dev/null || fail "étape 1 : ping 10.10.1.1"
[[ $(ip route get 10.10.1.1) == *"dev vpntui0"* ]] || fail "étape 1 : 10.10.1.1 ne passe pas par vpntui0"
[[ $(rx_pkts) -gt $rx0 ]] || fail "étape 1 : rx vpntui0 inchangé"
blocked "étape 1 : ping 10.10.9.9" ping -c1 -W1 10.10.9.9
nmap_none || fail "étape 1 : nmap trouve 10.10.9.9"
blocked "étape 1 : nmap 10.10.9.9" false
blocked "étape 1 : ping IPv6 fd77::1" ping6 -c1 -w1 fd77::1
ctr ping -c1 -W2 192.168.77.1 >/dev/null || fail "étape 1 : conteneur -> 192.168.77.1 doit réussir"
blocked "étape 1 : conteneur -> 10.10.9.9" ctr ping -c1 -W1 10.10.9.9
ok "étape 1 : armed, tunnel utilisé, scope hors tunnel/IPv6/forward bloqués, Internet simulé ouvert"

# 2. chute : peer retiré côté serveur
peer_remove
start_traffic
wait_state 'reconnecting|locked' 30 traffic || fail "étape 2 : pas de chute détectée en 30 s ($OUT)"
blocked "étape 2 : ping 10.10.1.1" ping -c1 -W1 10.10.1.1
blocked "étape 2 : ping 10.10.9.9" ping -c1 -W1 10.10.9.9
nmap_none || fail "étape 2 : nmap trouve 10.10.9.9"
locked_blocked "étape 2 : ping 192.168.77.1 (verrouillé)" ping -c1 -W1 192.168.77.1
for _ in $(seq 1 10); do # plus de fenêtre armed intermittente tant que le peer est absent
  state_is 'reconnecting|locked' || fail "étape 2 : état $OUT alors que le peer est absent"
  table_locked || fail "étape 2 : table non verrouillée alors que le peer est absent"
  sleep 0.3
done
blocked "étape 2 : conteneur -> 10.10.9.9" ctr ping -c1 -W1 10.10.9.9
ok "étape 2 : tunnel tombé, tout bloqué sauf endpoint"

# 3. reconnexion : peer remis avant l'épuisement des tentatives
peer_add
wait_state armed 20 || fail "étape 3 : pas de retour armed ($OUT)"
for _ in 1 2 3 4 5; do ping -c1 -W2 10.10.1.1 >/dev/null 2>&1 && break; done
ping -c1 -W2 10.10.1.1 >/dev/null || fail "étape 3 : ping 10.10.1.1 après reconnexion"
table_has 'oifname "vpntui0" accept' || fail "étape 3 : règle tunnel absente"
stop_traffic
ok "étape 3 : reconnexion, armed, ping OK"

# 3b. peer retiré côté serveur : tentatives épuisées -> locked durable, puis down.
peer_remove
start_traffic
wait_state 'reconnecting|locked' 30 traffic || fail "étape 3b : pas de chute"
wait_state locked 90 || fail "étape 3b : pas locked après épuisement ($OUT)"
stop_traffic
for _ in $(seq 1 25); do # ~7,5 s : verrouillé stable, aucun aller-retour armed
  state_is locked || fail "étape 3b : locked non durable ($OUT)"
  table_locked || fail "étape 3b : table non verrouillée"
  sleep 0.3
done
blocked "étape 3b : ping 10.10.9.9" ping -c1 -W1 10.10.9.9
cli down
expect_rc 0 "étape 3b : down"
state_is disarmed || fail "étape 3b : pas disarmed ($OUT)"
table_absent || fail "étape 3b : table encore présente"
ping -c1 -W1 10.10.9.9 >/dev/null || fail "étape 3b : témoin, 10.10.9.9 devrait réussir après down"
peer_add
ok "étape 3b : épuisement -> locked durable, down -> disarmed, table absente, témoin OK"

# 4. panic_off (CLI puis binaire)
cli up a
expect_rc 0 "étape 4 : up"
cli panic-off --yes
expect_rc 0 "étape 4 : panic-off"
table_absent || fail "étape 4 : table présente après panic-off"
! ip link show vpntui0 >/dev/null 2>&1 || fail "étape 4 : vpntui0 présente après panic-off"
state_is disarmed || fail "étape 4 : pas disarmed ($OUT)"
cli up a
expect_rc 0 "étape 4 : up bis"
stop_daemon KILL # sinon le daemon vivant reverrouille dès que l'interface disparaît
"$BIN" --panic-off --run-dir "$TMP/run" --state-dir "$TMP/state" --cache-dir "$TMP/cache" --marker "$TMP/armed.json" >"$TMP/panic.out" 2>&1 || fail "étape 4 : vpn-tuid --panic-off : $(<"$TMP/panic.out")"
table_absent || fail "étape 4 : table présente après vpn-tuid --panic-off"
! ip link show vpntui0 >/dev/null 2>&1 || fail "étape 4 : vpntui0 présente après vpn-tuid --panic-off"
ok "étape 4 : panic_off par RPC et par binaire"

# 5. crash du daemon (déjà arrêté à l'étape 4)
it_daemon "${DARGS[@]}"
cli up a
expect_rc 0 "étape 5 : up"
state_is armed || fail "étape 5 : pas armed ($OUT)"
stop_daemon KILL
table_has 'oifname "vpntui0" accept' || fail "étape 5 : table disparue après kill -9"
blocked "étape 5 : ping 10.10.9.9 daemon mort" ping -c1 -W1 10.10.9.9
it_daemon "${DARGS[@]}"
state_is 'armed|locked' || fail "étape 5 : état après relance : $OUT"
grep -qE '"kind":"reconcile","detail":"(resumed|locked)"' "$TMP/cache/events.jsonl" || fail "étape 5 : événement reconcile resumed/locked absent"
table_has drop || fail "étape 5 : table absente après relance"
blocked "étape 5 : ping 10.10.9.9 après relance" ping -c1 -W1 10.10.9.9
# cas 2 : interface disparue pendant que le daemon est mort
stop_daemon KILL
ip link del vpntui0
it_daemon "${DARGS[@]}"
wait_state locked 10 || fail "étape 5 : pas locked, interface perdue ($OUT)"
table_has drop || fail "étape 5 : table absente (cas 2)"
! table_has 'oifname "vpntui0" accept' || fail "étape 5 : table non verrouillée (cas 2)"
blocked "étape 5 : ping 10.10.9.9 (cas 2)" ping -c1 -W1 10.10.9.9
blocked "étape 5 : ping 192.168.77.1 (cas 2)" ping -c1 -W1 192.168.77.1
ok "étape 5 : crash -> table maintenue, reconcile armed/locked, interface perdue -> locked"

# 6. SIGTERM ne désarme pas
cli down
expect_rc 0 "étape 6 : down"
cli up a
expect_rc 0 "étape 6 : up"
stop_daemon TERM
table_has drop || fail "étape 6 : table disparue après SIGTERM"
blocked "étape 6 : ping 10.10.9.9" ping -c1 -W1 10.10.9.9
ok "étape 6 : SIGTERM ne désarme pas"

# 7. journal
it_daemon "${DARGS[@]}"
cli panic-off --yes
expect_rc 0 "étape 7 : panic-off"
cli logs --json
expect_rc 0 "étape 7 : logs --json"
for k in up 'drop|lock' reconnect panic_off reconcile; do
  [[ $OUT =~ \"kind\":\"($k)\" ]] || fail "étape 7 : événement $k absent du journal"
done
ok "étape 7 : journal complet"

echo "PASS"
