#!/usr/bin/env bash
# Test d'intégration OpenVPN en netns rootless (aucun sudo). Lancer depuis la racine : nix develop -c scripts/it-ovpn.sh
# Exit 77 (skip) sans /dev/net/tun. Compile le daemon hors userns, puis se ré-exécute dans `unshare -Urn`.
set -euo pipefail
if [[ ! -e /dev/net/tun ]]; then
  echo "SKIP : /dev/net/tun absent"
  exit 77
fi
# shellcheck source=scripts/it-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/it-lib.sh"
it_bootstrap "$0" "$@"

USER_T=testuser-zq81
PASS_T=testpass-k4w9
P="$TMP/pki"
mkdir -p "$P"

# --- PKI de test ---
(
  cd "$P"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -subj "/CN=test-ca" -days 2 2>/dev/null
  issue() { # <nom> <eku>
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
    printf 'extendedKeyUsage=%s\nbasicConstraints=CA:FALSE\n' "$2" >"$1.ext"
    openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1.crt" -days 2 -extfile "$1.ext" 2>/dev/null
  }
  issue server serverAuth
  issue client clientAuth
  openvpn --genkey secret tc.key
)

# --- Serveur OpenVPN dans le netns serveur ---
it_server_netns
srv ip addr add 10.20.0.1/32 dev lo
cat >"$TMP/verify.sh" <<EOS
#!/usr/bin/env bash
# auth-user-pass-verify via-file : \$1 = fichier username/password
[[ \$(sed -n 1p "\$1") == $USER_T && \$(sed -n 2p "\$1") == $PASS_T ]]
EOS
chmod +x "$TMP/verify.sh"
cat >"$TMP/server.conf" <<EOC
dev tun
proto udp
port 1194
topology subnet
server 10.8.0.0 255.255.255.0
push "route 10.20.0.0 255.255.255.0"
ca $P/ca.crt
cert $P/server.crt
key $P/server.key
dh none
tls-crypt $P/tc.key
data-ciphers AES-256-GCM
keepalive 5 30
auth-user-pass-verify $TMP/verify.sh via-file
script-security 2
verb 3
EOC
srv openvpn --config "$TMP/server.conf" >"$TMP/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 100); do
  grep -q "Initialization Sequence Completed" "$TMP/server.log" && break
  kill -0 "$SRV_PID" 2>/dev/null || { sed 's/^/  server: /' "$TMP/server.log" >&2; fail "le serveur openvpn s'est arrêté"; }
  sleep 0.1
done
grep -q "Initialization Sequence Completed" "$TMP/server.log" || { sed 's/^/  server: /' "$TMP/server.log" >&2; fail "serveur openvpn pas prêt après 10 s"; }

# --- Profil client inline ---
{
  cat <<'EOC'
client
dev tun
proto udp
remote 192.168.77.1 1194
nobind
auth-user-pass
remote-cert-tls server
data-ciphers AES-256-GCM
verb 3
EOC
  for b in ca:ca.crt cert:client.crt key:client.key tls-crypt:tc.key; do
    echo "<${b%%:*}>"
    cat "$P/${b#*:}"
    echo "</${b%%:*}>"
  done
  printf '<auth-user-pass>\n%s\n%s\n</auth-user-pass>\n' "$USER_T" "$PASS_T"
} >"$TMP/t.ovpn"

it_daemon --ovpn-user "" --ovpn-group "" --connect-timeout 30s

cli import "$TMP/t.ovpn" --id t
expect_rc 0 "import"
no_secret_in "$USER_T" "$TMP/state"
no_secret_in "$PASS_T" "$TMP/state"
ok "import t, identifiants absents du state"

cli up t
expect_rc 0 "up t"
cli status --json
expect_rc 0 "status"
status_has '"state":"armed"'
status_has '"profile":"t"'
[[ $(<"$LHOST_FILE") == 10.8.0.* ]] || fail "lhost = $(<"$LHOST_FILE")"
ping -c1 -W2 10.20.0.1 >/dev/null || fail "ping 10.20.0.1 via le tunnel"
grep -F '"scope_learned"' "$TMP/cache/events.jsonl" | grep -qF '10.20.0.0/24' || fail "scope_learned 10.20.0.0/24 absent"
if compgen -G "$TMP/run/auth-*" >/dev/null; then fail "fichier auth-* présent dans $TMP/run"; fi
for s in "$USER_T" "$PASS_T"; do
  no_secret_in "$s" "$TMP/state" "$TMP/run" "$TMP/cache" "$TMP/daemon.log"
done
ok "up t : armed, LHOST 10.8.0.x, ping, scope_learned, pas d'auth-*, pas d'identifiants sur disque"

cli down
expect_rc 0 "down"
if ip link show vpntui0 >/dev/null 2>&1; then fail "vpntui0 encore présente après down"; fi
ok "down : interface absente"

echo "PASS"
