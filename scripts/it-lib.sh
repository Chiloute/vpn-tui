# Bibliothèque commune des tests d'intégration en netns rootless (sourcée par it-wg.sh / it-ovpn.sh).
# Usage dans le script : source it-lib.sh ; it_bootstrap "$0" "$@" ; (la suite s'exécute dans le userns)
# shellcheck shell=bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RC=0
OUT=""
ERR=""
# shellcheck disable=SC2034 # variables lues par les scripts appelants
SPID=""
DPID=""

fail() {
  echo "FAIL: $*" >&2
  if [[ -f ${TMP:-}/daemon.log ]]; then sed 's/^/  daemon: /' "$TMP/daemon.log" >&2; fi
  exit 1
}

ok() { echo "OK $*"; }

# Hors userns : tmp + build (CGO_ENABLED=0), puis ré-exécution du script dans `unshare -Urn`.
# Dans le userns (sentinelle IT_INNER) : reprend $TMP et installe le nettoyage des processus.
it_bootstrap() {
  if [[ -z ${IT_INNER:-} ]]; then
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    echo "Build du daemon..."
    (cd "$ROOT" && CGO_ENABLED=0 go build -o "$TMP/vpn-tuid" ./daemon/cmd/vpn-tuid) || fail "go build du daemon"
    local rc=0
    IT_INNER=1 IT_TMP="$TMP" unshare -Urn "$@" || rc=$?
    exit "$rc"
  fi
  TMP="$IT_TMP"
  BIN="$TMP/vpn-tuid"
  SOCK="$TMP/vpn-tuid.sock"
  trap it_cleanup EXIT
  ip link set lo up
  umask 077
  export XDG_CACHE_HOME="$TMP/xdg"
  # shellcheck disable=SC2034
  LHOST_FILE="$XDG_CACHE_HOME/vpn-tui/lhost"
  it_keyring
}

it_cleanup() {
  local p
  for p in "$DPID" "$SPID"; do
    if [[ -n $p ]]; then
      kill "$p" 2>/dev/null || true
      wait "$p" 2>/dev/null || true
    fi
  done
  # serveur openvpn lancé par it-ovpn.sh (SRV_PID)
  [[ -n ${SRV_PID:-} ]] && { kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; } || true
}

# Faux secret-tool : store écrit stdin dans $KEYRING_DIR/<id>, lookup le relit, clear le supprime.
it_keyring() {
  KEYRING_DIR="$TMP/keyring"
  mkdir -p "$KEYRING_DIR"
  export KEYRING_DIR
  cat >"$TMP/secret-tool" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
id=${*: -1}
case $1 in
  store) cat >"$KEYRING_DIR/$id" ;;
  lookup) cat "$KEYRING_DIR/$id" ;;
  clear) rm -f "$KEYRING_DIR/$id" ;;
  *) exit 2 ;;
esac
EOS
  chmod +x "$TMP/secret-tool"
  export VPN_TUI_SECRET_TOOL="$TMP/secret-tool"
}

# Netns « serveur » : processus `unshare -n sleep infinity`, veth vs(192.168.77.1) <-> vc(192.168.77.2, ici).
it_server_netns() {
  unshare -n sleep infinity &
  SPID=$!
  for _ in $(seq 1 50); do
    [[ $(readlink "/proc/$SPID/ns/net") != "$(readlink /proc/self/ns/net)" ]] && break
    sleep 0.1
  done
  [[ $(readlink "/proc/$SPID/ns/net") != "$(readlink /proc/self/ns/net)" ]] || fail "netns serveur non créé"
  ip link add vc type veth peer name vs
  ip link set vs netns "$SPID"
  ip addr add 192.168.77.2/24 dev vc
  ip link set vc up
  srv ip link set lo up
  srv ip addr add 192.168.77.1/24 dev vs
  srv ip link set vs up
}

# Exécute une commande dans le netns serveur.
srv() { nsenter -t "$SPID" -n "$@"; }

# Lance le daemon (arguments supplémentaires passés tels quels) et attend le socket.
it_daemon() {
  rm -f "$SOCK"
  "$BIN" --socket "$SOCK" --group root --state-dir "$TMP/state" --run-dir "$TMP/run" --cache-dir "$TMP/cache" "$@" >"$TMP/daemon.log" 2>&1 &
  DPID=$!
  for _ in $(seq 1 50); do
    [[ -S $SOCK ]] && break
    kill -0 "$DPID" 2>/dev/null || fail "le daemon s'est arrêté au démarrage"
    sleep 0.1
  done
  [[ -S $SOCK ]] || fail "socket absent après 5 s"
}

# Vrai CLI (bun) ; code de sortie dans RC, stdout dans OUT, stderr dans ERR.
cli() {
  RC=0
  OUT=$(cd "$ROOT" && VPN_TUI_SOCKET="$SOCK" bun run app/src/index.ts "$@" 2>"$TMP/cli.err") || RC=$?
  ERR=$(cat "$TMP/cli.err")
}

# expect_rc <attendu> <étape> : vérifie RC du dernier cli().
expect_rc() { [[ $RC -eq $1 ]] || fail "$2 : exit $RC (attendu $1) : $OUT $ERR"; }

# no_secret_in <motif> <chemins...> : échoue si le motif fixe apparaît dans un fichier.
no_secret_in() {
  local pat=$1 f
  shift
  for f in "$@"; do
    [[ -e $f ]] || continue
    if grep -rqF -e "$pat" "$f"; then fail "secret trouvé dans $f"; fi
  done
}

status_has() { [[ $OUT == *"$1"* ]] || fail "status sans $1 : $OUT"; }
