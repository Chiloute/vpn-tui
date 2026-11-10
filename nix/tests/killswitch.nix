# NixOS VM test: module install, kill switch, WG/OpenVPN switch, reboot, panic-off.
# Language-independent assertions: exit codes, `status --json`, nft state, counters.
{
  pkgs,
  self,
  nft ? false, # true: NixOS firewall in nftables mode (inet nixos-fw) instead of iptables-nft
}: let
  ovpnUser = "testuser-zq81";
  ovpnPass = "testpass-k4w9";

  # PKI + WireGuard keys + profile templates, generated at build time (@SRV@ = server IP, substituted at run time).
  pki = pkgs.runCommand "vpn-tui-test-pki" {nativeBuildInputs = [pkgs.openssl pkgs.openvpn pkgs.wireguard-tools];} ''
    mkdir $out && cd $out
    for n in srv cli; do wg genkey > $n.key; wg pubkey < $n.key > $n.pub; done
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt -subj /CN=test-ca -days 3650 2>/dev/null
    issue() {
      openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $1.key -out $1.csr -subj "/CN=$1" 2>/dev/null
      printf 'keyUsage=digitalSignature,keyAgreement\nextendedKeyUsage=%s\nbasicConstraints=CA:FALSE\n' $2 > $1.ext
      openssl x509 -req -in $1.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out $1.crt -days 3650 -extfile $1.ext 2>/dev/null
    }
    issue server serverAuth
    issue client clientAuth
    openvpn --genkey secret tc.key
    cat > wg.conf.tmpl <<EOF
    [Interface]
    PrivateKey = $(cat cli.key)
    Address = 10.10.1.2/32

    [Peer]
    PublicKey = $(cat srv.pub)
    Endpoint = @SRV@:51820
    AllowedIPs = 10.10.1.0/24
    EOF
    sed -i 's/^    //' wg.conf.tmpl
    {
      printf 'client\ndev tun\nproto udp\nremote @SRV@ 1194\nnobind\nauth-user-pass\nremote-cert-tls server\ndata-ciphers AES-256-GCM\nverb 3\n'
      for b in ca:ca.crt cert:client.crt key:client.key tls-crypt:tc.key; do
        echo "<''${b%%:*}>"; cat ''${b#*:}; echo "</''${b%%:*}>"
      done
      printf '<auth-user-pass>\n%s\n%s\n</auth-user-pass>\n' ${ovpnUser} ${ovpnPass}
    } > t.ovpn.tmpl
    chmod a+r *
  '';

  fakeSecretTool = pkgs.writeShellScript "fake-secret-tool" ''
    set -eu
    umask 077
    d=$HOME/.fake-keyring
    mkdir -p "$d"
    cmd=$1
    for id; do :; done
    case $cmd in
      store) cat > "$d/$id" ;;
      lookup) cat "$d/$id" ;;
      clear) rm -f "$d/$id" ;;
      *) exit 2 ;;
    esac
  '';

  # Snapshot of the nft tables other than vpn_tui, counters normalised.
  fwsnap = pkgs.writeShellScriptBin "fwsnap" ''
    nft list tables | grep -v vpn_tui | while read -r _ fam name; do
      echo "== $fam $name"
      nft list table $fam $name | sed 's/counter packets [0-9]* bytes [0-9]*/counter/'
    done
  '';

  # Sum of packets received from the LAN addressed to the leak targets.
  leak = pkgs.writeShellScriptBin "leak" ''
    nft list table inet cnt | awk '/counter packets/ { for (i = 1; i <= NF; i++) if ($i == "packets") s += $(i + 1) } END { print s + 0 }'
  '';

  verify = pkgs.writeShellScript "verify" ''
    [[ $(${pkgs.gnused}/bin/sed -n 1p "$1") == ${ovpnUser} && $(${pkgs.gnused}/bin/sed -n 2p "$1") == ${ovpnPass} ]]
  '';
in
  pkgs.testers.runNixOSTest ({nodes, ...}: {
    name = "vpn-tui-killswitch${pkgs.lib.optionalString nft "-nft"}";

    nodes.server = {
      networking.firewall.enable = false;
      boot.kernelModules = ["tun" "wireguard" "nf_tables"];
      environment.systemPackages = [pkgs.wireguard-tools pkgs.nftables pkgs.iproute2 leak];
      services.openvpn.servers.srv.config = ''
        dev tun
        proto udp
        port 1194
        topology subnet
        server 10.8.0.0 255.255.255.0
        push "route 10.20.0.0 255.255.255.0"
        ca ${pki}/ca.crt
        cert ${pki}/server.crt
        key ${pki}/server.key
        dh none
        tls-crypt ${pki}/tc.key
        data-ciphers AES-256-GCM
        keepalive 5 30
        auth-user-pass-verify ${verify} via-file
        script-security 2
        verb 3
      '';
    };

    nodes.client = {
      imports = [self.nixosModules.default];
      virtualisation.memorySize = 2048;
      services.vpn-tui = {
        enable = true;
        users = ["alice"];
        restoreLockOnBoot = true;
        handshakeTimeout = "5s";
        reconnect.maxAttempts = 3;
        reconnect.maxBackoff = "2s";
      };
      networking.firewall.enable = true;
      networking.nftables.enable = nft;
      users.users.alice.isNormalUser = true;
      users.users.bob.isNormalUser = true;
      # Leak path: all of 10.10.0.0/16 is reachable outside the tunnel via the LAN.
      networking.interfaces.eth1.ipv4.routes = [
        {
          address = "10.10.0.0";
          prefixLength = 16;
          via = nodes.server.networking.primaryIPAddress;
        }
      ];
      environment.systemPackages = [pkgs.nmap pkgs.socat pkgs.iputils pkgs.util-linux pkgs.nftables fwsnap];
    };

    testScript = ''
      import json, shlex, time

      SRV = "${nodes.server.networking.primaryIPAddress}"
      SOCK = "/run/vpn-tui/vpn-tuid.sock"
      T0 = time.time()

      def step(msg):
          print("STEP (%ds): %s" % (time.time() - T0, msg))

      def vt(args, user="alice", quiet_err=False):
          inner = "VPN_TUI_SECRET_TOOL=${fakeSecretTool} vpn-tui " + args + (" 2>/dev/null" if quiet_err else " 2>&1")
          return client.execute("su " + user + " -c " + shlex.quote(inner))

      def vt_ok(args):
          rc, out = vt(args)
          assert rc == 0, "vpn-tui %s: rc=%d %s" % (args, rc, out)
          return out

      def status(user="alice"):
          return json.loads(vt("status --json", user, True)[1])

      def wait(cond, what, timeout=90, interval=0.5):
          end = time.time() + timeout
          while time.time() < end:
              if cond():
                  return
              time.sleep(interval)
          raise Exception("timeout: " + what)

      def table():
          rc, out = client.execute("nft list table inet vpn_tui")
          return out if rc == 0 else None

      def tunnel_rule():
          t = table()
          return t is not None and 'oifname "vpntui0" accept' in t

      def is_locked():
          t = table()
          return t is not None and "drop" in t and 'oifname "vpntui0" accept' not in t

      def leaked():
          return int(server.succeed("leak").strip())

      def no_leak(what):
          assert leaked() == 0, "%s: the server received leaked traffic : %s" % (what, server.succeed("nft list table inet cnt"))

      def rpc(method_params, user="alice"):
          msg = '{"jsonrpc":"2.0","id":1,"method":' + method_params + "}"
          inner = "echo " + shlex.quote(msg) + " | socat -t2 - UNIX-CONNECT:" + SOCK
          return client.succeed("su " + user + " -c " + shlex.quote(inner))

      def set_scope(pid):
          p = '"profile_update","params":{"id":"%s","scope":{"cidrs":["10.10.0.0/16"],"exclude":[],"learned":[]},"killswitch":{"enabled":true,"allow_internet":true,"block_ipv6":true}}' % pid
          res = rpc(p)
          assert '"result"' in res, res

      def dump():
          print(client.execute("journalctl -u vpn-tuid -u vpn-tuid-restore-lock --no-pager | tail -60")[1])
          print(client.execute("nft list ruleset; ip -br addr; ip route; systemctl status vpn-tuid --no-pager")[1])
          print(server.execute("systemctl status openvpn-srv --no-pager | tail -20; leak")[1])

      def main():
          start_all()
          server.wait_for_unit("multi-user.target")
          server.wait_for_unit("openvpn-srv.service")
          client.wait_for_unit("multi-user.target")

          # --- Server: WireGuard, leak targets on lo, counters (LAN packets only) ---
          server.succeed("ip link add wg0 type wireguard")
          server.succeed("wg set wg0 listen-port 51820 private-key ${pki}/srv.key peer $(cat ${pki}/cli.pub) allowed-ips 10.10.1.2/32")
          server.succeed("ip addr add 10.10.1.1/24 dev wg0 && ip link set wg0 up")
          server.succeed("ip addr add 10.10.9.9/32 dev lo && ip addr add 10.20.0.1/32 dev lo")
          server.succeed("nft 'add table inet cnt; add chain inet cnt input { type filter hook input priority 0; policy accept; }; add rule inet cnt input iifname \"eth1\" ip daddr 10.10.9.9 counter; add rule inet cnt input iifname \"eth1\" ip daddr 10.10.1.1 counter'")
          server.wait_until_succeeds("ip -br addr show tun0")
          peer_pub = server.succeed("cat ${pki}/cli.pub").strip()

          def peer_remove():
              server.succeed("wg set wg0 peer " + peer_pub + " remove")

          def peer_add():
              server.succeed("wg set wg0 peer " + peer_pub + " allowed-ips 10.10.1.2/32")

          # Control: without the kill switch the leak is reachable and the counter works.
          client.succeed("ping -c1 -W2 10.10.9.9")
          assert leaked() > 0, "server counter silent"
          server.succeed("nft reset rules table inet cnt >/dev/null")

          # --- 1. Installation ---
          step("1 install")
          client.succeed("systemctl is-active vpn-tuid.socket")
          assert client.succeed("stat -c '%A %U %G' " + SOCK).strip() == "srw-rw---- root vpn-tui"
          client.fail("systemctl is-active vpn-tuid.service")  # socket activation: not started yet
          rc, out = vt("status")
          assert rc == 1, "alice status: rc=%d %s" % (rc, out)  # disarmed -> 1
          client.succeed("systemctl is-active vpn-tuid.service")
          assert status()["state"] == "disarmed"
          rc, out = vt("status", "bob")
          assert rc == 3, "bob status: rc=%d %s" % (rc, out)  # inaccessible (directory/socket 0750/0660)
          # Rejected by the daemon: bob reaches the socket with the vpn-tui gid but is not a group member.
          bob_uid = client.succeed("id -u bob").strip()
          res = client.succeed("echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"status\"}' | setpriv --reuid bob --regid vpn-tui --clear-groups socat -t2 - UNIX-CONNECT:" + SOCK)
          assert '"error"' in res and "-32001" in res, res
          client.succeed("journalctl -u vpn-tuid --no-pager | grep -E 'uid=%s( |$)'" % bob_uid)

          # --- 2. Import ---
          step("2 import")
          client.succeed("sed s/@SRV@/%s/ ${pki}/wg.conf.tmpl > /tmp/wg.conf" % SRV)
          client.succeed("sed s/@SRV@/%s/ ${pki}/t.ovpn.tmpl > /tmp/ovpn.ovpn" % SRV)
          client.succeed("chmod 644 /tmp/wg.conf /tmp/ovpn.ovpn")
          vt_ok("import /tmp/wg.conf --id wg")
          vt_ok("import /tmp/ovpn.ovpn --id ovpn")
          wgkey = client.succeed("cat ${pki}/cli.key").strip()
          client.succeed("grep -qF " + shlex.quote(wgkey) + " /home/alice/.fake-keyring/wg")
          client.succeed("grep -qF ${ovpnPass} /home/alice/.fake-keyring/ovpn")
          for secret in [wgkey, "${ovpnPass}", "${ovpnUser}"]:
              client.fail("grep -rF -e " + shlex.quote(secret) + " /var/lib/vpn-tui /run/vpn-tui /var/cache/vpn-tui")
          client.succeed("test -z \"$(find /var/lib/vpn-tui -type d ! -perm 700)\"")
          client.succeed("test -z \"$(find /var/lib/vpn-tui -type f ! -perm 600)\"")
          client.succeed("test -n \"$(find /var/lib/vpn-tui/profiles -type f)\"")
          client.succeed("printf 'client\\ndev tun\\nremote %s 1194\\nup /bin/sh\\n' > /tmp/bad.ovpn; chmod 644 /tmp/bad.ovpn" % SRV)
          rc, out = vt("import /tmp/bad.ovpn --id bad")
          assert rc == 1, "import up /bin/sh: rc=%d %s" % (rc, out)
          client.fail("ls /var/lib/vpn-tui/profiles | grep -w bad")
          set_scope("wg")
          set_scope("ovpn")  # without a scope, 10.10.9.9 would legitimately not be blocked under OpenVPN
          prof = json.loads(vt("list --json", "alice", True)[1])["profiles"]
          assert [p["scope"]["cidrs"] for p in prof if p["id"] == "wg"] == [["10.10.0.0/16"]]

          # --- 3. WireGuard up ---
          step("3 wireguard up")
          fw_before = client.succeed("fwsnap")
          assert fw_before.strip(), "no NixOS firewall table before up"
          if ${if nft then "True" else "False"}:
              assert "nixos-fw" in client.succeed("nft list tables")
          vt_ok("up wg")
          no_leak("3 after up")
          st = status()
          assert st["state"] == "armed" and st["profile"] == "wg", st
          assert tunnel_rule()
          client.succeed("ping -c1 -W3 10.10.1.1")
          no_leak("3 after tunnel ping")
          assert "dev vpntui0" in client.succeed("ip route get 10.10.1.1")
          client.fail("ping -c1 -W1 10.10.9.9")
          no_leak("3 after leak ping")
          assert "0 hosts up" in client.succeed("nmap -sn -n -PE -PS80 --max-retries 1 --host-timeout 5s 10.10.9.9")
          no_leak("3")
          assert client.succeed("fwsnap") == fw_before, "NixOS firewall tables modified by up"

          # --- 4. Tunnel failure ---
          step("4 tunnel failure")
          peer_remove()
          client.succeed("systemd-run --unit=traffic ${pkgs.iputils}/bin/ping -i 0.3 10.10.1.1 >/dev/null")
          wait(lambda: status()["state"] == "locked", "locked after exhaustion", 120)
          client.succeed("systemctl stop traffic")
          ev = [json.loads(l) for l in vt("logs --json", "alice", True)[1].splitlines() if l.startswith("{")]
          assert any(e["kind"] == "reconnect" for e in ev), "no reconnect event"
          for _ in range(10):  # locked is durable: no armed round trip
              assert status()["state"] == "locked" and is_locked()
              time.sleep(0.5)
          client.fail("ping -c1 -W1 10.10.1.1")
          client.fail("ping -c1 -W1 10.10.9.9")
          no_leak("4")
          peer_add()
          vt_ok("up wg")
          wait(lambda: status()["state"] == "armed", "armed after peer restore")
          client.wait_until_succeeds("ping -c1 -W2 10.10.1.1")

          # --- 5. WG -> OpenVPN switch, continuous probe towards the leak ---
          step("5 WG -> OpenVPN switch")
          client.succeed("systemd-run --unit=probe sh -c 'while :; do ${pkgs.iputils}/bin/ping -c1 -W1 10.10.9.9 >/dev/null 2>&1 && touch /tmp/probe-leak; sleep 0.2; done'")
          vt_ok("up ovpn")
          st = status()
          assert st["state"] == "armed" and st["profile"] == "ovpn", st
          assert st["lhost"].startswith("10.8.0."), st
          client.succeed("ping -c1 -W3 10.20.0.1")
          assert "dev vpntui0" in client.succeed("ip route get 10.20.0.1")
          ev = [json.loads(l) for l in vt("logs --json", "alice", True)[1].splitlines() if l.startswith("{")]
          assert any(e["kind"] == "scope_learned" and "10.20.0.0/24" in e["detail"] for e in ev), "scope_learned missing"
          client.fail("ls /run/vpn-tui/auth-*")
          client.fail("grep -rF ${ovpnPass} /run/vpn-tui /var/lib/vpn-tui /var/cache/vpn-tui")
          client.fail("test -e /tmp/probe-leak")
          no_leak("5")
          # --- 9. Effective hardening ---
          step("9 hardening")
          props = dict(l.split("=", 1) for l in client.succeed("systemctl show vpn-tuid -p CapabilityBoundingSet,NoNewPrivileges,ProtectSystem").splitlines())
          assert props["CapabilityBoundingSet"] == "cap_net_admin cap_net_raw", props
          assert props["NoNewPrivileges"] == "yes" and props["ProtectSystem"] == "strict", props
          pid = client.succeed("pgrep -x openvpn").split()[0]
          proc = dict(l.split(":\t", 1) for l in client.succeed("cat /proc/%s/status" % pid).splitlines() if ":\t" in l)
          assert int(proc["CapBnd"], 16) == 0x3000, proc["CapBnd"]
          assert int(proc["CapEff"], 16) & ~0x3000 == 0, proc["CapEff"]
          assert proc["NoNewPrivs"] == "1", proc["NoNewPrivs"]
          assert client.succeed("cat /proc/%s/cgroup" % pid).strip().endswith("vpn-tuid.service")

          # --- 6. Daemon restart ---
          step("6 daemon restart")
          client.succeed("systemctl restart vpn-tuid")
          assert table() is not None, "table missing after restart"
          assert status()["state"] in ("armed", "locked"), status()
          assert table() is not None
          client.fail("ping -c1 -W1 10.10.9.9")
          client.fail("test -e /tmp/probe-leak")
          no_leak("6")
          client.succeed("systemctl stop probe")
          if status()["state"] != "armed":
              vt_ok("up ovpn")
          assert status()["state"] == "armed"

          # --- 7. Reboot with an armed profile ---
          step("7 reboot")
          client.shutdown()
          client.start()
          client.wait_for_unit("multi-user.target")
          client.succeed("systemctl is-active vpn-tuid-restore-lock")
          client.succeed("systemctl start network-online.target")  # nothing pulls it in this VM
          def mono(unit):
              return int(client.succeed("systemctl show %s -p ActiveEnterTimestampMonotonic --value" % unit))
          t_lock = mono("vpn-tuid-restore-lock.service")
          # The lock precedes network-pre, eth1 addressing/routing and network-online.
          for u in ["network-pre.target", "network-addresses-eth1.service", "network-online.target"]:
              assert 0 < t_lock < mono(u), "restore-lock (%d) not before %s (%d)" % (t_lock, u, mono(u))
          assert is_locked(), "table not locked after boot : %s" % table()
          client.fail("ping -c1 -W1 10.10.9.9")
          no_leak("7 boot")
          st = status()
          assert st["state"] == "locked", st
          assert is_locked()
          vt_ok("down")
          assert status()["state"] == "disarmed"
          assert table() is None
          client.succeed("ping -c1 -W2 10.10.9.9")  # control
          assert leaked() > 0
          server.succeed("nft reset rules table inet cnt >/dev/null")

          # --- 8. panic-off ---
          step("8 panic-off")
          vt_ok("up wg")
          assert status()["state"] == "armed" and tunnel_rule()
          vt_ok("panic-off --yes")
          assert table() is None
          client.fail("ip link show vpntui0")
          vt_ok("up wg")
          assert status()["state"] == "armed" and tunnel_rule()
          client.succeed("systemctl stop vpn-tuid.socket vpn-tuid.service")
          client.succeed("vpn-tuid --panic-off --run-dir /run/vpn-tui --state-dir /var/lib/vpn-tui --cache-dir /var/cache/vpn-tui --marker /var/lib/vpn-tui/armed.json")
          assert table() is None
          client.fail("ip link show vpntui0")
          client.fail("test -e /var/lib/vpn-tui/armed.json")

      try:
          main()
      except BaseException:
          dump()
          raise
      step("OK")
    '';
  })
