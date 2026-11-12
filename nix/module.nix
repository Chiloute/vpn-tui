# NixOS module: root daemon vpn-tuid (socket-activated, hardened) + client.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.vpn-tui;
  inherit (lib) mkOption mkEnableOption mkIf types;

  # Go duration (time.ParseDuration), e.g. 60s, 1m30s, 500ms.
  duration = types.strMatching "([0-9]+(\\.[0-9]+)?(ns|us|ms|s|m|h))+";
  pkg = cfg.package;
  bin = "${pkg}/bin/vpn-tuid";
  # ExecStart does not go through a shell: an empty argument stays empty.
  common = [
    "--group vpn-tui"
    "--state-dir /var/lib/vpn-tui"
    "--run-dir /run/vpn-tui"
    "--cache-dir /var/cache/vpn-tui"
    "--marker /var/lib/vpn-tui/armed.json"
    "--openvpn ${pkgs.openvpn}/bin/openvpn"
    "--resolvectl ${pkgs.systemd}/bin/resolvectl"
    # OpenVPN runs in the same hardened sandbox as the daemon. Without CAP_SETUID/CAP_SETGID
    # in the bounding set, `--user nobody` would fail: no privilege drop.
    ''--ovpn-user "" --ovpn-group ""''
  ];
  args = common ++ [
    "--idle-timeout ${cfg.idleTimeout}"
    "--reconnect-max-attempts ${toString cfg.reconnect.maxAttempts}"
    "--reconnect-max-backoff ${cfg.reconnect.maxBackoff}"
    "--handshake-timeout ${cfg.handshakeTimeout}"
  ];

  hardening = {
    CapabilityBoundingSet = "CAP_NET_ADMIN CAP_NET_RAW";
    AmbientCapabilities = "";
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    ReadWritePaths = ["/var/lib/vpn-tui" "/run/vpn-tui" "/var/cache/vpn-tui"];
    RestrictAddressFamilies = ["AF_UNIX" "AF_NETLINK" "AF_INET" "AF_INET6"];
    SystemCallFilter = ["@system-service"];
    MemoryDenyWriteExecute = true;
    LockPersonality = true;
    # Verified: neither the daemon nor OpenVPN writes sysctls (netlink only),
    # so ProtectKernelTunables=yes is safe. Set to "no" if an up/down script writes one.
    ProtectKernelTunables = true;
    ProtectControlGroups = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectKernelLogs = true;
    SystemCallArchitectures = "native";
    # OpenVPN opens /dev/net/tun.
    DevicePolicy = "closed";
    DeviceAllow = ["/dev/net/tun rw"];
  };
in {
  options.services.vpn-tui = {
    enable = mkEnableOption "the vpn-tui VPN daemon with kill switch";
    package = mkOption {
      type = types.package;
      description = "The vpn-tui package (daemon and client).";
    };
    users = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Users added to the vpn-tui group.";
    };
    idleTimeout = mkOption {
      type = duration;
      default = "60s";
      description = "The daemon exits after this much time with no activity and no VPN.";
    };
    restoreLockOnBoot = mkOption {
      type = types.bool;
      default = false;
      description = "Re-apply the kill switch lock at boot if the marker file exists.";
    };
    reconnect.maxAttempts = mkOption {
      type = types.int;
      default = 10;
    };
    reconnect.maxBackoff = mkOption {
      type = duration;
      default = "60s";
    };
    handshakeTimeout = mkOption {
      type = duration;
      default = "180s";
      description = "WireGuard: the tunnel is considered dead after this long without a handshake.";
    };
    notify.enable = mkEnableOption "the vpn-tui-notify user unit for desktop notifications";
  };

  config = mkIf (cfg.enable || cfg.restoreLockOnBoot) {
    assertions = [
      {
        assertion = !(builtins.elem "root" cfg.users);
        message = "services.vpn-tui.users: root is not needed (already allowed).";
      }
      {
        assertion = cfg.restoreLockOnBoot -> cfg.enable;
        message = "services.vpn-tui.restoreLockOnBoot requires services.vpn-tui.enable.";
      }
    ];

    users.groups.vpn-tui = {};
    users.users = lib.genAttrs cfg.users (_: {extraGroups = ["vpn-tui"];});
    environment.systemPackages = [pkg];

    # The inet vpn_tui table coexists with the others (networking.firewall, nftables):
    # a drop in ANY base chain of the same hook is final.
    # We do not depend on networking.nftables.enable and do not touch the firewall.
    boot.kernelModules = ["wireguard" "tun" "nf_tables"];

    systemd.tmpfiles.rules = [
      "d /var/lib/vpn-tui 0700 root root -"
      "d /var/lib/vpn-tui/profiles 0700 root root -"
      # x for the group: traverse to the socket. auth-* and state.json are 0600.
      "d /run/vpn-tui 0750 root vpn-tui -"
      # setgid: events.jsonl recreated by the purge stays group-readable without CAP_CHOWN.
      "d /var/cache/vpn-tui 2750 root vpn-tui -"
    ];

    systemd.sockets.vpn-tuid = {
      description = "vpn-tui daemon socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenStream = "/run/vpn-tui/vpn-tuid.sock";
        SocketMode = "0660";
        SocketUser = "root";
        SocketGroup = "vpn-tui";
      };
    };

    systemd.services.vpn-tuid = {
      description = "vpn-tui daemon";
      requires = ["vpn-tuid.socket"];
      after = ["vpn-tuid.socket"];
      # openvpn calls `ip`; systemd provides resolvectl.
      path = [pkgs.openvpn pkgs.iproute2 pkgs.systemd];
      serviceConfig =
        {
          Type = "simple";
          ExecStart = lib.concatStringsSep " " ([bin] ++ args);
          # Keep openvpn alive across a daemon stop/restart: the tunnel is adopted at the next start.
          KillMode = "process";
        }
        // hardening;
    };

    systemd.services.vpn-tuid-restore-lock = mkIf cfg.restoreLockOnBoot {
      description = "vpn-tui: restore the kill switch lock at boot";
      wantedBy = ["multi-user.target"];
      before = ["network-pre.target"];
      wants = ["network-pre.target"];
      # No DefaultDependencies: explicitly wait for tmpfiles (/run/vpn-tui) and /var/lib.
      after = ["systemd-tmpfiles-setup.service"];
      unitConfig = {
        DefaultDependencies = false;
        RequiresMountsFor = "/var/lib/vpn-tui";
      };
      path = [pkgs.openvpn pkgs.iproute2 pkgs.systemd];
      serviceConfig =
        {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = lib.concatStringsSep " " ([bin "--restore-lock"] ++ common);
        }
        // hardening;
    };

    systemd.user.services.vpn-tui-notify = mkIf cfg.notify.enable {
      description = "vpn-tui desktop notifications";
      wantedBy = ["default.target"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkg}/bin/vpn-tui notify";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
