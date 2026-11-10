# Security

This page describes the threat model of vpn-tui, what the daemon exposes, how imported configurations and secrets are handled, and the known limits.

## Threat model

`vpn-tuid` runs as root and starts OpenVPN as root. Two inputs are not trusted.

**An attacker who controls the user session.** This is a process running as a member of the `vpn-tui` group (or as root). It can use every method of the socket (list below). The intended maximum impact is to bring up or cut the existing profiles. Within the code, the same attacker can also:

- call `panic_off`, which removes the kill switch;
- edit a profile with `profile_update`, including `killswitch.enabled = false` or an empty scope;
- import a new profile that points to a server it controls (the configuration must pass the allowlist, but a `remote` and a `redirect-gateway` are allowed);
- delete profiles and read the journal.

What it cannot do through the daemon: run a command as root through a configuration (scripts and plugins are rejected), name a file path (the client never sends one), or read secrets back (no method returns them). The Secret Service belongs to the user session, so an attacker in that session reads the secrets there. Protecting the keyring from your own session is out of scope.

**A malicious imported configuration.** A `.ovpn` or WireGuard file from a third party can contain directives that run code (`up`, `plugin`, `PostUp`), read or write files, or open a control interface. The daemon parses every configuration with an allowlist before storing it and again before every connection. Anything not listed is rejected.

## Daemon surface

### Methods

The list of methods is fixed by the schema (`$defs/method`). Any other method is rejected as an invalid request.

| Method | Effect |
| --- | --- |
| `status` | State, profile, LHOST, counters. |
| `list` | Profiles, without secrets (`has_secrets` only). |
| `up` | Brings a profile up. The only method that carries secrets. |
| `down` | Stops the tunnel, removes the firewall. |
| `panic_off` | Stops everything, removes the firewall and the markers. |
| `profile_import` | Parses and stores a profile. |
| `profile_update` | Edits name, tags, color, scope, kill switch, DNS. |
| `profile_delete` | Deletes a profile. |
| `scope_learn_accept` | Adds learned CIDRs to the scope. |
| `events_subscribe` | Streams events on the connection. |
| `logs` | Reads the journal (1000 events at most). |

### Caller check

- Every connection is checked with `SO_PEERCRED`. The daemon accepts uid 0, or a uid that belongs to the group set by `--group` (default `vpn-tui`), looked up in `/etc/group` on each connection.
- Any other caller gets a `forbidden` error (`-32001`) and the connection is closed. The refusal is logged with the uid and the PID.
- The socket is 0660. With the NixOS module its group is `vpn-tui` (see [configuration.md](configuration.md#locations)).

### Input limits

- A message is 64 KiB at most. A longer one gets `too_large` (`-32002`) and the connection is closed. A request is read with a 30 s timeout.
- Every request is validated against the JSON schema, which forbids unknown properties. Profile methods also reject unknown fields at decoding.
- A profile identifier matches `^[a-z0-9][a-z0-9-]{0,31}$`. An imported file is 48 KiB at most for OpenVPN and 16 KiB for WireGuard.
- Secrets have fixed shapes: OpenVPN user (1 to 256 characters) and password (1024 at most); WireGuard keys are 44-character base64.
- The daemon logs the method and the identifier, never the content or the secrets.

### Storage

- The client never sends a path. The daemon builds `/var/lib/vpn-tui/profiles/<id>/` from a validated identifier, and the configuration file name is fixed by the profile type (`client.ovpn` or `wg.conf`).
- All accesses go through `os.Root` rooted at `profiles/`, so nothing can leave that directory. Symbolic links and non-regular files are refused.
- Directories are created 0700 and files 0600. Files are written to a temporary name, synced, then renamed.
- Runtime files live in `/run/vpn-tui`: 0700 when the daemon creates the directory, 0750 `root:vpn-tui` with the NixOS module, where `state.json` and the credentials file stay 0600. The OpenVPN management socket is a Unix socket in that directory.

## Allowlist for imported configurations

The parsers live in `daemon/internal/ovpn/parse.go` and `daemon/internal/wg/parse.go`. They reject, among others: NUL bytes, invalid UTF-8 and control characters (OpenVPN), duplicated keys (WireGuard), and the OpenVPN prefix `--`. The stored file is a rewritten version of the input, not the input itself: comments are dropped and `remote` lines are normalised.

### OpenVPN

**Allowed.**

| Directives | Argument check |
| --- | --- |
| `client`, `nobind`, `persist-key`, `persist-tun`, `remote-random`, `auth-nocache`, `pull`, `route-nopull`, `block-outside-dns` | none |
| `auth-user-pass` | none (a file argument is rejected) |
| `dev`, `dev-type` | only `tun` |
| `proto` | `udp`, `udp4`, `udp6`, `tcp`, `tcp4`, `tcp6`, `tcp-client` variants |
| `remote <host> [port] [proto]` | valid host name or IP (no zone), port 1 to 65535 |
| `resolv-retry` | `infinite` or an integer |
| `remote-cert-tls` | `server` or `client` |
| `key-direction` | `0` or `1` |
| `comp-lzo`, `allow-compression` | only `no` |
| `verify-x509-name` | a safe token, optional type `name`, `name-prefix` or `subject` |
| `cipher`, `auth` | a safe token, not `none` |
| `data-ciphers`, `data-ciphers-fallback`, `tls-cipher`, `tls-version-min` | safe tokens |
| `explicit-exit-notify`, `verb`, `mute`, `ping`, `ping-restart`, `connect-timeout`, `server-poll-timeout`, `connect-retry` | integers |
| `redirect-gateway` | `local`, `autolocal`, `def1`, `bypass-dhcp`, `bypass-dns`, `block-local`, `ipv6`, `!ipv4` |
| `route` | 1 to 4 arguments: IP, integer, `vpn_gateway`, `net_gateway`, `remote_host` or `default` |
| `<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>` | inline blocks, content checked as PEM or OpenVPN static key |

**Rejected, with the reason.**

| Directives | Reason |
| --- | --- |
| `up`, `down`, `route-up`, `route-pre-down`, `tls-verify`, `learn-address`, `client-connect`, `client-disconnect`, `auth-user-pass-verify` | run a script |
| `ipchange` | runs a command |
| `script-security` | allows script execution |
| `plugin`, `pkcs11-*` | load native code or an external library |
| `iproute` | runs an arbitrary program |
| `config`, `cd`, `chroot` | include a file, change directory or root |
| `writepid`, `log`, `log-append`, `status` | write an arbitrary file |
| `daemon` | changes the execution mode |
| `management*` | opens a control interface (the daemon sets its own) |
| `setenv*` | changes the environment |
| `ca`, `cert`, `key`, `tls-auth`, `tls-crypt`, `tls-crypt-v2`, `askpass`, `auth-user-pass <file>` as directives | reference an external file: only inline blocks are accepted |
| `<auth-user-pass>` block | plaintext secret: the client must extract it to the keyring |
| `cipher none`, `auth none` | would send traffic in clear |
| any other directive | not in the allowlist |

The last row is a usability limit: common directives such as `keepalive`, `tls-client`, `reneg-sec` and `mssfix` are refused.

At launch, the daemon writes a runtime configuration from the stored one. It removes `remote`, `remote-random`, `dev` and `dev-type`, and adds the IPs it resolved itself (`remote <ip> <port> <proto>`). It starts OpenVPN with an argument array (no shell), with `--script-security 1`, `--dev vpntui0 --dev-type tun`, its own management socket, `--auth-nocache`, `--auth-retry none`, and `--user`/`--group` set to `nobody`/`nogroup` by default (the NixOS module empties them, see [systemd hardening](#systemd-hardening)). Only `PATH` is passed in the environment.

### WireGuard

**Allowed.** In `[Interface]`: `PrivateKey` (only the value `@keyring`), `Address`, `DNS` (IP addresses only), `MTU` (576 to 9000), `ListenPort`. In `[Peer]`: `PublicKey` (base64, 32 bytes), `PresharedKey` (only `@keyring`), `Endpoint` (`host:port`), `AllowedIPs`, `PersistentKeepalive`. One `[Interface]` first, at least one `[Peer]`.

**Rejected.**

| Key | Reason |
| --- | --- |
| `PostUp`, `PostDown`, `PreUp`, `PreDown` | script |
| `SaveConfig` | writes to disk |
| `Table`, `FwMark` | routing is managed by the daemon |
| plaintext `PrivateKey` or `PresharedKey` | the client must extract it to the keyring |
| DNS search domains | only IP addresses are accepted |
| any other key or section | not in the allowlist |

The daemon builds the interface and the routing itself, through netlink. For a full tunnel (`AllowedIPs` covering the default route) it sets up `fwmark 51820` rules, like `wg-quick`.

## Secrets

1. **At import**, the client extracts the secrets before anything is sent: the `<auth-user-pass>` block of OpenVPN, `PrivateKey` and `PresharedKey` of WireGuard. The daemon never receives them at import, and rejects a file that still contains them.
2. **In the keyring**, the client stores them with `secret-tool store`. The secret goes through stdin, not through arguments. The entry carries `service=vpn-tui` and `profile=<id>`.
3. **At `up`**, the client reads them back and sends them in `up.params.secrets`. This is the only place where secrets travel on the socket.
4. **In the daemon**, they stay in memory only, in the active session, so that a reconnection can reuse them. They are wiped by `down`, `panic_off` and when the reconnection attempts run out. They are not written to `state.json`, to the marker or to the journal. The type that holds them prints `[redacted]`.
5. **OpenVPN** reads credentials from a file `/run/vpn-tui/auth-<id>`, created with `O_EXCL` and mode 0600 in a 0700 directory. The file is deleted as soon as the start returns, whether it succeeded or not. A user name or password containing a line break is refused. OpenVPN output lines that contain the user name or password are replaced by `[redacted]`, and so is the `auth-token`.
6. **WireGuard** keys go to the kernel through netlink. No file is written.

Remaining exposure: the inline `<key>` (client certificate key) and `<tls-crypt>` blocks of an OpenVPN file are not extracted. They stay in `client.ovpn` under `/var/lib/vpn-tui/profiles/<id>/` (0600, root).

## systemd hardening

The NixOS module (`nix/module.nix`) applies these options to `vpn-tuid.service` and to the restore-lock oneshot. OpenVPN is a child process and inherits the same sandbox.

| Option | Value |
| --- | --- |
| `CapabilityBoundingSet` | `CAP_NET_ADMIN CAP_NET_RAW` |
| `AmbientCapabilities` | empty |
| `NoNewPrivileges` | `true` |
| `ProtectSystem` | `strict` |
| `ProtectHome` | `true` |
| `PrivateTmp` | `true` |
| `ReadWritePaths` | `/var/lib/vpn-tui`, `/run/vpn-tui`, `/var/cache/vpn-tui` |
| `RestrictAddressFamilies` | `AF_UNIX`, `AF_NETLINK`, `AF_INET`, `AF_INET6` |
| `SystemCallFilter` | `@system-service` |
| `SystemCallArchitectures` | `native` |
| `MemoryDenyWriteExecute`, `LockPersonality`, `RestrictNamespaces`, `RestrictRealtime` | `true` |
| `ProtectKernelTunables`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname` | `true` |
| `DevicePolicy`, `DeviceAllow` | `closed`, `/dev/net/tun rw` |

The module reports a `systemd-analyze security` score of 2.9 for the daemon service (figure given by the maintainer, not reproduced here).

Consequences:

- Without `CAP_SETUID` and `CAP_SETGID`, OpenVPN cannot switch to `nobody`. The module therefore passes `--ovpn-user "" --ovpn-group ""`: OpenVPN runs as root, inside this sandbox. Run by hand, `vpn-tuid` drops OpenVPN to `nobody:nogroup` by default.
- The daemon only writes under the three `ReadWritePaths`.
- The module comment states that neither the daemon nor OpenVPN writes a sysctl (netlink only), which is why `ProtectKernelTunables` is on.

The `vpn-tui-notify` user unit generated by the module has no sandboxing options. It does not touch the firewall and does not connect to anything but the daemon socket.

No test in the repository runs the daemon under these options (`flake.nix` has a TODO for a `killswitch` check).

## In doubt, lock

When the daemon cannot tell what the situation is, it locks instead of disarming. In the code:

- A failed `up` with the kill switch on leaves the `locked` state, not `disarmed`.
- A failed `down` (tunnel or firewall) leaves the state `locked`.
- A failed `Arm` leaves the state `locked`.
- When reconnection attempts run out, the state stays `locked`.
- At startup, `Reconcile` locks in every case it cannot resume cleanly, and when a probe fails. It never calls `Disarm`.
- An unreadable `state.json` counts as "active". An unreadable marker locks everything, with no endpoint allowed.
- Stopping or restarting the daemon never removes the firewall.

Only `down`, `panic_off` and `vpn-tuid --panic-off` remove the table.

## Known limits

- **Routes and the kill switch.** The allowlist accepts `route ... net_gateway`, `redirect-gateway` with `bypass-dhcp`, `bypass-dns` or `local`, and OpenVPN applies the routes pushed by the server unless the file has `route-nopull`. The daemon does not filter routes. Traffic can be steered outside the tunnel at the routing level. Only the firewall stops it, through `scope`, `allow_internet` and `block_ipv6`. With an empty scope and `allow_internet = true`, only IPv6 is stopped (if `block_ipv6` is on) while the tunnel is up.
- **No reconnection after a daemon restart.** Secrets are not persisted. After a restart, a tunnel that survived is adopted (`resumed`), but if it drops, the daemon locks (kill switch on) or disarms (off) and does not reconnect. Run `up` again.
- **`vpn-tuid --panic-off` needs the daemon stopped.** The command does not signal the daemon and does not touch its memory. A running daemon keeps its session and its reconnection loop, and can apply the lock again.
- **DNS pushed by an OpenVPN server is ignored.** The daemon runs no `up` script. It only applies the DNS of the profile (`dns.servers`) through `resolvectl`. Without it, DNS queries go to the system resolver, outside the tunnel, unless `dns.force` or `allow_internet = false` blocks them.
- **OpenVPN integration.** Real OpenVPN is only exercised by `scripts/it-ovpn.sh`, which needs `/dev/net/tun` and exits with 77 otherwise. Unit tests use a fake `openvpn`. No VM test is in the repository yet (`flake.nix` has a TODO for a `killswitch` check).
- **WireGuard handshake wait is fixed at 10 s.** `up` fails after that delay. `--handshake-timeout` (180 s) is a different setting: it detects a dead tunnel after the connection is up.
- **`up /bin/sh` is refused only by the daemon.** The client does not validate directives. It sends the file and shows the daemon error.
- **A failed `Lock` is not fatal to the state.** If netlink refuses the call, the daemon emits an `error` event and records `locked` anyway.
- **Table removed by another tool.** `flush ruleset` deletes `vpn_tui` too. The daemon only checks the table at startup.
- **Socket group.** When the daemon creates the socket itself, it stays owned by root. The `vpn-tui` group only gets access through systemd socket activation, as the NixOS module sets up.
- **OpenVPN runs as root under the module.** The privilege drop is off (see [systemd hardening](#systemd-hardening)). The sandbox limits the damage, but a flaw in OpenVPN itself runs with the daemon's capabilities.

## Reporting a vulnerability

TODO: add a private contact (address or private advisory page). Do not open a public issue for a vulnerability.
