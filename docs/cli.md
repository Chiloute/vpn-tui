# Command-line reference

This page covers the `vpn-tui` subcommands, their exit codes, the `lhost` file, `vpn-tui notify` and the `vpn-tuid` flags.

`vpn-tui` with no argument opens the TUI (key bindings: [keys.md](keys.md)). With at least one argument, it runs a subcommand and exits.

## `vpn-tui` subcommands

```text
vpn-tui status [--json]
vpn-tui import <file> [--name NAME] [--id ID]
vpn-tui list [--json]
vpn-tui up <id>
vpn-tui down
vpn-tui lhost
vpn-tui logs [--since 24h|7d|30m|RFC3339_DATE] [--json]
vpn-tui panic-off [--yes]
vpn-tui notify
vpn-tui --version
vpn-tui --help
```

Options are parsed globally: `--json`, `--help` (`-h`), `--version` (`-v`), `--name`, `--id`, `--since`, `--yes`. An unknown option or command prints the usage on stderr and exits with 1. `--help` prints the usage and exits with 0. `--version` prints the version and exits with 0.

Every command that talks to the daemon uses the socket `/run/vpn-tui/vpn-tuid.sock`, or the one in the `VPN_TUI_SOCKET` environment variable. A request times out after 5 s, except `up` (90 s).

### `status`

Prints the daemon state on one line.

| State | Output | Exit code |
| --- | --- | --- |
| `armed` | `● CONNECTED <profile>  LHOST <ip>  KILLSWITCH ON\|OFF` | 0 |
| `disarmed` | `○ DISCONNECTED` | 1 |
| `locked` | `■ LOCKED` | 2 |
| `reconnecting` | `◐ RECONNECTING <attempt>/<max>` | 2 |
| daemon unreachable, access denied, RPC error | message on stderr | 3 |

`--json` prints the raw result of the `status` method (fields: `state`, `profile`, `killswitch`, `lhost`, `scope`, `since`, `reconnect`, `interface`, `rx_bytes`, `tx_bytes`). The exit code does not change.

```bash
vpn-tui status
vpn-tui status --json | jq -r .lhost
```

### `import <file>`

Imports an OpenVPN (`.ovpn`) or WireGuard (`.conf`) profile. The type comes from the extension, then from the content (`[Interface]` for WireGuard; `remote`, `client` or `dev` for OpenVPN).

| Option | Effect | Default |
| --- | --- | --- |
| `--name NAME` | Display name (1 to 64 characters). | File name without extension. |
| `--id ID` | Identifier, `^[a-z0-9][a-z0-9-]{0,31}$`. | Slugified name. |

Steps, in order:

1. The client reads the file and extracts the secrets: the `<auth-user-pass>` block (OpenVPN, two lines: user name and password), `PrivateKey` and `PresharedKey` (WireGuard). In the content it sends, the block is replaced by a bare `auth-user-pass` directive, and the WireGuard keys by `@keyring`.
2. The client sends the cleaned content to the daemon (`profile_import`). The daemon applies its allowlist (see [security.md](security.md#allowlist-for-imported-configurations)).
3. If the daemon accepts, the client stores the secrets in the Secret Service (`secret-tool store`). If that fails, it asks the daemon to delete the profile.

On success, the command prints a summary:

```text
Profile imported: thm
  type    : openvpn
  id      : thm
  server  : 10.10.10.10 1194
  secrets : none
```

`server` is the first `remote` (OpenVPN) or `Endpoint` (WireGuard). `secrets` reads `moved to the keyring` when secrets were extracted.

When the daemon rejects the configuration, the command prints its message on stderr, for example `line 12: directive "up" is forbidden (runs a script)`.

| Code | Case |
| --- | --- |
| 0 | Profile imported. |
| 1 | Unreadable file or unrecognised type, `auth-user-pass <file>` (unsupported), config rejected by the daemon (`-32006`) or invalid parameters (`-32602`), keyring failure. |
| 3 | Daemon unreachable, access denied, other RPC error. |

The client does not filter dangerous directives (for example `up /bin/sh`). Only the daemon rejects them.

### `list`

Prints a table with the columns `ID`, `NAME`, `TYPE`, `TAGS`, `SCOPE` and `SECRETS` (`yes` when the profile has a keyring reference, `no` otherwise). With no profile it prints `No profiles`. `--json` prints the raw result of the `list` method. Exit code 0, or 3 on a daemon or transport error.

### `up <id>`

Brings the profile `<id>` up. Exactly one identifier is accepted.

1. The client calls `list` to check that the profile exists and whether it has secrets.
2. If `has_secrets` is true, it reads the secrets from the keyring (`secret-tool lookup service vpn-tui profile <id>`).
3. It calls `up` with the identifier and the secrets. The daemon answers once the tunnel is up and the firewall armed.
4. It prints the same text as `status`. If that last `status` call fails, the profile is up anyway: the command prints a warning on stderr and exits with 0.

Bringing up a profile while another one is active switches from one to the other without removing the firewall (see [architecture.md](architecture.md#state-machine)).

| Code | Case |
| --- | --- |
| 0 | Profile active. |
| 1 | Unknown profile, secrets missing from the keyring, unreadable keyring, error returned by `up` (profile already active, connection failed, secrets refused). |
| 3 | Daemon unreachable, access denied, RPC error on `list` or `status`. |

### `down`

Stops the tunnel and removes the firewall. Prints the resulting state (`○ DISCONNECTED`). Exit code 0, or 3 on a daemon or transport error. If the daemon cannot stop the tunnel or remove the nft table, it returns the error, applies the lock and the state becomes `locked`. If only the `status` call after the `down` fails, the command prints a warning and exits with 0.

### `lhost`

Prints the IPv4 address of the tunnel (LHOST) on stdout, with no other text.

| Code | Case |
| --- | --- |
| 0 | LHOST printed. |
| 1 | No LHOST (no tunnel, or tunnel without IPv4). Nothing is printed. |
| 3 | Daemon unreachable, access denied, RPC error. |

```bash
nc -lvnp 4444 -s "$(vpn-tui lhost)"
```

### `logs`

Prints the events of the daemon journal, oldest first (1000 at most).

| Option | Effect | Default |
| --- | --- | --- |
| `--since` | Duration (`30m`, `24h`, `7d`) or RFC 3339 date. | `24h` |
| `--json` | One JSON event per line. | text |

Text format: `YYYY-MM-DD HH:MM:SS  <profile|->  <state>  <kind>  <detail>`, in local time. With no event it prints `No events` (nothing with `--json`).

| Code | Case |
| --- | --- |
| 0 | Printed. |
| 1 | Invalid `--since`. |
| 3 | Daemon unreachable, access denied, RPC error. |

### `panic-off`

Asks the daemon to remove the kill switch, stop the tunnel and clear its markers.

| Option | Effect |
| --- | --- |
| `--yes` | No confirmation. Required when stdin is not a terminal. |

Without `--yes`, the command asks you to type `yes`. Any other answer cancels. On success it prints `Kill switch removed and tunnel dropped.` followed by the state (or a warning on stderr if the state cannot be read; the exit code stays 0).

| Code | Case |
| --- | --- |
| 0 | Kill switch removed. |
| 1 | No terminal and no `--yes`, or confirmation refused. |
| 3 | Daemon unreachable or RPC error. The command then reminds you of `vpn-tuid --panic-off` (root) and `nft delete table inet vpn_tui`. |

### `notify`

See [Desktop notifications](#desktop-notifications-vpn-tui-notify).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (for `status`: state `armed`). |
| 1 | Usage or local error; for `status`: state `disarmed`; for `lhost`: no LHOST. |
| 2 | `status` only: state `locked` or `reconnecting`. |
| 3 | Daemon unreachable, timeout, response outside the contract, or RPC error (access denied `-32001` included). |

## The `lhost` file

Each time the client reads the daemon state, it writes the LHOST address to `~/.cache/vpn-tui/lhost` (or `$XDG_CACHE_HOME/vpn-tui/lhost`). The file holds `IP\n`, or nothing when there is no LHOST. The write is atomic (temporary file, then `rename`) and only happens when the content changes. The directory is created with mode 0700. If the write fails, the client prints a warning and carries on.

`status`, `up`, `down`, `lhost`, `panic-off`, the TUI (on every refresh) and `vpn-tui notify` update the file. When none of them is running, the file can be stale.

Usage examples.

tmux (`~/.tmux.conf`):

```tmux
set -g status-interval 5
set -g status-right '#(cat ~/.cache/vpn-tui/lhost 2>/dev/null)'
```

zsh (`~/.zshrc`):

```zsh
lhost() { cat ~/.cache/vpn-tui/lhost 2>/dev/null; }
setopt prompt_subst
RPROMPT='$(lhost)'
```

waybar (`~/.config/waybar/config`):

```json
"custom/lhost": {
  "exec": "cat ~/.cache/vpn-tui/lhost 2>/dev/null",
  "interval": 5,
  "format": "VPN {}"
}
```

> [!NOTE]
> These snippets are not tested in the repository. Only the file format (`IP\n`) is.

## Desktop notifications: `vpn-tui notify`

`vpn-tui notify` subscribes to the daemon events (`events_subscribe`) and calls `notify-send` for some of them. It also updates the `lhost` file on every event. It runs until `SIGINT` or `SIGTERM`, then exits with 0.

| Event | Notification title | Urgency |
| --- | --- | --- |
| `up` | VPN connected | normal |
| `down` | VPN disconnected | normal |
| `drop` | tunnel lost | critical |
| `reconnect` | reconnecting | normal |
| `lock` | VPN locked | critical |
| `panic_off` | panic-off | critical |
| `scope_learned` | scope learned | normal |

Other event kinds trigger no notification. The body holds the profile and the detail, stripped of control characters and cut to 200 characters.

When the connection to the daemon drops, the command retries after 2 s, doubling the delay on each failure up to 30 s. If `notify-send` is missing, it warns once on stderr and carries on without notifications. The `VPN_TUI_NOTIFY_SEND` variable replaces the binary.

The NixOS module generates the user unit `vpn-tui-notify` (in `nix/module.nix`) when `services.vpn-tui.notify.enable` is set: `ExecStart=<vpn-tui>/bin/vpn-tui notify`, `Restart=on-failure`, `RestartSec=5`, `WantedBy=default.target`. The root daemon never sends a notification.

## Environment variables

| Variable | Effect |
| --- | --- |
| `VPN_TUI_SOCKET` | Daemon socket path. Default: `/run/vpn-tui/vpn-tuid.sock`. |
| `XDG_CACHE_HOME` | Root of the `lhost` file. Default: `~/.cache`. |
| `XDG_CONFIG_HOME` | Root of `vpn-tui/config.yaml`. Default: `~/.config`. |
| `VPN_TUI_SECRET_TOOL` | Replaces the `secret-tool` binary. |
| `VPN_TUI_NOTIFY_SEND` | Replaces the `notify-send` binary. |

## `vpn-tuid`

The daemon runs as root. It aligns itself with the host at startup, then serves the JSON-RPC socket. With no client, no active VPN and no lock, it exits after `--idle-timeout`.

```text
vpn-tuid [flags]
vpn-tuid --version
vpn-tuid --panic-off
vpn-tuid --restore-lock
```

| Flag | Default | Effect |
| --- | --- | --- |
| `--socket` | `/run/vpn-tui/vpn-tuid.sock` | Unix socket path. Ignored under systemd socket activation (fd 3). |
| `--group` | `vpn-tui` | Group allowed to connect. Root is always allowed. |
| `--idle-timeout` | `60s` | Exit after this long with no connection, no active tunnel and no lock. |
| `--state-dir` | `/var/lib/vpn-tui` | State directory. Profiles live in `<state-dir>/profiles`. |
| `--run-dir` | `/run/vpn-tui` | Runtime files (`state.json`, OpenVPN config and management socket). Created with mode 0700. |
| `--cache-dir` | `/var/cache/vpn-tui` | `events.jsonl` journal. Created with mode 0750. |
| `--openvpn` | (looked up in `PATH`) | OpenVPN binary. |
| `--ovpn-user` | `nobody` | User OpenVPN drops privileges to. Empty: no drop. |
| `--ovpn-group` | `nogroup` | Matching group. Empty: no drop. |
| `--connect-timeout` | `60s` | OpenVPN connection timeout (until the `CONNECTED` state). |
| `--reconnect-max-attempts` | `10` | Reconnection attempts before staying locked. |
| `--reconnect-max-backoff` | `60s` | Cap of the delay between attempts (1 s at first, doubled each attempt). |
| `--handshake-timeout` | `180s` | WireGuard: tunnel considered dead after this long without a handshake while packets are being sent. |
| `--marker` | `<state-dir>/armed.json` | "Armed" marker file. |
| `--journal-max-age` | `168h` | Journal retention (7 days). |
| `--resolvectl` | (looked up in `PATH`) | `resolvectl` binary. Not found: profile DNS is not applied. |
| `--panic-off` | false | See below. |
| `--restore-lock` | false | See below. |
| `--version` | false | Prints the version and exits. |

The wait for the first WireGuard handshake (10 s) has no flag.

A fatal error is written to stderr (`slog`) and the daemon exits with 1.

### `vpn-tuid --panic-off`

Emergency exit. The command opens no socket, does not contact the daemon and does not use its state manager. It runs every step even if one fails:

1. deletes the nft table `inet vpn_tui`;
2. if `state.json` holds a PID, stops that process only when its `comm` is `openvpn`;
3. deletes the `fwmark 51820` routing rules;
4. deletes the `vpntui0` interface;
5. deletes the armed marker and `state.json`;
6. writes a `panic_off` event to the journal.

Each step prints one line saying whether it succeeded, failed or was skipped. The exit code is 1 if at least one step failed, otherwise 0. Run it as root, with the daemon stopped (see [security.md](security.md#known-limits)).

```bash
sudo systemctl stop vpn-tuid.socket vpn-tuid.service   # unit names from the NixOS module
sudo vpn-tuid --panic-off
```

### `vpn-tuid --restore-lock`

Oneshot mode for machine boot. If the armed marker exists, the command re-applies the nft lock (state `locked`: the firewall lets `lo` and the VPN endpoints through) and exits. Without a marker it does nothing. If the marker is unreadable, it locks everything (no endpoint allowed) and exits with 1. The tunnel is not brought back up.

The NixOS module runs this command at boot (unit `vpn-tuid-restore-lock`) when `services.vpn-tui.restoreLockOnBoot` is true (default: false).
