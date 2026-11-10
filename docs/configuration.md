# Configuration

This page covers the TOML profile, the TUI configuration files, the NixOS module options and the file locations.

## Profile (`profile.toml`)

The daemon stores each profile in `/var/lib/vpn-tui/profiles/<id>/profile.toml`, next to the sanitized VPN configuration (`client.ovpn` or `wg.conf`). You create a profile with `vpn-tui import` or the TUI, and edit it with the TUI (`profile_update` method). The daemon re-reads and validates the file on every access: an invalid profile is skipped by `list` (a warning goes to the daemon log) and refused everywhere else.

Example, as the daemon writes it:

```toml
id = "thm"
name = "TryHackMe"
type = "openvpn"
config = "client.ovpn"
tags = ["thm"]
color = "base0D"

[scope]
cidrs = ["10.10.0.0/16"]
exclude = []
learned = []

[killswitch]
enabled = true
allow_internet = true
block_ipv6 = true

[dns]
servers = []
force = false

[secrets]
keyring_ref = "vpn-tui/thm"
```

### Fields

| Field | Type | Editable | Value at import | Constraint |
| --- | --- | --- | --- | --- |
| `id` | string | no | `--id`, else derived from the name | `^[a-z0-9][a-z0-9-]{0,31}$`. Name of the profile directory. |
| `name` | string | yes | `--name`, else the file name | 1 to 64 characters. |
| `type` | string | no | detected | `openvpn` or `wireguard`. |
| `config` | string | no | set by the type | `client.ovpn` (OpenVPN) or `wg.conf` (WireGuard). |
| `tags` | list | yes | empty | At most 8, each `^[a-z0-9-]{1,16}$`. |
| `color` | string | yes | `base0D` | Base16 theme color name: `base00` to `base0F`. |
| `scope.cidrs` | list of CIDRs | yes | empty | See below. |
| `scope.exclude` | list of CIDRs | yes | empty | See below. |
| `scope.learned` | list of CIDRs | yes | empty | Routes learned and accepted. |
| `killswitch.enabled` | boolean | yes | `true` | Turns the firewall on. |
| `killswitch.allow_internet` | boolean | yes | `true` | Allows traffic outside the scope. |
| `killswitch.block_ipv6` | boolean | yes | `true` | Blocks all IPv6 outside the tunnel. |
| `dns.servers` | list of IPs | yes | empty | At most 8, IP addresses without zone. |
| `dns.force` | boolean | yes | `false` | Routes all DNS to these servers. |
| `secrets.keyring_ref` | string | no | see below | `vpn-tui/<id>` or empty. |

Each CIDR list holds at most 1024 entries. A CIDR must be canonical: `10.10.0.0/16` is accepted, `10.10.1.5/16` is rejected, and so is any CIDR with an IPv6 zone.

#### `scope`

The scope is the list of target networks (the engagement) that must never be reached outside the tunnel.

- `cidrs`: protected networks. The firewall drops any packet addressed to them that does not leave through `vpntui0`.
- `exclude`: subnets of `cidrs` that are not protected. The rule is `daddr { cidrs } daddr != { exclude } drop`.
- `learned`: routes read from the interface after connection (default routes excluded), reported by the `scope_learned` event. The TUI offers to accept them (key `s`): the `scope_learn_accept` method adds them to `cidrs` and to `learned`. Nothing is added without that action.

An imported profile has an empty scope. Until you add one, the armed firewall protects no network and is limited to `block_ipv6`. The exact rules are in [architecture.md](architecture.md#nft-rules-by-state).

#### `killswitch`

- `enabled = false`: no firewall. The profile goes up and down without any nft table. When the tunnel drops, the state becomes `reconnecting`, with no lock.
- `allow_internet = false`: any output that does not go through the tunnel, to `lo` or to a VPN endpoint is dropped.
- `block_ipv6 = true`: any IPv6 packet outside the tunnel is dropped (except `lo` and the endpoints).

#### `dns`

The servers are applied to the `vpntui0` interface with `resolvectl` (systemd-resolved) and reverted when the tunnel stops. Without `resolvectl`, a warning is logged and the profile DNS is not applied. If `servers` is empty, nothing is applied.

- `force = false`: the servers only serve the domains routed to the interface (`default-route` false).
- `force = true`: domain `~.` and DNS default route on the interface, and the firewall drops ports 53 and 853 (UDP and TCP) outside the tunnel.

The DNS pushed by an OpenVPN server is not applied (see [security.md](security.md#known-limits)).

#### `secrets.keyring_ref`

Reference of the Secret Service entry. At import, the daemon sets it to `vpn-tui/<id>` for every WireGuard profile and for an OpenVPN profile whose configuration contains `auth-user-pass`. Profiles without secrets have an empty value. The daemon never reads the keyring: the client stores and reads the secrets with `secret-tool`, attributes `service=vpn-tui` and `profile=<id>`, JSON content:

| Type | Content |
| --- | --- |
| OpenVPN | `{"username": "...", "password": "..."}` |
| WireGuard | `{"private_key": "...", "preshared_key": "..."}` (`preshared_key` optional) |

## TUI configuration: `~/.config/vpn-tui/config.yaml`

The file is optional. It is merged key by key over `app/config/default.yaml` (embedded in the binary), then validated as a whole. An unreadable or invalid file is ignored entirely, with a warning. An unknown key under `keybinds` invalidates the file. The path follows `XDG_CONFIG_HOME` when set.

### `keybinds`

One entry per command: `<view>.<command>: "<key>"`. Several keys are separated by a comma (`"up,k"`). The full list of names and default values is in [keys.md](keys.md), generated from the code. Loading fails if two commands of the same view (global commands included) use the same key.

```yaml
keybinds:
  global.copyLhost: "shift+y"
  profiles.nav: "up,down,j,k"
```

### `theme`

Same schema as the ilovetui file below. Values in `theme` override those of `~/.config/ilovetui/config.yaml`.

```yaml
theme:
  border: heavy
  colors:
    base0d: "#80B880"
```

## Shared theme: `~/.config/ilovetui/config.yaml`

This file belongs to the ilovetui library and is shared by every TUI that uses it. The layers, weakest to strongest: ilovetui defaults, this file, then the `theme` section of `~/.config/vpn-tui/config.yaml`.

| Key | Type | ilovetui default | Effect |
| --- | --- | --- | --- |
| `nerd_fonts` | boolean | `true` | Nerd Font glyphs. |
| `emoji_fonts` | boolean | `true` | Emoji glyphs. |
| `reduced_motion` | boolean | `false` | No animation. |
| `mouse` | boolean | `true` | Mouse handlers. |
| `border` | `single`, `double`, `rounded`, `heavy` | `rounded` | Frame style. |
| `colors.base00` to `colors.base0f` | `#rrggbb` | purple palette | Base16 palette. |

A profile's `color` (`base00` to `base0F`) points to one of these entries.

## NixOS module

The flake exports `nixosModules.default` (`nix/module.nix`). Import it, then set the options under `services.vpn-tui`.

| Option | Type | Default | Effect |
| --- | --- | --- | --- |
| `services.vpn-tui.enable` | boolean | `false` | Installs the `vpn-tuid.socket` and `vpn-tuid.service` units (socket-activated), the `vpn-tui` group and the package. |
| `services.vpn-tui.package` | package | default package of this flake for the host system | Package providing `vpn-tuid` and `vpn-tui`. |
| `services.vpn-tui.users` | list of strings | `[]` | Users added to the `vpn-tui` group. `root` is refused by an assertion. |
| `services.vpn-tui.idleTimeout` | string | `"60s"` | `--idle-timeout`. |
| `services.vpn-tui.restoreLockOnBoot` | boolean | `false` | Adds the `vpn-tuid-restore-lock` oneshot unit, which runs `vpn-tuid --restore-lock` at boot. Requires `enable`. |
| `services.vpn-tui.reconnect.maxAttempts` | integer | `10` | `--reconnect-max-attempts`. |
| `services.vpn-tui.reconnect.maxBackoff` | string | `"60s"` | `--reconnect-max-backoff`. |
| `services.vpn-tui.handshakeTimeout` | string | `"180s"` | `--handshake-timeout` (WireGuard). |
| `services.vpn-tui.notify.enable` | boolean | `false` | Installs the `vpn-tui-notify` user unit (`vpn-tui notify`). |

Durations are strings in the format the daemon flags accept (`60s`, `2m`).

Example:

```nix
{
  inputs.vpn-tui.url = "github:Chiloute/vpn-tui";

  # in the NixOS configuration:
  imports = [ inputs.vpn-tui.nixosModules.default ];
  services.vpn-tui = {
    enable = true;
    users = [ "alice" ];
    restoreLockOnBoot = true;
    reconnect.maxAttempts = 20;
    notify.enable = true;
  };
}
```

A user added to `users` must start a new session for the group membership to apply. The daemon checks the group on every connection, from `/etc/group`.

What the module sets, beyond the options:

- Flags passed to `vpn-tuid`: `--group vpn-tui`, `--state-dir /var/lib/vpn-tui`, `--run-dir /run/vpn-tui`, `--cache-dir /var/cache/vpn-tui`, `--marker /var/lib/vpn-tui/armed.json`, the store paths of `openvpn` and `resolvectl`, and `--ovpn-user "" --ovpn-group ""`. With the module, OpenVPN does not drop privileges: it runs in the same hardened sandbox as the daemon (see [security.md](security.md#systemd-hardening)).
- Kernel modules loaded at boot: `wireguard`, `tun`, `nf_tables`.
- Directories created by `systemd-tmpfiles`: `/var/lib/vpn-tui` and `/var/lib/vpn-tui/profiles` (0700, root), `/run/vpn-tui` (0750, `root:vpn-tui`), `/var/cache/vpn-tui` (2750, `root:vpn-tui`, setgid).
- Socket unit `vpn-tuid.socket`: `/run/vpn-tui/vpn-tuid.sock`, mode 0660, owner `root`, group `vpn-tui`.
- It does not enable `networking.nftables` and does not change `networking.firewall` (see [architecture.md](architecture.md#coexistence-with-other-nftables-chains)).

> [!NOTE]
> No flake check evaluates the module yet (`flake.nix` carries a TODO for a `killswitch` check). The options above are read from `nix/module.nix`, not from a test.

## Locations

| Path | Content | Mode | Lifetime |
| --- | --- | --- | --- |
| `/var/lib/vpn-tui/profiles/<id>/` | `profile.toml` and sanitized configuration | directories 0700, files 0600 | persistent |
| `/var/lib/vpn-tui/armed.json` | "armed" marker: profile, interface, endpoints, date (no secret) | 0600 | persistent; removed by `down` and `panic_off` |
| `/run/vpn-tui/` | runtime directory | 0700 when the daemon creates it; 0750 `root:vpn-tui` with the NixOS module | volatile (tmpfs) |
| `/run/vpn-tui/vpn-tuid.sock` | JSON-RPC socket | 0660 | volatile |
| `/run/vpn-tui/state.json` | current state: profile, state, interface, LHOST, OpenVPN PID, dates (no secret) | 0600 | volatile |
| `/run/vpn-tui/ovpn-<id>.conf`, `ovpn-mgmt.sock` | OpenVPN runtime configuration and management socket | 0600 | removed when OpenVPN stops |
| `/run/vpn-tui/auth-<id>` | OpenVPN credentials, during startup only | 0600 | deleted as soon as `Start` returns |
| `/var/cache/vpn-tui/events.jsonl` | event journal, one JSON object per line | 0640 (readable by the group with the module's setgid directory) | 7 days |
| `~/.cache/vpn-tui/lhost` | current LHOST | process default | rewritten on every state read |
| `~/.config/vpn-tui/config.yaml` | keys and theme | | |
| `~/.config/ilovetui/config.yaml` | shared theme | | |

The socket is created with mode 0660. When the daemon creates the socket itself, it does not change its group: only root can connect. With the NixOS module, systemd provides the socket (socket activation, fd 3) with group `vpn-tui`, so group members can connect.

### Journal and retention

The `events.jsonl` journal receives every daemon event (`up`, `down`, `drop`, `reconnect`, `lock`, `panic_off`, `reconcile`, `scope_learned`, `error`) with the UTC time, the profile, the state and a detail of at most 1024 bytes. At startup and then every hour, the daemon deletes entries older than `--journal-max-age` (7 days by default). Unparsable lines are kept. The `logs` method returns at most 1000 events; the TUI asks for the last 7 days.
