# vpn-tui

VPN manager for penetration testers. It handles OpenVPN and WireGuard profiles (TryHackMe, HackTheBox, client engagements) and protects the target network with an nftables kill switch.

It has two parts:

- `vpn-tuid`: a root daemon written in Go. It parses and stores profiles, starts the tunnels, applies the nftables rules and runs the state machine.
- `vpn-tui`: a TUI and CLI written in TypeScript for Bun. It runs in your session, keeps secrets in the Secret Service and talks to the daemon over a Unix socket.

<img alt="demo" src="./.github/assets/demo.gif" width="700" />

> [!WARNING]
> Use this tool only on systems and networks you are explicitly and in writing authorised to test, within the agreed scope. The author declines all responsibility for unauthorised or illegal use.

## Requirements

| Requirement | Detail |
| --- | --- |
| OS | Linux, NixOS first. Architectures `x86_64-linux` (amd64) and `aarch64-linux` (arm64). |
| nftables | Kernel support (`nf_tables`). The daemon talks to the kernel through netlink and does not need the `nft` binary. |
| WireGuard | Kernel support (`wireguard` module). The daemon does not need `wg` or `wg-quick`. |
| OpenVPN | The `openvpn` binary, for OpenVPN profiles. Needs `/dev/net/tun`. |
| Secret Service | `libsecret` (`secret-tool`) and a running Secret Service (GNOME Keyring, KeePassXC...). Used for profiles with credentials or WireGuard keys. |
| Optional | `resolvectl` (systemd-resolved) to apply a profile's DNS; `notify-send` (libnotify) for `vpn-tui notify`; a terminal with OSC 52 for the copy-LHOST key. |

To build from source: Go 1.26 and Bun (see [docs/development.md](docs/development.md)).

## Installation

Pick one method and expand it.

<details>
<summary><strong>Flake and NixOS module</strong></summary>

Add the flake as an input, import the module and enable the service:

```nix
{
  inputs.vpn-tui.url = "github:Chiloute/vpn-tui";

  outputs = { nixpkgs, vpn-tui, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        vpn-tui.nixosModules.default
        {
          services.vpn-tui = {
            enable = true;
            users = [ "alice" ];   # added to the vpn-tui group
          };
        }
      ];
    };
  };
}
```

Rebuild, then start a new session so the group membership applies:

```bash
sudo nixos-rebuild switch --flake .#myhost
```

The module installs the daemon as a socket-activated service, creates the `vpn-tui` group and the directories, and puts `vpn-tui` in the system packages. All options are in [docs/configuration.md](docs/configuration.md#nixos-module).

The packages can also be built on their own: `nix build github:Chiloute/vpn-tui` (client and daemon), `.#vpn-tuid` or `.#vpn-tui`. The daemon needs a root service to run, so use the module on NixOS.

</details>

<details>
<summary><strong>NUR</strong></summary>

The package is also in the [NUR](https://github.com/nix-community/NUR) under the repository name `Chiloute` (source: [Chiloute/nur-packages](https://github.com/Chiloute/nur-packages)). The `vpn-tui` attribute provides both `bin/vpn-tui` and `bin/vpn-tuid`. Keep the module from this flake and point `services.vpn-tui.package` (type `package`, default: this flake's `default` package) at the NUR package. The module runs `bin/vpn-tuid` for the daemon units and `bin/vpn-tui` for `vpn-tui-notify`.

```nix
{
  inputs = {
    nur.url = "github:nix-community/NUR";
    vpn-tui.url = "github:Chiloute/vpn-tui";
  };

  outputs = { nixpkgs, nur, vpn-tui, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        { nixpkgs.overlays = [ nur.overlays.default ]; }
        vpn-tui.nixosModules.default
        ({ pkgs, ... }: {
          services.vpn-tui = {
            enable = true;
            users = [ "alice" ];
            package = pkgs.nur.repos.Chiloute.vpn-tui;
          };
        })
      ];
    };
  };
}
```

Without the NUR overlay, use the NUR repository as a direct flake input:

```nix
inputs.nur-chiloute.url = "github:Chiloute/nur-packages";

# in a module
services.vpn-tui.package = nur-chiloute.packages.${pkgs.stdenv.hostPlatform.system}.vpn-tui;
```

> [!NOTE]
> The NUR only ships the package. The NixOS module still comes from this repository (`vpn-tui.nixosModules.default`). The NUR has no binary cache, so Nix builds the Go daemon and the Bun client locally. The NUR repository picks up new tags of this repository once a week, so a new release can take up to a week to appear there.

On a system without NixOS, `nix profile install github:Chiloute/nur-packages#vpn-tui` installs the client and the daemon. Nothing starts the daemon for you: run `vpn-tuid` as root yourself.

</details>

## Quick start

Import a TryHackMe profile, bring it up, read the state and your LHOST, then take it down:

```bash
vpn-tui import ~/Downloads/thm.ovpn --name thm
vpn-tui up thm
vpn-tui status
vpn-tui lhost
vpn-tui down
```

Expected output of `status` and `lhost` (the addresses are examples):

```text
● CONNECTED thm  LHOST 10.8.0.2  KILLSWITCH ON
10.8.0.2
```

`vpn-tui` with no argument opens the TUI. Its key bindings are in [docs/keys.md](docs/keys.md).

A new profile has an empty scope. Add the target networks (for example `10.10.0.0/16`) in the profile editor, or accept the routes the daemon learns, so that the kill switch protects them. Without a scope, the armed firewall only blocks IPv6 outside the tunnel (default settings). A dropped tunnel still locks everything.

## What it does

- Imports `.ovpn` and WireGuard `.conf` files. The daemon accepts a short list of directives and rejects the rest, so a configuration cannot run a script as root.
- Keeps credentials and keys in the Secret Service. The daemon holds them in memory only.
- Applies an nftables kill switch in the table `inet vpn_tui`: locked during connection and after a drop, scope-only when armed.
- Reconnects with an exponential backoff and stays locked when attempts run out.
- Writes your LHOST to `~/.cache/vpn-tui/lhost` for tmux, zsh or waybar.
- Keeps a 7-day event journal and sends desktop notifications with `vpn-tui notify`.

## Documentation

| Page | Content |
| --- | --- |
| [docs/cli.md](docs/cli.md) | Subcommands, exit codes, the `lhost` file, `notify`, `vpn-tuid` flags. |
| [docs/configuration.md](docs/configuration.md) | TOML profile, YAML configuration, NixOS module options, file locations. |
| [docs/architecture.md](docs/architecture.md) | Components, state machine, nft rules, startup reconciliation, journal. |
| [docs/security.md](docs/security.md) | Threat model, daemon surface, allowlists, secrets, known limits. |
| [docs/development.md](docs/development.md) | Dev shell, tests, scripts, builds. |
| [docs/keys.md](docs/keys.md) | Key bindings of the TUI (generated). |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Branches, commits, checks before a pull request. |

## Known limits

The kill switch works at the firewall, not at the routing table: routes pushed by an OpenVPN server or `net_gateway` routes are not filtered. After a daemon restart, the daemon does not reconnect by itself. The full list is in [docs/security.md](docs/security.md#known-limits).

## Licence

[MIT](LICENSE).

Required Notice: Copyright 2026 Chiloute (https://github.com/Chiloute/vpn-tui)
