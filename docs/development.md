# Development

This page covers the development shell, the unit and integration tests, the helper scripts and the builds. Run every command from the repository root unless stated otherwise. No test needs root.

## Layout

| Path | Content |
| --- | --- |
| `daemon/cmd/vpn-tuid/` | Daemon entry point (`main.go`, `panicoff.go`). |
| `daemon/internal/` | Daemon packages (see [architecture.md](architecture.md#components)). |
| `proto/rpc.schema.json` | JSON-RPC contract, embedded in the daemon and imported by the client. |
| `app/src/` | `vpn-tui`: `cli`, `tui`, `store`, `import`, `keyring`, `lhost`, `notify`, `rpc`, `help`, `config`. |
| `app/config/default.yaml` | Default key bindings. |
| `scripts/` | Integration and end-to-end scripts. |
| `nix/`, `flake.nix` | Packages and development shell. |

## Development shell

```bash
nix develop
```

The shell provides `go`, `gopls`, `gotools`, `staticcheck` (`go-tools`), `bun`, `openvpn`, `wireguard-tools`, `nftables`, `iproute2`, `nmap`, `libsecret`, `socat` and `shellcheck`.

Install the TUI dependencies once:

```bash
cd app && bun install
```

## Unit tests

Go (daemon):

```bash
go test ./...
```

Bun (TUI and CLI):

```bash
cd app && bun test
```

Type check of the TUI and CLI:

```bash
cd app && bun run typecheck   # tsc --noEmit
```

`go test ./...` also runs the tests of `proto/` and the golden files of the nft ruleset (`daemon/internal/nft/testdata/*.nft`). A Bun test compares `docs/keys.md` with the generated output and fails when the file is out of date (see [Regenerating `docs/keys.md`](#regenerating-docskeysmd)).

## Rootless network namespace tests

Some Go tests need `CAP_NET_ADMIN` to create nftables tables, interfaces and routes. Without it, they are skipped. They run without root in a new user and network namespace:

```bash
unshare -Urn go test -count=1 -p 1 ./...
```

For one package:

```bash
unshare -Urn go test -count=1 ./daemon/internal/nft/
unshare -Urn go test -count=1 ./daemon/internal/driver/
```

- `unshare -Urn` creates a user namespace where you are root (`-r`) and a new network namespace (`-n`), so the tests never touch the host firewall.
- `-count=1` disables the test cache, which would hide the effect of the namespace.
- `-p 1` runs one package at a time. The tests of different packages use the same names in the namespace (the table `vpn_tui`, the interface `vpntui0`) and would collide in parallel.
- The tests are also skipped when the `nft` binary is not in `PATH` (provided by `nix develop`).

## Integration and end-to-end scripts

The `it-*.sh` scripts build the daemon with `CGO_ENABLED=0`, then run themselves again inside `unshare -Urn`. They use a second network namespace as the VPN server, and a fake `secret-tool` (`scripts/it-lib.sh`) so the keyring is not involved. Run them in the development shell:

| Script | What it checks |
| --- | --- |
| `scripts/it-wg.sh` | WireGuard: import of two profiles with secrets in the keyring, `up`, switch from one profile to the other, `down`, `up` without secrets refused (exit 1), no secret in the state, run and cache directories or the daemon log. |
| `scripts/it-ovpn.sh` | OpenVPN with a generated PKI and a real `openvpn` server. |
| `scripts/it-killswitch.sh` | The kill switch: traffic to the scope and IPv6 are blocked when armed and when locked, with a simulated leak. |
| `scripts/e2e-phase1.sh` | Real daemon and real CLI, `status` exit codes: 1 when disarmed with access allowed (case 1, in a user namespace, `--group root`), 3 when the user is not in the daemon group (case 2), 3 when the socket does not exist (case 3). |
| `scripts/e2e-phase2.sh` | Import of a TryHackMe profile with secrets, rejection of a malicious configuration, no secret written on the daemon side. |

```bash
nix develop -c scripts/it-wg.sh
nix develop -c scripts/it-ovpn.sh
nix develop -c scripts/it-killswitch.sh
nix develop -c scripts/e2e-phase1.sh
nix develop -c scripts/e2e-phase2.sh
```

Each script prints `OK ...` lines and exits with 0, or prints `FAIL: ...` with the daemon log and exits with 1.

`scripts/it-ovpn.sh` exits with **77** (skip, printed as `SKIP : /dev/net/tun absent`) when `/dev/net/tun` does not exist. That is the case in some containers and sandboxes. Treat 77 as "not run", not as a pass. The other scripts do not need `/dev/net/tun`.

Run `shellcheck scripts/*.sh` after editing a script.

## Regenerating `docs/keys.md`

`docs/keys.md` is generated from the help table `app/src/help/table.ts`. Do not edit it by hand.

```bash
cd app && bun run gen:keys
```

The command rewrites `docs/keys.md`. Commit the result with the change to the table.

## Regenerating the demo

The README animation `.github/assets/demo.gif` is recorded with [VHS](https://github.com/charmbracelet/vhs) from `.github/assets/demo.tape`. It drives the real `vpn-tui` on your machine: the daemon must be running and the first profile in the list must connect. Profile names and addresses appear in the recording.

```bash
nix run --inputs-from . nixpkgs#vhs -- .github/assets/demo.tape
```

## Building

Daemon:

```bash
CGO_ENABLED=0 go build -o vpn-tuid ./daemon/cmd/vpn-tuid
CGO_ENABLED=0 go build -ldflags "-X main.version=0.0.0" -o vpn-tuid ./daemon/cmd/vpn-tuid   # with a version
```

TUI and CLI (single binary, `bun-linux-x64` or `bun-linux-arm64` according to the machine):

```bash
cd app && bun run scripts/build.ts dist/vpn-tui
```

Without an argument, the output is `app/dist/vpn-tui`. `app/dist/` is ignored by git.

With Nix:

```bash
nix build .#vpn-tuid
nix build .#vpn-tui
nix build            # both, in one output
```

The flake supports `x86_64-linux` and `aarch64-linux`.

The Go vendor hash (`nix/daemon.nix`, `vendorHash`) and the hash of the Bun dependencies (`nix/app.nix`, `outputHash`) are fixed values. Update them after any change to `go.mod`, `go.sum` or `app/bun.lock`: build once with a wrong hash and copy the hash Nix reports.

## `nix flake check`

```bash
nix flake check
```

The checks declared in `flake.nix` are `go-tests` (the daemon package built with `doCheck = true`, so `go test ./...`, where the netns tests skip themselves for lack of `CAP_NET_ADMIN` in the build sandbox) and `bun-tests` (`bun test`). `flake.nix` carries a TODO for a `killswitch` check, which does not exist yet: no check evaluates `nix/module.nix`.
