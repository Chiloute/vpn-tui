# Contributing

Thanks for helping. This page covers the workflow and the checks to run before you push. Setup and test details are in [docs/development.md](docs/development.md).

## Workflow

1. Fork the repository and clone your fork.
2. Create a branch from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `test/<topic>` or `build/<topic>`.
3. Make small, atomic commits. One pull request addresses one subject: do not mix a feature, a refactoring and a documentation rewrite.
4. Run the checks below.
5. Open a pull request against `main`. Describe what changes, why, and how you tested it. Mention any new limit or behaviour change in `docs/`.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`, in English, imperative mood, no final period.

- Types in use: `feat`, `fix`, `test`, `docs`, `build`, `chore`, `refactor`.
- Scopes in use: `app`, `tui`, `daemon`, `state`, `nft`, `ovpn`, `wg`, `dns`, `events`, `proto`, `nix`.

Examples from the history: `feat(nft): generate kill switch ruleset and apply it atomically via netlink`, `build(app): add OpenTUI and ilovetui, help table, keys doc and build script`.

## Checks before pushing

From the repository root, in `nix develop` (see [docs/development.md](docs/development.md#development-shell)):

```bash
gofmt -l .                                    # must print nothing
go vet ./...
go test ./...
unshare -Urn go test -count=1 -p 1 ./...      # netns tests, no root needed
(cd app && bun test)
(cd app && bun run typecheck)                 # tsc --noEmit
shellcheck scripts/*.sh
```

If you touch `nix/` or `flake.nix`, also run `nix flake check`. If you touch a script, run it (`nix develop -c scripts/it-wg.sh`, and the others listed in [docs/development.md](docs/development.md#integration-and-end-to-end-scripts)).

## Repository-specific points

- **`docs/keys.md` is generated.** Never edit it by hand. After changing `app/src/help/table.ts` or `app/config/default.yaml`, run `cd app && bun run gen:keys` and commit the result. A Bun test fails otherwise.
- **The RPC contract is shared.** `proto/rpc.schema.json` is embedded in the daemon and imported by the client. A change to it touches both sides, and both test suites must pass.
- **Do not weaken an allowlist to make one file pass.** The OpenVPN and WireGuard parsers are a security boundary (see [docs/security.md](docs/security.md)). A new accepted directive needs a reason in the pull request and a test, and a rejected directive needs a test too.
- **No real secrets or real VPN files in the repository.** Test data in `daemon/internal/*/testdata/` must use placeholders.
- **Netns tests share names.** They use the table `vpn_tui` and the interface `vpntui0` in their namespace, so run them with `-p 1`.
- **Nix hashes.** After a change to `go.mod`, `go.sum` or `app/bun.lock`, update `vendorHash` in `nix/daemon.nix` and `outputHash` in `nix/app.nix`.
- **Keep the documentation true to the code.** When you change a flag, an exit code, a default or a rule, update the matching page in `docs/` in the same pull request.

## Security reports

Do not open a public issue for a vulnerability. Report it privately. TODO: add the private contact (address or private advisory page), the same one as in [docs/security.md](docs/security.md#reporting-a-vulnerability).

## Licence

By contributing, you agree that your contribution is distributed under the project licence, [MIT](LICENSE).
