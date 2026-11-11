{
  lib,
  version,
  buildGoModule,
}:
buildGoModule rec {
  pname = "vpn-tuid";
  inherit version;
  src = lib.cleanSource ../.;
  vendorHash = "sha256-3O+215G9KuNSYjFVDpDMyXrXNX3tYxFb+2zRnSz9IUw=";
  subPackages = ["daemon/cmd/vpn-tuid"];
  env.CGO_ENABLED = 0;
  env.GOTOOLCHAIN = "local";
  ldflags = ["-s" "-w" "-X main.version=${version}"];
  # checkPhase runs `go test ./...`; netns tests are skipped without CAP_NET_ADMIN.

  meta = {
    description = "vpn-tui daemon (OpenVPN/WireGuard, kill switch)";
    homepage = "https://github.com/Chiloute/vpn-tui";
    license = lib.licenses.mit;
    mainProgram = "vpn-tuid";
    platforms = lib.platforms.linux;
  };
}
