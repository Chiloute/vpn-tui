{
  lib,
  buildGoModule,
}:
buildGoModule rec {
  pname = "vpn-tuid";
  version = "0.0.0";
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
    # polyform-nc absent de nixpkgs
    license = {
      fullName = "PolyForm Noncommercial License 1.0.0";
      url = "https://polyformproject.org/licenses/noncommercial/1.0.0";
      free = false;
      redistributable = true;
    };
    mainProgram = "vpn-tuid";
    platforms = lib.platforms.linux;
  };
}
