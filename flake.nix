{
  description = "vpn-tui — gestionnaire VPN en TUI/CLI (daemon Go, interface Bun)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    supportedSystems = ["x86_64-linux" "aarch64-linux"];

    forAllSystems = f:
      nixpkgs.lib.genAttrs supportedSystems
      (system: f system (import nixpkgs {inherit system;}));
  in {
    devShells = forAllSystems (system: pkgs: {
      default = import ./nix/shell.nix {inherit pkgs;};
    });
  };
}
