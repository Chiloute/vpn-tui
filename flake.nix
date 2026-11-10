{
  description = "vpn-tui: VPN manager with a TUI/CLI (Go daemon, Bun front end)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    supportedSystems = ["x86_64-linux" "aarch64-linux"];

    forAllSystems = f:
      nixpkgs.lib.genAttrs supportedSystems
      (system: f system (import nixpkgs {
        inherit system;
        # PolyForm NC license is unfree for nixpkgs
        config.allowUnfreePredicate = p: builtins.elem (nixpkgs.lib.getName p) ["vpn-tuid" "vpn-tui"];
      }));
    mk = pkgs: let
      app = pkgs.callPackage ./nix/app.nix {};
    in rec {
      vpn-tuid = pkgs.callPackage ./nix/daemon.nix {};
      vpn-tui = app.package;
      default = pkgs.symlinkJoin {
        name = "vpn-tui-all";
        paths = [vpn-tuid vpn-tui];
        meta.mainProgram = "vpn-tui";
      };
      bun-tests = app.tests;
    };
  in {
    packages = forAllSystems (system: pkgs: {inherit (mk pkgs) vpn-tuid vpn-tui default;});

    nixosModules.default = import ./nix/module.nix self;

    checks = forAllSystems (system: pkgs: {
      killswitch = import ./nix/tests/killswitch.nix {inherit pkgs self;};
      killswitch-nft = import ./nix/tests/killswitch.nix {inherit pkgs self; nft = true;};
      go-tests = (mk pkgs).vpn-tuid.overrideAttrs {doCheck = true;};
      bun-tests = (mk pkgs).bun-tests;
    });

    devShells = forAllSystems (system: pkgs: {
      default = import ./nix/shell.nix {inherit pkgs;};
    });
  };
}
