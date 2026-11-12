{
  description = "vpn-tui: VPN manager with a TUI/CLI (Go daemon, Bun front end)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    supportedSystems = ["x86_64-linux" "aarch64-linux"];
    # single source: app/package.json (also read by the client for --version)
    version = (builtins.fromJSON (builtins.readFile ./app/package.json)).version;

    forAllSystems = f:
      nixpkgs.lib.genAttrs supportedSystems
      (system: f system (import nixpkgs {
        inherit system;
      }));
    mk = pkgs: let
      app = pkgs.callPackage ./nix/app.nix {inherit version;};
    in rec {
      vpn-tuid = pkgs.callPackage ./nix/daemon.nix {inherit version;};
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

    # nix/module.nix has no default package (also imported as-is by NUR); the flake supplies one.
    nixosModules.default = {
      lib,
      pkgs,
      ...
    }: {
      imports = [./nix/module.nix];
      services.vpn-tui.package = lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.default;
    };

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
