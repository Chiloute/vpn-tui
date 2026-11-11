{
  lib,
  version,
  stdenvNoCC,
  bun,
  makeWrapper,
  libsecret,
  libnotify,
}: let
  root = lib.cleanSource ../.;
  src = lib.cleanSource ../app;
  # Bun dependencies: fixed-output derivation (network access allowed thanks to the output hash).
  # Both Linux architectures are installed: one hash for x86_64 and aarch64.
  nodeModules = stdenvNoCC.mkDerivation {
    pname = "vpn-tui-node-modules";
    version = "0";
    inherit src;
    nativeBuildInputs = [bun];
    dontConfigure = true;
    dontFixup = true;
    buildPhase = ''
      export HOME=$TMPDIR
      bun install --frozen-lockfile --no-progress --os=linux --cpu=x64 --cpu=arm64
    '';
    installPhase = "cp -r node_modules $out";
    outputHashMode = "recursive";
    outputHashAlgo = "sha256";
    outputHash = "sha256-gpl9ntGRIKTTIgz14p/aBJ2sQ3DZCugwzH7ypBToYjs=";
  };
in {
  inherit nodeModules;
  package = stdenvNoCC.mkDerivation {
    pname = "vpn-tui";
    inherit version;
    src = root;
    sourceRoot = "source/app"; # the code imports ../../../proto
    nativeBuildInputs = [bun makeWrapper];
    dontConfigure = true;
    # strip/patchelf break compiled bun binaries
    dontStrip = true;
    dontPatchELF = true;
    buildPhase = ''
      export HOME=$TMPDIR
      cp -r ${nodeModules} node_modules
      chmod -R u+w node_modules
      mkdir -p $out/libexec
      bun run scripts/build.ts $out/libexec/vpn-tui
    '';
    installPhase = ''
      mkdir -p $out/bin
      makeWrapper $out/libexec/vpn-tui $out/bin/vpn-tui \
        --prefix PATH : ${lib.makeBinPath [libsecret libnotify]}
    '';
    meta = {
      description = "vpn-tui TUI/CLI client";
      homepage = "https://github.com/Chiloute/vpn-tui";
      license = lib.licenses.mit;
      mainProgram = "vpn-tui";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  };
  tests = stdenvNoCC.mkDerivation {
    pname = "vpn-tui-bun-tests";
    version = "0";
    src = root;
    sourceRoot = "source/app";
    nativeBuildInputs = [bun libsecret libnotify];
    dontConfigure = true;
    buildPhase = ''
      export HOME=$TMPDIR
      cp -r ${nodeModules} node_modules
      chmod -R u+w node_modules
      bun test
    '';
    installPhase = "touch $out";
  };
}
