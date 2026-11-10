{pkgs}:
pkgs.mkShell {
  packages = with pkgs; [
    go
    gopls
    gotools
    go-tools # staticcheck
    bun
    openvpn
    wireguard-tools
    nftables
    iproute2
    nmap
    libsecret
    socat
    shellcheck
  ];

  shellHook = ''
    echo "vpn-tui — development shell"
    echo "  go test ./...        # daemon tests"
    echo "  cd app && bun test   # TUI/CLI tests"
  '';
}
