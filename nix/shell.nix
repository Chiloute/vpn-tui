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
  ];

  shellHook = ''
    echo "vpn-tui — shell de développement"
    echo "  go test ./...        # tests du daemon"
    echo "  cd app && bun test   # tests du TUI/CLI"
  '';
}
