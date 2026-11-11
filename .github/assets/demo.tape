# Recorded with VHS against a running daemon and at least one imported profile.
# Regenerate: nix run --inputs-from . nixpkgs#vhs -- .github/assets/demo.tape, then pixelate the LHOST (see docs/development.md).
Output ./.github/assets/demo.gif
Require vpn-tui

Set FontSize 20
Set Width 1400
Set Height 700
Set Padding 20

Type "vpn-tui"
Sleep 800ms
Enter
Sleep 2s

# bring the selected profile up, wait for the banner
Enter
Wait+Screen /CONNECTED/
Sleep 3s

# profile detail: routes, DNS, learned scope
Type "d"
Sleep 3s
Escape
Sleep 1s

# event log
Type "L"
Sleep 3s
Escape
Sleep 1s

# bring it down
Enter
Wait+Screen /DISCONNECTED/
Sleep 2s

Type "q"
Sleep 500ms
