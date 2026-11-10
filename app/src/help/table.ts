// Source unique de l'aide : raccourcis, prose des vues, section Kill switch.
// Consommée par le TUI (useBindings, modale d'aide), config/default.yaml (noms) et docs/keys.md.

export type Cmd = { name: string; desc: string; defaultKey: string; shortHelp?: boolean };

export type View = {
  id: string;
  title: string;
  role: string;
  actions: string[];
  warnings: string[];
  commands: Cmd[];
};

const KEY_NAMES: Record<string, string> = { up: "↑", down: "↓", left: "←", right: "→", pageup: "PgUp", pagedown: "PgDn", escape: "Esc", return: "Enter" };
/** "up,down,j,k" -> "↑ ↓ j k" pour l'affichage. */
export const prettyKey = (key: string): string =>
  key.split(",").map((k) => KEY_NAMES[k.trim()] ?? k.trim().replace(/^shift\+(\w)$/, (_, c: string) => c.toUpperCase())).join(" ");

const nav = (view: string): Cmd => ({ name: `${view}.nav`, desc: "navigate", defaultKey: "up,down,j,k", shortHelp: true });

export const views = {
  profiles: {
    id: "profiles",
    title: "Profiles",
    role: "Imported VPN profiles with their state. Entry point of the TUI.",
    actions: ["Navigate, bring the tunnel up or down.", "Import, create, edit or delete a profile."],
    warnings: ["Deleting a profile asks for confirmation.", "Bringing a profile up arms the kill switch."],
    commands: [
      nav("profiles"),
      { name: "profiles.toggle", desc: "up/down", defaultKey: "return", shortHelp: true },
      { name: "profiles.detail", desc: "detail", defaultKey: "d", shortHelp: true },
      { name: "profiles.scope", desc: "accept learned scope", defaultKey: "s" },
      { name: "profiles.import", desc: "import", defaultKey: "i", shortHelp: true },
      { name: "profiles.new", desc: "new", defaultKey: "n" },
      { name: "profiles.edit", desc: "edit", defaultKey: "e" },
      { name: "profiles.delete", desc: "delete", defaultKey: "x" },
    ],
  },
  detail: {
    id: "detail",
    title: "Detail",
    role: "Profile detail: routes, DNS, learned scope and connection state.",
    actions: ["Accept the learned scope to add it to the allowed routes.", "Edit the profile."],
    warnings: ["Accepting a scope widens what the tunnel can reach: check before confirming."],
    commands: [
      { name: "detail.scope", desc: "accept scope", defaultKey: "s", shortHelp: true },
      { name: "detail.edit", desc: "edit", defaultKey: "e" },
      { name: "detail.back", desc: "back", defaultKey: "escape", shortHelp: true },
    ],
  },
  logs: {
    id: "logs",
    title: "Logs",
    role: "Daemon event log: connections, reconnections, kill switch.",
    actions: ["Browse recent events."],
    warnings: [],
    commands: [
      nav("logs"),
      { name: "logs.page", desc: "page", defaultKey: "pageup,pagedown" },
      { name: "logs.back", desc: "back", defaultKey: "escape", shortHelp: true },
    ],
  },
  import: {
    id: "import",
    title: "Import",
    role: "Import a profile file (.ovpn or WireGuard) in three steps: path, preview, confirmation. Secrets go to the keyring, not to disk.",
    actions: [
      "Type the path (~ accepted, Tab completes the name), then Enter to read the file and show the preview.",
      "Adjust the name and the id, then Enter on \"Import\".",
    ],
    warnings: [
      "A rejected file shows the exact parser or daemon message, line by line, and nothing is imported.",
      "Secrets are never displayed.",
    ],
    commands: [
      { name: "import.confirm", desc: "read / import", defaultKey: "return", shortHelp: true },
      { name: "import.next", desc: "complete / next", defaultKey: "tab", shortHelp: true },
      { name: "import.prev", desc: "previous field", defaultKey: "shift+tab" },
      { name: "import.cancel", desc: "cancel", defaultKey: "escape", shortHelp: true },
    ],
  },
  edit: {
    id: "edit",
    title: "Edit",
    role: "Form to create an OpenVPN or WireGuard profile (n), or to edit the selected profile (e): name, tags, color, scope, kill switch, DNS. The type and configuration cannot be changed: re-import the file.",
    actions: [
      "Move between fields, Enter on the button to save.",
      "Secrets (private key, password, sensitive PEM blocks) are masked and go through the keyring.",
    ],
    warnings: [
      "Cancelling a modified form asks for confirmation.",
      "Disabling the kill switch leaves the scope unprotected.",
      "Letters typed in an input field never trigger a shortcut.",
    ],
    commands: [
      { name: "edit.next", desc: "next field", defaultKey: "tab", shortHelp: true },
      { name: "edit.prev", desc: "previous field", defaultKey: "shift+tab" },
      { name: "edit.submit", desc: "validate field / button", defaultKey: "return" },
      { name: "edit.save", desc: "save", defaultKey: "ctrl+s", shortHelp: true },
      { name: "edit.cancel", desc: "cancel", defaultKey: "escape", shortHelp: true },
    ],
  },
  help: {
    id: "help",
    title: "Help",
    role: "Keys of the current view and how the kill switch works.",
    actions: ["Read, then close."],
    warnings: [],
    commands: [
      { name: "help.scroll", desc: "scroll", defaultKey: "up,down,j,k", shortHelp: true },
      { name: "help.page", desc: "page", defaultKey: "pageup,pagedown" },
      { name: "help.close", desc: "close", defaultKey: "escape", shortHelp: true },
    ],
  },
  confirm: {
    id: "confirm",
    title: "Confirmation",
    role: "Confirmation dialog before a destructive action (delete, scope). Panic-off requires typing \"yes\".",
    actions: ["Answer yes or no."],
    warnings: ["Press y to confirm, n or Esc to cancel."],
    commands: [
      { name: "confirm.yes", desc: "yes", defaultKey: "y", shortHelp: true },
      { name: "confirm.no", desc: "no", defaultKey: "n,escape", shortHelp: true },
    ],
  },
} as const satisfies Record<string, View>;

export type ViewId = keyof typeof views;

export const globalCommands: Cmd[] = [
  { name: "global.help", desc: "help", defaultKey: "?", shortHelp: true },
  { name: "global.quit", desc: "quit", defaultKey: "q", shortHelp: true },
  { name: "global.panic", desc: "panic-off", defaultKey: "!" },
  { name: "global.logs", desc: "logs", defaultKey: "shift+l" },
  { name: "global.copyLhost", desc: "copy LHOST", defaultKey: "c" },
];

export const killswitch = {
  title: "Kill switch",
  intro: "The daemon installs an nftables table `inet vpn_tui` that blocks all traffic outside the tunnel.",
  states: [
    {
      id: "disarmed",
      label: "DISARMED",
      desc: "No tunnel, no rule. Nothing is blocked.",
    },
    {
      id: "armed",
      label: "ARMED",
      desc: "Tunnel up. All traffic outside the tunnel is blocked; only the tunnel and the local link pass.",
    },
    {
      id: "locked",
      label: "LOCKED",
      desc: "Tunnel lost or reconnection attempts exhausted. All traffic stays blocked, including outside the tunnel, until a manual action (up or panic-off).",
    },
    {
      id: "reconnecting",
      label: "RECONNECTING",
      desc: "Tunnel lost, retrying. Traffic outside the tunnel stays blocked during attempts.",
    },
  ],
  panicOff:
    "panic-off removes the kill switch rules and restores normal network access; confirmation is required. " +
    "Without the daemon, run as root `vpn-tuid --panic-off` or `nft delete table inet vpn_tui`.",
} as const;
