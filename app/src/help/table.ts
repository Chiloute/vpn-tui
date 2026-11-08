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

const KEY_NAMES: Record<string, string> = { up: "↑", down: "↓", left: "←", right: "→", pageup: "PgUp", pagedown: "PgDn", escape: "Esc", return: "Entrée" };
/** "up,down,j,k" -> "↑ ↓ j k" pour l'affichage. */
export const prettyKey = (key: string): string =>
  key.split(",").map((k) => KEY_NAMES[k.trim()] ?? k.trim().replace(/^shift\+(\w)$/, (_, c: string) => c.toUpperCase())).join(" ");

const nav = (view: string): Cmd => ({ name: `${view}.nav`, desc: "naviguer", defaultKey: "up,down,j,k", shortHelp: true });

export const views = {
  profiles: {
    id: "profiles",
    title: "Profils",
    role: "Liste des profils VPN importés avec leur état. Point d'entrée du TUI.",
    actions: ["Naviguer, monter ou couper le tunnel.", "Importer, créer, éditer ou supprimer un profil."],
    warnings: ["Supprimer un profil demande une confirmation.", "Monter un profil arme le kill switch."],
    commands: [
      nav("profiles"),
      { name: "profiles.toggle", desc: "up/down", defaultKey: "return", shortHelp: true },
      { name: "profiles.detail", desc: "détail", defaultKey: "d", shortHelp: true },
      { name: "profiles.scope", desc: "accepter le scope appris", defaultKey: "s" },
      { name: "profiles.import", desc: "importer", defaultKey: "i", shortHelp: true },
      { name: "profiles.new", desc: "nouveau", defaultKey: "n" },
      { name: "profiles.edit", desc: "éditer", defaultKey: "e" },
      { name: "profiles.delete", desc: "supprimer", defaultKey: "x" },
    ],
  },
  detail: {
    id: "detail",
    title: "Détail",
    role: "Détail d'un profil : routes, DNS, scope appris et état de la connexion.",
    actions: ["Accepter le scope appris pour l'ajouter aux routes autorisées.", "Éditer le profil."],
    warnings: ["Accepter un scope élargit ce que le tunnel peut atteindre : vérifier avant de valider."],
    commands: [
      { name: "detail.scope", desc: "accepter le scope", defaultKey: "s", shortHelp: true },
      { name: "detail.edit", desc: "éditer", defaultKey: "e" },
      { name: "detail.back", desc: "retour", defaultKey: "escape", shortHelp: true },
    ],
  },
  logs: {
    id: "logs",
    title: "Logs",
    role: "Journal des événements du daemon : connexions, reconnexions, kill switch.",
    actions: ["Parcourir les événements récents."],
    warnings: [],
    commands: [
      nav("logs"),
      { name: "logs.page", desc: "page", defaultKey: "pageup,pagedown" },
      { name: "logs.back", desc: "retour", defaultKey: "escape", shortHelp: true },
    ],
  },
  import: {
    id: "import",
    title: "Import",
    role: "Import d'un fichier de profil (.ovpn ou WireGuard) en trois temps : chemin, aperçu, confirmation. Les secrets vont dans le trousseau, pas sur disque.",
    actions: [
      "Saisir le chemin (~ accepté, Tab complète le nom), puis Entrée pour lire le fichier et afficher l'aperçu.",
      "Ajuster le nom et l'identifiant, puis Entrée sur « Importer ».",
    ],
    warnings: [
      "Un fichier refusé affiche le message exact du parseur ou du daemon, ligne par ligne, et rien n'est importé.",
      "Les secrets ne sont jamais affichés.",
    ],
    commands: [
      { name: "import.confirm", desc: "lire / importer", defaultKey: "return", shortHelp: true },
      { name: "import.next", desc: "compléter / suivant", defaultKey: "tab", shortHelp: true },
      { name: "import.prev", desc: "champ précédent", defaultKey: "shift+tab" },
      { name: "import.cancel", desc: "annuler", defaultKey: "escape", shortHelp: true },
    ],
  },
  edit: {
    id: "edit",
    title: "Édition / création",
    role: "Formulaire de création d'un profil OpenVPN ou WireGuard (n), ou d'édition du profil sélectionné (e) : nom, tags, couleur, scope, kill switch, DNS. Le type et la configuration ne sont pas modifiables : réimporter le fichier.",
    actions: [
      "Passer d'un champ à l'autre, Entrée sur le bouton pour enregistrer.",
      "Les secrets (clé privée, mot de passe, blocs PEM sensibles) sont masqués et passent par le trousseau.",
    ],
    warnings: [
      "Annuler un formulaire modifié demande une confirmation.",
      "Désactiver le kill switch laisse le scope non protégé.",
      "Les lettres tapées dans un champ de saisie ne déclenchent aucun raccourci.",
    ],
    commands: [
      { name: "edit.next", desc: "champ suivant", defaultKey: "tab", shortHelp: true },
      { name: "edit.prev", desc: "champ précédent", defaultKey: "shift+tab" },
      { name: "edit.submit", desc: "valider le champ / bouton", defaultKey: "return" },
      { name: "edit.save", desc: "enregistrer", defaultKey: "ctrl+s", shortHelp: true },
      { name: "edit.cancel", desc: "annuler", defaultKey: "escape", shortHelp: true },
    ],
  },
  help: {
    id: "help",
    title: "Aide",
    role: "Rappel des touches de la vue courante et du fonctionnement du kill switch.",
    actions: ["Lire, puis fermer."],
    warnings: [],
    commands: [
      { name: "help.scroll", desc: "défiler", defaultKey: "up,down,j,k", shortHelp: true },
      { name: "help.page", desc: "page", defaultKey: "pageup,pagedown" },
      { name: "help.close", desc: "fermer", defaultKey: "escape", shortHelp: true },
    ],
  },
  confirm: {
    id: "confirm",
    title: "Confirmation",
    role: "Fenêtre de confirmation avant une action destructrice (suppression, scope). Le panic-off exige de taper « oui ».",
    actions: ["Répondre oui ou non."],
    warnings: ["« y » reste réservé à la copie du LHOST : la confirmation utilise « o »."],
    commands: [
      { name: "confirm.yes", desc: "oui", defaultKey: "o", shortHelp: true },
      { name: "confirm.no", desc: "non", defaultKey: "n,escape", shortHelp: true },
    ],
  },
} as const satisfies Record<string, View>;

export type ViewId = keyof typeof views;

export const globalCommands: Cmd[] = [
  { name: "global.help", desc: "aide", defaultKey: "?", shortHelp: true },
  { name: "global.quit", desc: "quitter", defaultKey: "q", shortHelp: true },
  { name: "global.panic", desc: "panic-off", defaultKey: "!" },
  { name: "global.logs", desc: "logs", defaultKey: "shift+l" },
  { name: "global.copyLhost", desc: "copier LHOST", defaultKey: "y" },
];

export const killswitch = {
  title: "Kill switch",
  intro: "Le daemon pose une table nftables `inet vpn_tui` qui coupe tout trafic hors tunnel.",
  states: [
    {
      id: "disarmed",
      label: "DÉSARMÉ",
      desc: "Aucun tunnel, aucune règle. Rien n'est bloqué.",
    },
    {
      id: "armed",
      label: "ARMÉ",
      desc: "Tunnel établi. Tout trafic hors du tunnel est bloqué ; seuls le tunnel et le lien local passent.",
    },
    {
      id: "locked",
      label: "VERROUILLÉ",
      desc: "Tunnel perdu ou reconnexions épuisées. Tout le trafic reste bloqué, y compris hors tunnel, jusqu'à une action manuelle (up ou panic-off).",
    },
    {
      id: "reconnecting",
      label: "RECONNEXION",
      desc: "Tunnel perdu, nouvelle tentative en cours. Le trafic hors tunnel reste bloqué pendant les tentatives.",
    },
  ],
  panicOff:
    "panic-off supprime les règles du kill switch et rend l'accès réseau normal, avec confirmation obligatoire. " +
    "Sans daemon, exécuter en root `vpn-tuid --panic-off` ou `nft delete table inet vpn_tui`.",
} as const;
