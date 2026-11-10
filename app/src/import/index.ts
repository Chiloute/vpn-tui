export type ProfileType = "openvpn" | "wireguard";
export type Secrets =
  | { username: string; password: string }
  | { private_key: string; preshared_key?: string };

export function detectType(content: string, filename?: string): ProfileType {
  const ext = filename?.toLowerCase().match(/\.(ovpn|conf)$/)?.[1];
  if (ext === "ovpn") return "openvpn";
  if (/^\s*\[Interface\]\s*$/im.test(content)) return "wireguard";
  if (ext === "conf") {
    throw new Error("fichier .conf sans section [Interface] : type de profil non reconnu");
  }
  if (/^\s*(remote|client|dev)\s/m.test(content)) return "openvpn";
  throw new Error("type de profil non reconnu (attendu : .ovpn OpenVPN ou .conf WireGuard)");
}

export function slugify(name: string): string {
  const s = name
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, 32)
    .replace(/-+$/, "");
  if (!/^[a-z0-9][a-z0-9-]{0,31}$/.test(s)) throw new Error(`nom de profil impossible à convertir en identifiant : "${name}"`);
  return s;
}

export function extractSecrets(type: ProfileType, content: string): { content: string; secrets: Secrets | null } {
  return type === "openvpn" ? extractOpenvpn(content) : extractWireguard(content);
}

function extractOpenvpn(content: string) {
  if (/^[ \t]*auth-user-pass[ \t]+\S/m.test(content)) {
    throw new Error("`auth-user-pass <fichier>` non supporté : utilisez un bloc <auth-user-pass> ou la directive seule");
  }
  const open = content.search(/^[ \t]*<auth-user-pass>[ \t]*\r?$/m);
  if (open < 0) {
    if (/<\/?auth-user-pass>/.test(content)) throw new Error("bloc <auth-user-pass> mal formé");
    return { content, secrets: null };
  }
  const close = /^[ \t]*<\/auth-user-pass>[ \t]*\r?(\n|$)/m.exec(content.slice(open));
  if (!close) throw new Error("bloc <auth-user-pass> non fermé");
  const inner = content.slice(open, open + close.index).replace(/^[^\n]*\n?/, "");
  const lines = inner.split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim() !== "");
  const [username, password] = lines;
  if (lines.length !== 2 || username === undefined || password === undefined) {
    throw new Error("bloc <auth-user-pass> mal formé : 2 lignes attendues (identifiant, mot de passe)");
  }
  const rest = content.slice(0, open) + content.slice(open + close.index + close[0].length);
  if (/<\/?auth-user-pass>/.test(rest)) throw new Error("plusieurs blocs <auth-user-pass>");
  // An inline block alone enables auth; keep that meaning once the block is gone.
  const out = /^[ \t]*auth-user-pass[ \t]*\r?$/m.test(rest) ? rest : rest.replace(/\n?$/, "\nauth-user-pass\n");
  return { content: out, secrets: { username, password } };
}

const B64_KEY = /^[A-Za-z0-9+/]{43}=$/;

function extractWireguard(content: string) {
  let section = "";
  let priv: string | undefined;
  let psk: string | undefined;
  const out = content.split("\n").map((line) => {
    const sec = /^\s*\[(\w+)\]/.exec(line);
    if (sec) section = sec[1]!.toLowerCase();
    const m = /^(\s*)(PrivateKey|PresharedKey)(\s*=\s*)(.*?)(\s*)$/i.exec(line);
    if (!m) return line;
    const name = m[2]!.toLowerCase();
    const value = m[4]!;
    if (name === "privatekey" && section === "interface") {
      if (priv !== undefined) throw new Error("plusieurs PrivateKey dans [Interface]");
      if (!B64_KEY.test(value)) throw new Error("PrivateKey invalide (base64 de 44 caractères attendu)");
      priv = value;
    } else if (name === "presharedkey" && section === "peer") {
      if (!B64_KEY.test(value)) throw new Error("PresharedKey invalide (base64 de 44 caractères attendu)");
      if (psk !== undefined && psk !== value) throw new Error("plusieurs PresharedKey différentes : une seule est supportée");
      psk = value;
    } else return line;
    return `${m[1]}${m[2]}${m[3]}@keyring${m[5]}`;
  });
  if (priv === undefined) throw new Error("PrivateKey absente de la section [Interface]");
  const secrets: Secrets = psk === undefined ? { private_key: priv } : { private_key: priv, preshared_key: psk };
  return { content: out.join("\n"), secrets };
}
