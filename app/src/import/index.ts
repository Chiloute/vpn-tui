export type ProfileType = "openvpn" | "wireguard";
export type Secrets =
  | { username: string; password: string }
  | { private_key: string; preshared_key?: string };

export function detectType(content: string, filename?: string): ProfileType {
  const ext = filename?.toLowerCase().match(/\.(ovpn|conf)$/)?.[1];
  if (ext === "ovpn") return "openvpn";
  if (/^\s*\[Interface\]\s*$/im.test(content)) return "wireguard";
  if (ext === "conf") {
    throw new Error(".conf file without an [Interface] section: unrecognized profile type");
  }
  if (/^\s*(remote|client|dev)\s/m.test(content)) return "openvpn";
  throw new Error("unrecognized profile type (expected .ovpn OpenVPN or .conf WireGuard)");
}

export const ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
export const ID_RULE = "a-z, 0-9 and - (32 characters max, must start with a letter or digit)";

export function slugify(name: string): string {
  const s = name
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, 32)
    .replace(/-+$/, "");
  if (!ID.test(s)) throw new Error(`profile name cannot be converted to an id: "${name}"`);
  return s;
}

export function extractSecrets(type: ProfileType, content: string): { content: string; secrets: Secrets | null } {
  return type === "openvpn" ? extractOpenvpn(content) : extractWireguard(content);
}

function extractOpenvpn(content: string) {
  if (/^[ \t]*auth-user-pass[ \t]+\S/m.test(content)) {
    throw new Error("`auth-user-pass <file>` is not supported: use an <auth-user-pass> block or the bare directive");
  }
  const open = content.search(/^[ \t]*<auth-user-pass>[ \t]*\r?$/m);
  if (open < 0) {
    if (/<\/?auth-user-pass>/.test(content)) throw new Error("malformed <auth-user-pass> block");
    return { content, secrets: null };
  }
  const close = /^[ \t]*<\/auth-user-pass>[ \t]*\r?(\n|$)/m.exec(content.slice(open));
  if (!close) throw new Error("unclosed <auth-user-pass> block");
  const inner = content.slice(open, open + close.index).replace(/^[^\n]*\n?/, "");
  const lines = inner.split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim() !== "");
  const [username, password] = lines;
  if (lines.length !== 2 || username === undefined || password === undefined) {
    throw new Error("malformed <auth-user-pass> block: 2 lines expected (username, password)");
  }
  const rest = content.slice(0, open) + content.slice(open + close.index + close[0].length);
  if (/<\/?auth-user-pass>/.test(rest)) throw new Error("multiple <auth-user-pass> blocks");
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
      if (priv !== undefined) throw new Error("multiple PrivateKey entries in [Interface]");
      if (!B64_KEY.test(value)) throw new Error("invalid PrivateKey (44-character base64 expected)");
      priv = value;
    } else if (name === "presharedkey" && section === "peer") {
      if (!B64_KEY.test(value)) throw new Error("invalid PresharedKey (44-character base64 expected)");
      if (psk !== undefined && psk !== value) throw new Error("multiple different PresharedKey entries: only one is supported");
      psk = value;
    } else return line;
    return `${m[1]}${m[2]}${m[3]}@keyring${m[5]}`;
  });
  if (priv === undefined) throw new Error("PrivateKey missing from the [Interface] section");
  const secrets: Secrets = psk === undefined ? { private_key: priv } : { private_key: priv, preshared_key: psk };
  return { content: out.join("\n"), secrets };
}
