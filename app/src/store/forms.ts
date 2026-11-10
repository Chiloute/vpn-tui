import type { Secrets } from "../import";

export type OpenvpnForm = {
  name: string; id?: string; remote: string; port: number; proto: "udp" | "tcp";
  ca: string; cert: string; key: string; tlsCrypt?: string; tlsAuth?: string;
  username?: string; password?: string;
};
export type WireguardForm = {
  name: string; id?: string; address: string; dns?: string | string[]; privateKey: string;
  peer: { publicKey: string; endpoint: string; allowedIPs: string | string[]; presharedKey?: string; keepalive?: number };
};
export type ProfileForm = OpenvpnForm | WireguardForm;

const line = (label: string, v: string) => {
  if (/[\r\n]/.test(v) || v.trim() === "") throw new Error(`invalid ${label}`);
  return v.trim();
};
const list = (v: string | string[]) => (Array.isArray(v) ? v : [v]).map((x) => line("list", x)).join(", ");
const block = (tag: string, v: string) => `<${tag}>\n${v.trim()}\n</${tag}>\n`;

/** Produces the .ovpn / .conf content (secrets included, to be passed through extractSecrets afterwards). */
export function buildContent(f: ProfileForm): { type: "openvpn" | "wireguard"; filename: string; content: string } {
  if ("remote" in f) {
    if (!Number.isInteger(f.port) || f.port < 1 || f.port > 65535) throw new Error("invalid port");
    if (f.proto !== "udp" && f.proto !== "tcp") throw new Error("invalid protocol");
    if (/\s/.test(f.remote) || !f.remote) throw new Error("invalid server");
    if ((f.username === undefined) !== (f.password === undefined)) throw new Error("username and password go together");
    let c = `client\ndev tun\nproto ${f.proto}\nremote ${f.remote} ${f.port}\nnobind\npersist-tun\nremote-cert-tls server\n`;
    c += block("ca", f.ca) + block("cert", f.cert) + block("key", f.key);
    if (f.tlsCrypt) c += block("tls-crypt", f.tlsCrypt);
    if (f.tlsAuth) c += "key-direction 1\n" + block("tls-auth", f.tlsAuth);
    if (f.username !== undefined) c += block("auth-user-pass", `${line("username", f.username)}\n${line("password", f.password!)}`);
    return { type: "openvpn", filename: "form.ovpn", content: c };
  }
  let c = `[Interface]\nPrivateKey = ${line("PrivateKey", f.privateKey)}\nAddress = ${line("Address", f.address)}\n`;
  if (f.dns?.length) c += `DNS = ${list(f.dns)}\n`;
  c += `\n[Peer]\nPublicKey = ${line("PublicKey", f.peer.publicKey)}\n`;
  if (f.peer.presharedKey) c += `PresharedKey = ${line("PresharedKey", f.peer.presharedKey)}\n`;
  c += `Endpoint = ${line("Endpoint", f.peer.endpoint)}\nAllowedIPs = ${list(f.peer.allowedIPs)}\n`;
  if (f.peer.keepalive !== undefined) {
    if (!Number.isInteger(f.peer.keepalive) || f.peer.keepalive < 0) throw new Error("invalid keepalive");
    c += `PersistentKeepalive = ${f.peer.keepalive}\n`;
  }
  return { type: "wireguard", filename: "form.conf", content: c };
}

/** Sensitive values of a form, to mask them in error messages. */
export function formSecrets(f: ProfileForm): string[] {
  const v = "remote" in f ? [f.key, f.password, f.tlsCrypt, f.tlsAuth] : [f.privateKey, f.peer.presharedKey];
  return v.filter((x): x is string => !!x);
}
export type { Secrets };
