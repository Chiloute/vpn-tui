import { isIP } from "node:net";
import type { OpenvpnForm, ProfileForm, WireguardForm } from "../store";

export type Errors = Record<string, string>;

export const isCidr = (s: string): boolean => {
  const [ip, len, ...rest] = s.split("/");
  const v = isIP(ip ?? "");
  return v > 0 && rest.length === 0 && /^\d{1,3}$/.test(len ?? "") && Number(len) <= (v === 4 ? 32 : 128);
};
const KEY = /^[A-Za-z0-9+/]{43}=$/;
const ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
const TAG = /^[a-z0-9-]{1,16}$/;
const ENDPOINT = /^(\[[0-9a-fA-F:]+\]|[^\s:[\]]+):(\d{1,5})$/;

export const commaList = (s: string): string[] => s.split(/[,\s]+/).filter(Boolean);
export const lines = (s: string): string[] => s.split("\n").map((l) => l.trim()).filter(Boolean);

const port = (s: string) => /^\d{1,5}$/.test(s) && Number(s) >= 1 && Number(s) <= 65535;

/** Vérifie que chaque élément satisfait `ok` ; renvoie l'erreur listant les invalides. */
function badItems(items: string[], ok: (s: string) => boolean, what: string): string | undefined {
  const bad = items.filter((i) => !ok(i));
  return bad.length ? `${what} invalide : ${bad.join(", ")}` : undefined;
}

/** Valide le formulaire de création (valeurs en chaînes) ; `form` n'est défini que sans erreur. */
export function buildForm(v: Record<string, string>): { errors: Errors; form?: ProfileForm } {
  const e: Errors = {};
  const get = (k: string) => (v[k] ?? "").trim();
  const need = (k: string, msg = "requis") => { if (!get(k)) e[k] = msg; };
  need("name");
  if (get("name").length > 64) e.name = "64 caractères maximum";
  if (get("id") && !ID.test(get("id"))) e.id = "a-z, 0-9 et - (32 caractères max, commence par une lettre ou un chiffre)";
  const id = get("id") || undefined;
  const opt = (k: string) => (get(k) ? get(k) : undefined);
  if (v.type === "openvpn") {
    need("remote");
    if (/\s/.test(get("remote"))) e.remote = "pas d'espace";
    if (!port(get("port"))) e.port = "port entre 1 et 65535";
    for (const k of ["ca", "cert", "key"]) need(k, "bloc PEM requis");
    if (get("tlsCrypt") && get("tlsAuth")) e.tlsAuth = "tls-crypt ou tls-auth, pas les deux";
    if (!get("username") !== !get("password")) e[get("username") ? "password" : "username"] = "identifiant et mot de passe vont ensemble";
    if (Object.keys(e).length) return { errors: e };
    const form: OpenvpnForm = {
      name: get("name"), id, remote: get("remote"), port: Number(get("port")), proto: v.proto === "tcp" ? "tcp" : "udp",
      ca: v.ca!, cert: v.cert!, key: v.key!, tlsCrypt: opt("tlsCrypt"), tlsAuth: opt("tlsAuth"), username: opt("username"), password: opt("password"),
    };
    return { errors: e, form };
  }
  need("address");
  const address = commaList(get("address"));
  e.address ??= badItems(address, isCidr, "CIDR")!;
  const dns = commaList(get("dns"));
  e.dns = badItems(dns, (s) => isIP(s) > 0, "IP")!;
  const keyErr = (k: string, req: boolean) => {
    if (!get(k)) { if (req) e[k] = "requis"; } else if (!KEY.test(get(k))) e[k] = "base64 de 44 caractères attendu";
  };
  keyErr("privateKey", true);
  keyErr("publicKey", true);
  keyErr("presharedKey", false);
  need("endpoint");
  if (get("endpoint") && !(ENDPOINT.exec(get("endpoint")) && port(ENDPOINT.exec(get("endpoint"))![2]!))) e.endpoint = "hôte:port attendu";
  const allowed = commaList(get("allowedIPs"));
  if (!allowed.length) e.allowedIPs = "requis";
  else e.allowedIPs = badItems(allowed, isCidr, "CIDR")!;
  if (get("keepalive") && !(/^\d{1,5}$/.test(get("keepalive")) && Number(get("keepalive")) <= 65535)) e.keepalive = "entier entre 0 et 65535";
  for (const k of Object.keys(e)) if (!e[k]) delete e[k];
  if (Object.keys(e).length) return { errors: e };
  const form: WireguardForm = {
    name: get("name"), id, address: address.join(", "), dns: dns.length ? dns : undefined, privateKey: get("privateKey"),
    peer: { publicKey: get("publicKey"), endpoint: get("endpoint"), allowedIPs: allowed, presharedKey: opt("presharedKey"), keepalive: get("keepalive") ? Number(get("keepalive")) : undefined },
  };
  return { errors: e, form };
}

/** Valide les champs éditables d'un profil existant. */
export function checkEdit(v: Record<string, string>): { errors: Errors; tags: string[]; cidrs: string[]; exclude: string[]; servers: string[] } {
  const e: Errors = {};
  const name = (v.name ?? "").trim();
  if (!name) e.name = "requis";
  else if (name.length > 64) e.name = "64 caractères maximum";
  const tags = commaList(v.tags ?? "");
  const tagErr = badItems(tags, (t) => TAG.test(t), "tag");
  if (tagErr) e.tags = `${tagErr} (a-z, 0-9, -, 16 max)`;
  else if (tags.length > 16 || new Set(tags).size !== tags.length) e.tags = "16 tags maximum, sans doublon";
  const cidrs = lines(v.cidrs ?? "");
  const exclude = lines(v.exclude ?? "");
  const ce = badItems(cidrs, isCidr, "CIDR");
  if (ce) e.cidrs = ce;
  const xe = badItems(exclude, isCidr, "CIDR");
  if (xe) e.exclude = xe;
  const servers = commaList(v.dns ?? "");
  const de = badItems(servers, (s) => isIP(s) > 0, "IP");
  if (de) e.dns = de;
  else if (servers.length > 8) e.dns = "8 serveurs maximum";
  return { errors: e, tags, cidrs, exclude, servers };
}
