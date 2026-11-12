import { isIP } from "node:net";
import type { OpenvpnForm, ProfileForm, WireguardForm } from "../store";
import { ID, ID_RULE } from "../import";

export type Errors = Record<string, string>;

export const isCidr = (s: string): boolean => {
  const [ip, len, ...rest] = s.split("/");
  const v = isIP(ip ?? "");
  return v > 0 && rest.length === 0 && /^\d{1,3}$/.test(len ?? "") && Number(len) <= (v === 4 ? 32 : 128);
};
const KEY = /^[A-Za-z0-9+/]{43}=$/;
const TAG = /^[a-z0-9-]{1,16}$/;
const ENDPOINT = /^(\[[0-9a-fA-F:]+\]|[^\s:[\]]+):(\d{1,5})$/;

export const commaList = (s: string): string[] => s.split(/[,\s]+/).filter(Boolean);
export const lines = (s: string): string[] => s.split("\n").map((l) => l.trim()).filter(Boolean);

const port = (s: string) => /^\d{1,5}$/.test(s) && Number(s) >= 1 && Number(s) <= 65535;

/** Checks that each item satisfies `ok`; returns the error listing the invalid ones. */
function badItems(items: string[], ok: (s: string) => boolean, what: string): string | undefined {
  const bad = items.filter((i) => !ok(i));
  return bad.length ? `invalid ${what}: ${bad.join(", ")}` : undefined;
}

/** Validates the creation form (string values); `form` is set only when there is no error. */
export function buildForm(v: Record<string, string>): { errors: Errors; form?: ProfileForm } {
  const e: Errors = {};
  const get = (k: string) => (v[k] ?? "").trim();
  const need = (k: string, msg = "required") => { if (!get(k)) e[k] = msg; };
  need("name");
  if (get("name").length > 64) e.name = "64 characters maximum";
  if (get("id") && !ID.test(get("id"))) e.id = ID_RULE;
  const id = get("id") || undefined;
  const opt = (k: string) => (get(k) ? get(k) : undefined);
  if (v.type === "openvpn") {
    need("remote");
    if (/\s/.test(get("remote"))) e.remote = "no spaces";
    if (!port(get("port"))) e.port = "port between 1 and 65535";
    for (const k of ["ca", "cert", "key"]) need(k, "PEM block required");
    if (get("tlsCrypt") && get("tlsAuth")) e.tlsAuth = "tls-crypt or tls-auth, not both";
    if (!get("username") !== !get("password")) e[get("username") ? "password" : "username"] = "username and password go together";
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
    if (!get(k)) { if (req) e[k] = "required"; } else if (!KEY.test(get(k))) e[k] = "44-character base64 expected";
  };
  keyErr("privateKey", true);
  keyErr("publicKey", true);
  keyErr("presharedKey", false);
  need("endpoint");
  if (get("endpoint") && !(ENDPOINT.exec(get("endpoint")) && port(ENDPOINT.exec(get("endpoint"))![2]!))) e.endpoint = "host:port expected";
  const allowed = commaList(get("allowedIPs"));
  if (!allowed.length) e.allowedIPs = "required";
  else e.allowedIPs = badItems(allowed, isCidr, "CIDR")!;
  if (get("keepalive") && !(/^\d{1,5}$/.test(get("keepalive")) && Number(get("keepalive")) <= 65535)) e.keepalive = "integer between 0 and 65535";
  for (const k of Object.keys(e)) if (!e[k]) delete e[k];
  if (Object.keys(e).length) return { errors: e };
  const form: WireguardForm = {
    name: get("name"), id, address: address.join(", "), dns: dns.length ? dns : undefined, privateKey: get("privateKey"),
    peer: { publicKey: get("publicKey"), endpoint: get("endpoint"), allowedIPs: allowed, presharedKey: opt("presharedKey"), keepalive: get("keepalive") ? Number(get("keepalive")) : undefined },
  };
  return { errors: e, form };
}

/** Validates the editable fields of an existing profile. */
export function checkEdit(v: Record<string, string>): { errors: Errors; tags: string[]; cidrs: string[]; exclude: string[]; servers: string[] } {
  const e: Errors = {};
  const name = (v.name ?? "").trim();
  if (!name) e.name = "required";
  else if (name.length > 64) e.name = "64 characters maximum";
  const tags = commaList(v.tags ?? "");
  const tagErr = badItems(tags, (t) => TAG.test(t), "tag");
  if (tagErr) e.tags = `${tagErr} (a-z, 0-9, -, 16 max)`;
  else if (tags.length > 16 || new Set(tags).size !== tags.length) e.tags = "16 tags maximum, no duplicates";
  const cidrs = lines(v.cidrs ?? "");
  const exclude = lines(v.exclude ?? "");
  const ce = badItems(cidrs, isCidr, "CIDR");
  if (ce) e.cidrs = ce;
  const xe = badItems(exclude, isCidr, "CIDR");
  if (xe) e.exclude = xe;
  const servers = commaList(v.dns ?? "");
  const de = badItems(servers, (s) => isIP(s) > 0, "IP");
  if (de) e.dns = de;
  else if (servers.length > 8) e.dns = "8 servers maximum";
  return { errors: e, tags, cidrs, exclude, servers };
}
