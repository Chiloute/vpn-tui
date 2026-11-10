import { expect, test } from "bun:test";
import { RpcError, type RpcEvent, type SubscribeOpts } from "../rpc/client";
import { detectType, extractSecrets } from "../import";
import { bannerModel, createStore, previewImport, type Status } from "./index";

const WG_PRIV = "A".repeat(43) + "=";
const WG_PSK = "B".repeat(43) + "=";
const status = (o: Partial<Status> = {}): Status => ({
  state: "disarmed", profile: null, killswitch: false, lhost: null, scope: [], since: null,
  reconnect: { attempt: 0, max: 10 }, interface: null, rx_bytes: 0, tx_bytes: 0, ...o,
});
const profile = (id: string, o: any = {}) => ({
  id, name: id, type: "openvpn", tags: [], color: "#fff", scope: { cidrs: [], exclude: [], learned: [] },
  killswitch: true, dns: { servers: [], force: false }, has_secrets: false, ...o,
});
const ev = (kind: string, detail = "", p: string | null = "a"): RpcEvent => ({ time: "2026-01-01T10:00:00Z", profile: p, state: "armed", kind, detail });

function harness(o: { status?: Status; profiles?: any[]; handlers?: Record<string, (p: any) => unknown> } = {}) {
  const calls: { method: string; params: any; opts?: any }[] = [];
  const subs: SubscribeOpts[] = [];
  let onEvent: (e: RpcEvent) => void = () => {};
  const stored: any[] = [], deleted: string[] = [], lhosts: (string | null)[] = [];
  let secrets: any = null;
  const store = createStore({
    retryMs: 10,
    call: async (method, params, opts) => {
      calls.push({ method, params, opts });
      const h = o.handlers?.[method];
      if (h) return h(params) as any;
      if (method === "status") return (o.status ?? status()) as any;
      if (method === "list") return { profiles: o.profiles ?? [] };
      if (method === "logs") return { events: [ev("up")] };
      return { ok: true };
    },
    subscribe: (cb, opts) => {
      onEvent = cb;
      subs.push(opts!);
      return { close() {} };
    },
    loadSecrets: async () => secrets,
    storeSecrets: async (id, s) => { stored.push([id, s]); },
    deleteSecrets: async (id) => { deleted.push(id); },
    writeLhost: (ip) => { lhosts.push(ip); },
    readFile: () => "client\nremote h 1194\n",
  });
  return { store, calls, subs, stored, deleted, lhosts, emit: (e: RpcEvent) => onEvent(e), setSecrets: (s: any) => (secrets = s) };
}
const methods = (h: { calls: { method: string }[] }) => h.calls.map((c) => c.method);
const tick = () => Bun.sleep(30);

test("start : refresh, logs 7j, abonnement, réabonnement après coupure, events plafonnés", async () => {
  const h = harness({ status: status({ lhost: "10.8.0.2" }) });
  await h.store.start();
  expect(methods(h).slice(0, 3)).toEqual(["status", "list", "logs"]);
  expect(h.lhosts).toEqual(["10.8.0.2"]);
  expect(h.store.getState().events.length).toBe(1);
  expect(h.subs.length).toBe(1);
  h.subs[0]!.onOpen!();
  expect(h.store.getState().daemonReachable).toBe(true);
  h.subs[0]!.onClose!();
  expect(h.store.getState().daemonReachable).toBe(false);
  await tick();
  expect(h.subs.length).toBe(2);
  for (let i = 0; i < 600; i++) h.emit(ev("up"));
  expect(h.store.getState().events.length).toBe(500);
  h.store.stop();
  h.subs[1]!.onClose!();
  await tick();
  expect(h.subs.length).toBe(2);
});

test("scope_learned -> pendingScope avec diff, puis acceptScope", async () => {
  const h = harness({ profiles: [profile("a", { scope: { cidrs: ["10.0.0.0/24"], exclude: [], learned: [] } })] });
  await h.store.start();
  h.emit(ev("scope_learned", "10.0.0.0/24,10.1.0.0/24"));
  expect(h.store.getState().pendingScope).toEqual({ profile: "a", cidrs: ["10.0.0.0/24", "10.1.0.0/24"], added: ["10.1.0.0/24"], existing: ["10.0.0.0/24"] });
  await h.store.acceptScope();
  expect(h.calls.find((c) => c.method === "scope_learn_accept")!.params).toEqual({ id: "a", cidrs: ["10.0.0.0/24", "10.1.0.0/24"] });
  expect(h.store.getState().pendingScope).toBeNull();
  h.store.stop();
});

test("toggle : up sans secrets, up avec secrets (90 s), down si actif, busy remis à null", async () => {
  const h = harness({ profiles: [profile("a"), profile("b", { has_secrets: true })] });
  const busy: any[] = [];
  h.store.onChange((s) => busy.push(s.busy));
  await h.store.toggle("a");
  const up = h.calls.find((c) => c.method === "up")!;
  expect(up.params).toEqual({ id: "a" });
  expect(up.opts.timeoutMs).toBe(90_000);
  expect(busy).toContain("up");
  expect(h.store.getState().busy).toBeNull();

  await h.store.toggle("b");
  expect(h.store.getState().lastError).toMatch(/introuvables/);
  h.setSecrets({ username: "u", password: "p" });
  await h.store.toggle("b");
  expect(h.calls.filter((c) => c.method === "up")[1]!.params).toEqual({ id: "b", secrets: { username: "u", password: "p" } });

  const h2 = harness({ status: status({ state: "armed", profile: "a", killswitch: true }), profiles: [profile("a")] });
  await h2.store.refresh();
  await h2.store.toggle("a");
  expect(methods(h2)).toContain("down");
  expect(methods(h2)).not.toContain("up");
});

test("panicOff, down, updateProfile, deleteProfile", async () => {
  const h = harness();
  await h.store.panicOff();
  await h.store.down();
  await h.store.updateProfile("a", { name: "Z" });
  await h.store.deleteProfile("a");
  expect(methods(h).filter((m) => !["status", "list"].includes(m))).toEqual(["panic_off", "down", "profile_update", "profile_delete"]);
  expect(h.calls.find((c) => c.method === "profile_update")!.params).toEqual({ id: "a", name: "Z" });
  expect(h.deleted).toEqual(["a"]);
});

test("import : secrets au keyring ; rollback si le stockage échoue ; erreur sans secret", async () => {
  const ovpn = "client\nremote h 1194\n<auth-user-pass>\nbob\nhunter2pass\n</auth-user-pass>\n";
  const h = harness();
  await h.store.importProfile({ filename: "x.ovpn", content: ovpn, name: "X" });
  expect(h.stored).toEqual([["x", { username: "bob", password: "hunter2pass" }]]);
  expect(JSON.stringify(h.calls.find((c) => c.method === "profile_import")!.params)).not.toContain("hunter2pass");

  const calls: string[] = [];
  const store = createStore({
    call: async (m) => { calls.push(m); return (m === "status" ? status() : m === "list" ? { profiles: [] } : { ok: true }) as any; },
    storeSecrets: async () => { throw new Error("keyring KO hunter2pass"); },
    writeLhost: () => {},
  });
  await store.importProfile({ filename: "x.ovpn", content: ovpn, name: "X" });
  expect(calls).toContain("profile_delete");
  expect(store.getState().lastError).toMatch(/import annulé/);
  expect(store.getState().busy).toBeNull();

  const bad = await h.store.importProfile({ filename: "x.txt", content: "rien" });
  expect(bad).toBeUndefined();
  expect(h.store.getState().lastError).toMatch(/non reconnu/);
  expect("error" in previewImport({ filename: "x.txt", content: "rien" })).toBe(true);
  const pv: any = previewImport({ filename: "x.ovpn", content: ovpn });
  expect(pv.preview).toEqual({ type: "openvpn", id: "x", name: "x", endpoint: "h 1194", hasSecrets: true });
});

test("daemon refuse l'import : lastError français, rien dans le keyring", async () => {
  const h = harness({ handlers: { profile_import: () => { throw new RpcError(-32006, "profil déjà existant"); } } });
  await h.store.importProfile({ filename: "x.ovpn", content: "client\nremote h 1194\n" });
  expect(h.store.getState().lastError).toContain("profil déjà existant");
  expect(h.stored).toEqual([]);
});

test("createProfile OpenVPN : contenu valide, secrets au keyring, rien dans profile_import", async () => {
  const h = harness();
  await h.store.createProfile({
    name: "Mon VPN", remote: "vpn.example.org", port: 1194, proto: "udp",
    ca: "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----", cert: "CERT", key: "PRIVATEKEYDATA",
    tlsCrypt: "TLSCRYPTKEY", username: "alice", password: "s3cretpw",
  });
  const sent = h.calls.find((c) => c.method === "profile_import")!.params;
  expect(sent.type).toBe("openvpn");
  expect(sent.id).toBe("mon-vpn");
  expect(sent.content).toContain("remote vpn.example.org 1194");
  expect(sent.content).not.toContain("s3cretpw");
  expect(h.stored).toEqual([["mon-vpn", { username: "alice", password: "s3cretpw" }]]);
  expect(h.store.getState().lastError).toBeNull();
});

test("createProfile WireGuard : contenu passe detectType/extractSecrets, pas de secret envoyé", async () => {
  const h = harness();
  await h.store.createProfile({
    name: "wg1", address: "10.0.0.2/32", dns: ["1.1.1.1"], privateKey: WG_PRIV,
    peer: { publicKey: "C".repeat(43) + "=", endpoint: "1.2.3.4:51820", allowedIPs: ["10.0.0.0/24"], presharedKey: WG_PSK, keepalive: 25 },
  });
  const sent = h.calls.find((c) => c.method === "profile_import")!.params;
  expect(sent.type).toBe("wireguard");
  expect(sent.content).not.toContain(WG_PRIV);
  expect(sent.content).not.toContain(WG_PSK);
  expect(h.stored).toEqual([["wg1", { private_key: WG_PRIV, preshared_key: WG_PSK }]]);
  // le contenu brut produit est bien reconnu
  const sentBack = sent.content as string;
  expect(detectType(sentBack, "x.conf")).toBe("wireguard");
  expect(extractSecrets("wireguard", sentBack.replace(/@keyring/, WG_PRIV).replace(/@keyring/, WG_PSK)).secrets).toEqual({ private_key: WG_PRIV, preshared_key: WG_PSK });
});

test("createProfile : un secret invalide n'apparaît pas dans lastError", async () => {
  const h = harness();
  await h.store.createProfile({
    name: "wg2", address: "10.0.0.2/32", privateKey: "TOPSECRETbad",
    peer: { publicKey: "C".repeat(43) + "=", endpoint: "1.2.3.4:51820", allowedIPs: "0.0.0.0/0" },
  });
  const err = h.store.getState().lastError!;
  expect(err).toBeTruthy();
  expect(err).not.toContain("TOPSECRETbad");
});

test("bannerModel : tous les états", () => {
  const now = Date.parse("2026-01-01T10:01:05Z");
  const since = "2026-01-01T10:00:00Z";
  const ps = [profile("a", { scope: { cidrs: ["10.0.0.0/8"], exclude: [], learned: [] } })];
  const ok = bannerModel(status({ state: "armed", profile: "a", killswitch: true, lhost: "10.8.0.2", scope: ["10.0.0.0/8"], since, rx_bytes: 3000, tx_bytes: 1000 }), ps, null, { now, prev: { rx: 1000, tx: 0, at: now - 2000 } });
  expect(ok).toMatchObject({ label: "● CONNECTÉ a", tone: "ok", killswitch: true, lhost: "10.8.0.2", uptime: "00:01:05", rate: { rx: 1000, tx: 500 } });
  expect(ok.scope.warning).toBeNull();
  expect(bannerModel(status({ state: "armed", profile: "a", killswitch: false }), ps, null).tone).toBe("danger");
  expect(bannerModel(status({ state: "armed", profile: "z", killswitch: true }), ps, null).scope.warning).toBe("pas de scope");
  const rc = bannerModel(status({ state: "reconnecting", profile: "a", reconnect: { attempt: 2, max: 10 } }), ps, null);
  expect([rc.label, rc.tone]).toEqual(["◐ RECONNEXION 2/10", "warn"]);
  const lk = bannerModel(status({ state: "locked" }), ps, null);
  expect([lk.label, lk.tone]).toEqual(["■ VERROUILLÉ", "danger"]);
  const dis = bannerModel(status(), ps, null);
  expect([dis.label, dis.tone, dis.uptime, dis.rate]).toEqual(["○ DÉCONNECTÉ", "neutral", null, null]);
});
