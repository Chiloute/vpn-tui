import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, type IO } from "./index";
import { call, TransportError } from "../rpc/client";

let dir: string, sock: string, server: Server | undefined;
let received: string[];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "vpn-tui-"));
  sock = join(dir, "s.sock");
  received = [];
});
afterEach(() => {
  server?.close();
  server = undefined;
  rmSync(dir, { recursive: true, force: true });
});

/** Faux daemon : `reply` reçoit la requête et renvoie l'objet de réponse. */
function serve(reply: (req: any) => unknown): Promise<void> {
  server = createServer((c) => {
    c.on("data", (d) => {
      received.push(d.toString());
      const req = JSON.parse(d.toString());
      c.write(JSON.stringify(reply(req)) + "\n");
    });
  });
  return new Promise((r) => server!.listen(sock, r));
}

const status = (state: string, extra = {}) => ({
  state,
  profile: state === "disarmed" ? null : "thm",
  killswitch: state !== "disarmed",
  lhost: state === "armed" ? "10.8.0.2" : null,
  scope: [],
  since: state === "disarmed" ? null : "2026-01-01T10:00:00Z",
  reconnect: { attempt: state === "reconnecting" ? 3 : 0, max: 10 },
  interface: state === "armed" ? "tun0" : null,
  rx_bytes: 0,
  tx_bytes: 0,
  ...extra,
});
const ok = (result: unknown) => (req: any) => ({ jsonrpc: "2.0", id: req.id, result });

async function run(args: string[]) {
  let out = "", err = "";
  const code = await main(args, { out: (s) => (out += s), err: (s) => (err += s) }, sock);
  return { code, out, err };
}

test.each([
  ["disarmed", 1, "○ DISCONNECTED"],
  ["armed", 0, "● CONNECTED thm  LHOST 10.8.0.2  KILLSWITCH ON"],
  ["locked", 2, "■ LOCKED"],
  ["reconnecting", 2, "◐ RECONNECTING 3/10"],
])("status %s", async (state, code, text) => {
  await serve(ok(status(state)));
  const r = await run(["status"]);
  expect(r.code).toBe(code);
  expect(r.out).toBe(text);
  const j = await run(["status", "--json"]);
  expect(j.code).toBe(code);
  expect(JSON.parse(j.out)).toEqual(status(state));
});

test("erreur forbidden -> 3", async () => {
  await serve((req) => ({ jsonrpc: "2.0", id: req.id, error: { code: -32001, message: "non" } }));
  const r = await run(["status"]);
  expect(r.code).toBe(3);
  expect(r.err).toContain("Access denied");
});

test("socket absent -> 3", async () => {
  const r = await run(["status"]);
  expect(r.code).toBe(3);
  expect(r.err).toContain("unreachable");
});

test("réponse non conforme -> 3", async () => {
  await serve(ok(status("armed", { surprise: 1 })));
  const r = await run(["status"]);
  expect(r.code).toBe(3);
  expect(r.err).toContain("invalid");
});

test("requête mal formée refusée avant envoi", async () => {
  await serve(ok({ ok: true }));
  await expect(call("status", { x: 1 }, { socket: sock })).rejects.toBeInstanceOf(TransportError);
  await expect(call("nope", undefined, { socket: sock })).rejects.toBeInstanceOf(TransportError);
  expect(received).toEqual([]);
});

test("sans argument -> usage, exit 1", async () => {
  const r = await run([]);
  expect(r.code).toBe(1);
  expect(r.err).toContain("TUI not implemented");
});

// ---- import / list ----
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const THM = `client
dev tun
proto udp
remote 10.10.10.10 1194
auth-user-pass
<auth-user-pass>
00000000000000000000dead
0000000000000000000000000000beef
</auth-user-pass>
`;
const WG = `[Interface]
PrivateKey = ${"A".repeat(43)}=
Address = 10.0.0.2/32

[Peer]
PublicKey = ${"B".repeat(43)}=
Endpoint = 1.2.3.4:51820
AllowedIPs = 10.0.0.0/24
`;
const prof = (o = {}) => ({
  id: "thm", name: "thm", type: "openvpn", tags: ["ctf"], color: "base0D",
  scope: { cidrs: ["10.0.0.0/8"], exclude: [], learned: [] },
  killswitch: { enabled: true, allow_internet: false, block_ipv6: true }, dns: { servers: [], force: false }, has_secrets: true, ...o,
});

let tool: string, kdir: string, oldTool: string | undefined;
function fakeTool(fail = false) {
  kdir = join(dir, "kr");
  mkdirSync(kdir, { recursive: true });
  tool = join(dir, "secret-tool");
  writeFileSync(tool, `#!/bin/sh\ncase "$1" in store) ${fail ? "echo boom >&2; exit 1" : `cat > "${kdir}/store"`} ;; clear) rm -f "${kdir}/store" ;; esac\n`);
  chmodSync(tool, 0o755);
  oldTool = process.env.VPN_TUI_SECRET_TOOL;
  process.env.VPN_TUI_SECRET_TOOL = tool;
}
afterEach(() => {
  if (oldTool === undefined) delete process.env.VPN_TUI_SECRET_TOOL;
  else process.env.VPN_TUI_SECRET_TOOL = oldTool;
  oldTool = undefined;
});

test("import THM : secrets hors requête, stockés au keyring", async () => {
  fakeTool();
  const f = join(dir, "THM Lab.ovpn");
  writeFileSync(f, THM);
  await serve((req) => ({ jsonrpc: "2.0", id: req.id, result: prof({ id: "thm-lab", name: "THM Lab" }) }));
  const r = await run(["import", f]);
  expect(r.code).toBe(0);
  expect(received.length).toBe(1);
  const req = JSON.parse(received[0]!);
  expect(req.method).toBe("profile_import");
  expect(req.params.id).toBe("thm-lab");
  expect(req.params.name).toBe("THM Lab");
  expect(received[0]).toContain("auth-user-pass");
  expect(received[0]).not.toContain("dead");
  expect(received[0]).not.toContain("beef");
  expect(JSON.parse(readFileSync(join(kdir, "store"), "utf8"))).toEqual({
    username: "00000000000000000000dead", password: "0000000000000000000000000000beef",
  });
  expect(r.out).toContain("moved to the keyring");
  expect(r.out).toContain("10.10.10.10 1194");
  expect(r.out + r.err).not.toMatch(/dead|beef/);
});

test("import : rejet daemon -32006 -> exit 1, keyring vide", async () => {
  fakeTool();
  const f = join(dir, "a.ovpn");
  writeFileSync(f, THM);
  await serve((req) => ({ jsonrpc: "2.0", id: req.id, error: { code: -32006, message: "directive interdite : up" } }));
  const r = await run(["import", f, "--id", "x"]);
  expect(r.code).toBe(1);
  expect(r.err).toBe("directive interdite : up");
  expect(existsSync(join(kdir, "store"))).toBe(false);
});

test("import : échec keyring -> profile_delete", async () => {
  fakeTool(true);
  const f = join(dir, "a.ovpn");
  writeFileSync(f, THM);
  await serve((req) => ({ jsonrpc: "2.0", id: req.id, result: req.method === "profile_delete" ? { ok: true } : prof() }));
  const r = await run(["import", f]);
  expect(r.code).toBe(1);
  expect(received.length).toBe(2);
  expect(JSON.parse(received[1]!)).toMatchObject({ method: "profile_delete", params: { id: "a" } });
  expect(r.err).toContain("keyring");
  expect(r.err).not.toMatch(/dead|beef/);
});

test("import WireGuard", async () => {
  fakeTool();
  const f = join(dir, "wg0.conf");
  writeFileSync(f, WG);
  await serve((req) => ({ jsonrpc: "2.0", id: req.id, result: prof({ id: "wg0", name: "wg0", type: "wireguard" }) }));
  const r = await run(["import", f, "--name", "wg0"]);
  expect(r.code).toBe(0);
  expect(received[0]).not.toContain("AAAAAAAA");
  expect(received[0]).toContain("@keyring");
  expect(JSON.parse(readFileSync(join(kdir, "store"), "utf8")).private_key).toBe("A".repeat(43) + "=");
  expect(r.out).toContain("1.2.3.4:51820");
  expect(r.out + r.err).not.toContain("AAAAAAAA");
});

test("import : arguments manquants / fichier illisible / socket absent", async () => {
  expect((await run(["import"])).code).toBe(1);
  const r = await run(["import", join(dir, "nope.ovpn")]);
  expect(r.code).toBe(1);
  expect(r.err).toContain("Import failed");
  const f = join(dir, "b.ovpn");
  writeFileSync(f, "client\nremote a 1\n");
  expect((await run(["import", f])).code).toBe(3);
});

test("list texte et --json", async () => {
  const res = { profiles: [prof(), prof({ id: "wg0", name: "wg0", type: "wireguard", tags: [], has_secrets: false })] };
  await serve(ok(res));
  const t = await run(["list"]);
  expect(t.code).toBe(0);
  const lines = t.out.split("\n");
  expect(lines[0]).toMatch(/^ID\s+NAME\s+TYPE\s+TAGS\s+SCOPE\s+SECRETS$/);
  expect(lines[1]).toMatch(/^thm\s+thm\s+openvpn\s+ctf\s+10\.0\.0\.0\/8\s+yes$/);
  expect(lines[2]).toMatch(/^wg0\s+wg0\s+wireguard\s+-\s+10\.0\.0\.0\/8\s+no$/);
  expect(JSON.parse((await run(["list", "--json"])).out)).toEqual(res);
});

test("list vide et daemon injoignable", async () => {
  expect((await run(["list"])).code).toBe(3);
  await serve(ok({ profiles: [] }));
  expect((await run(["list"])).out).toBe("No profiles");
});

// ---- up / down / lhost ----
let cache: string, oldCache: string | undefined;
beforeEach(() => {
  cache = join(dir, "cache");
  oldCache = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = cache;
});
afterEach(() => {
  if (oldCache === undefined) delete process.env.XDG_CACHE_HOME;
  else process.env.XDG_CACHE_HOME = oldCache;
});
const lhostFile = () => join(cache, "vpn-tui", "lhost");

function lifecycle(profiles: unknown[], st = status("armed")) {
  return serve((req) => {
    if (req.method === "list") return ok({ profiles })(req);
    if (req.method === "status") return ok(st)(req);
    return ok({ ok: true })(req);
  });
}
const methods = () => received.map((r) => JSON.parse(r).method);

test("up openvpn : secrets du keyring envoyés, LHOST écrit", async () => {
  fakeTool();
  writeFileSync(join(kdir, "store"), JSON.stringify({ username: "uuu", password: "ppp" }));
  writeFileSync(tool, `#!/bin/sh\ncat "${kdir}/store"\n`);
  await lifecycle([prof()]);
  const r = await run(["up", "thm"]);
  expect(r.code).toBe(0);
  expect(methods()).toEqual(["list", "up", "status"]);
  expect(JSON.parse(received[1]!).params).toEqual({ id: "thm", secrets: { username: "uuu", password: "ppp" } });
  expect(r.out).toBe("● CONNECTED thm  LHOST 10.8.0.2  KILLSWITCH ON");
  expect(readFileSync(lhostFile(), "utf8")).toBe("10.8.0.2\n");
  expect(r.out + r.err).not.toMatch(/uuu|ppp/);
});

test("up sans secrets : pas de champ secrets", async () => {
  await lifecycle([prof({ id: "wg0", type: "wireguard", has_secrets: false })]);
  expect((await run(["up", "wg0"])).code).toBe(0);
  expect(JSON.parse(received[1]!).params).toEqual({ id: "wg0" });
});

test("up : secrets absents -> exit 1 sans appel up", async () => {
  fakeTool();
  writeFileSync(tool, "#!/bin/sh\nexit 1\n");
  await lifecycle([prof()]);
  const r = await run(["up", "thm"]);
  expect(r.code).toBe(1);
  expect(r.err).toBe("secrets not found in the keyring for thm: re-import the profile");
  expect(methods()).toEqual(["list"]);
});

test("up : profil inconnu -> 1 ; erreur daemon -> 1 ; injoignable -> 3", async () => {
  await lifecycle([prof({ has_secrets: false })]);
  const r = await run(["up", "zzz"]);
  expect(r.code).toBe(1);
  expect(r.err).toContain("Unknown profile");
  server!.close();
  await serve((req) =>
    req.method === "list" ? ok({ profiles: [prof({ has_secrets: false })] })(req) : { jsonrpc: "2.0", id: req.id, error: { code: -32002, message: "boom" } },
  );
  const e = await run(["up", "thm"]);
  expect(e.code).toBe(1);
  expect(e.err).toContain("boom");
  rmSync(sock, { force: true });
  expect((await run(["up", "thm"])).code).toBe(3);
});

test("down : LHOST vidé", async () => {
  mkdirSync(join(cache, "vpn-tui"), { recursive: true });
  writeFileSync(lhostFile(), "10.8.0.2\n");
  await lifecycle([], status("disarmed"));
  const r = await run(["down"]);
  expect(r.code).toBe(0);
  expect(methods()).toEqual(["down", "status"]);
  expect(readFileSync(lhostFile(), "utf8")).toBe("");
});

test("lhost avec et sans IP", async () => {
  await lifecycle([]);
  const a = await run(["lhost"]);
  expect([a.code, a.out]).toEqual([0, "10.8.0.2"]);
  expect(readFileSync(lhostFile(), "utf8")).toBe("10.8.0.2\n");
  server!.close();
  await lifecycle([], status("disarmed"));
  const b = await run(["lhost"]);
  expect([b.code, b.out]).toEqual([1, ""]);
  expect(readFileSync(lhostFile(), "utf8")).toBe("");
});

test("status met à jour LHOST ; écriture impossible -> avertissement seulement", async () => {
  await lifecycle([]);
  expect((await run(["status"])).code).toBe(0);
  expect(readFileSync(lhostFile(), "utf8")).toBe("10.8.0.2\n");
  process.env.XDG_CACHE_HOME = "/proc/nope";
  const r = await run(["status"]);
  expect(r.code).toBe(0);
  expect(r.err).toContain("Warning");
});

// ---- logs / panic-off ----
const ev = (o = {}) => ({ time: "2026-11-08T14:03:12Z", profile: "thm", state: "armed", kind: "up", detail: "ok", ...o });
const pad = (n: number) => String(n).padStart(2, "0");
const sinceSent = () => JSON.parse(received[0]!).params.since as string;

test.each([["2h", 2 * 3600e3], ["7d", 7 * 86400e3], ["30m", 30 * 60e3]])("logs --since %s", async (d, ms) => {
  await serve(ok({ events: [] }));
  const r = await run(["logs", "--since", d]);
  expect(r.code).toBe(0);
  expect(Math.abs(Date.now() - ms - Date.parse(sinceSent()))).toBeLessThan(5000);
});

test("logs : défaut 24h, date RFC 3339, durée invalide", async () => {
  await serve(ok({ events: [] }));
  expect((await run(["logs"])).out).toBe("No events");
  expect(Math.abs(Date.now() - 86400e3 - Date.parse(sinceSent()))).toBeLessThan(5000);
  received.length = 0;
  await run(["logs", "--since", "2026-11-01T10:00:00+01:00"]);
  expect(sinceSent()).toBe("2026-11-01T09:00:00.000Z");
  received.length = 0;
  for (const bad of ["abc", "5x", "-2h", "2026-13-45T00:00:00Z", "2026-11-01"]) {
    const r = await run(["logs", `--since=${bad}`]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("Invalid duration");
  }
  expect(received).toEqual([]);
});

test("logs texte, --json, injoignable", async () => {
  expect((await run(["logs"])).code).toBe(3);
  const events = [ev(), ev({ profile: null, state: "disarmed", kind: "down", detail: "" })];
  await serve(ok({ events }));
  const t = await run(["logs"]);
  const d = new Date(events[0]!.time);
  const loc = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  expect(t.out.split("\n")[0]).toBe(`${loc}  thm  armed  up  ok`);
  expect(t.out.split("\n")[1]).toMatch(/  -  disarmed  down$/);
  const j = await run(["logs", "--json"]);
  expect(j.out.split("\n").map((l) => JSON.parse(l))).toEqual(events);
});

const runIO = async (args: string[], extra: Partial<IO>) => {
  let out = "", err = "";
  const code = await main(args, { out: (s) => (out += s), err: (s) => (err += s), ...extra }, sock);
  return { code, out, err };
};

test("panic-off --yes", async () => {
  mkdirSync(join(cache, "vpn-tui"), { recursive: true });
  writeFileSync(lhostFile(), "10.8.0.2\n");
  await lifecycle([], status("disarmed"));
  const r = await run(["panic-off", "--yes"]);
  expect(r.code).toBe(0);
  expect(methods()).toEqual(["panic_off", "status"]);
  expect(readFileSync(lhostFile(), "utf8")).toBe("");
  expect(r.out).toContain("Kill switch removed");
});

test("panic-off : confirmation oui / autre / non-TTY", async () => {
  await lifecycle([], status("disarmed"));
  let q = "";
  const yes = await runIO(["panic-off"], { isTTY: true, ask: async (x) => ((q = x), "yes") });
  expect(yes.code).toBe(0);
  expect(q).toBe("Remove the kill switch and drop the tunnel? Type \"yes\": ");
  expect(methods()).toEqual(["panic_off", "status"]);
  received.length = 0;
  const no = await runIO(["panic-off"], { isTTY: true, ask: async () => "Oui " });
  expect(no.code).toBe(1);
  const nt = await runIO(["panic-off"], { isTTY: false, ask: async () => "yes" });
  expect(nt.code).toBe(1);
  expect(nt.err).toContain("use --yes when non-interactive");
  expect(received).toEqual([]);
});

test("panic-off : daemon injoignable -> 3 + recours", async () => {
  const r = await run(["panic-off", "--yes"]);
  expect(r.code).toBe(3);
  expect(r.err).toContain("last resort (root): vpn-tuid --panic-off, or nft delete table inet vpn_tui");
});
