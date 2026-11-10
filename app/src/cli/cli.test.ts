import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "./index";
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
  ["disarmed", 1, "○ DÉCONNECTÉ"],
  ["armed", 0, "● CONNECTÉ thm  LHOST 10.8.0.2  KILLSWITCH ON"],
  ["locked", 2, "■ VERROUILLÉ"],
  ["reconnecting", 2, "◐ RECONNEXION 3/10"],
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
  expect(r.err).toContain("refusé");
});

test("socket absent -> 3", async () => {
  const r = await run(["status"]);
  expect(r.code).toBe(3);
  expect(r.err).toContain("injoignable");
});

test("réponse non conforme -> 3", async () => {
  await serve(ok(status("armed", { surprise: 1 })));
  const r = await run(["status"]);
  expect(r.code).toBe(3);
  expect(r.err).toContain("invalide");
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
  expect(r.err).toContain("TUI non implémenté");
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
  id: "thm", name: "thm", type: "openvpn", tags: ["ctf"], color: "#ffffff",
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
  expect(r.out).toContain("extraits vers le keyring");
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
  expect(r.err).toContain("Import impossible");
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
  expect(lines[0]).toMatch(/^ID\s+NOM\s+TYPE\s+TAGS\s+SCOPE\s+SECRETS$/);
  expect(lines[1]).toMatch(/^thm\s+thm\s+openvpn\s+ctf\s+10\.0\.0\.0\/8\s+oui$/);
  expect(lines[2]).toMatch(/^wg0\s+wg0\s+wireguard\s+-\s+10\.0\.0\.0\/8\s+non$/);
  expect(JSON.parse((await run(["list", "--json"])).out)).toEqual(res);
});

test("list vide et daemon injoignable", async () => {
  expect((await run(["list"])).code).toBe(3);
  await serve(ok({ profiles: [] }));
  expect((await run(["list"])).out).toBe("Aucun profil");
});
