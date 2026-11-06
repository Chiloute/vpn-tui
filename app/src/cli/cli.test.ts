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
