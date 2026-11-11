import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { subscribe } from "./client";

let dir: string, sock: string, server: Server | undefined, conn: Socket | undefined;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "vpn-tui-"));
  sock = join(dir, "s.sock");
});
afterEach(() => {
  conn?.destroy();
  server?.close();
  rmSync(dir, { recursive: true, force: true });
});

const ev = (kind: string) => ({ jsonrpc: "2.0", method: "event", params: { time: "2026-01-01T10:00:00Z", profile: "thm", state: "armed", kind, detail: "" } });

function serve(): Promise<void> {
  server = createServer((c) => {
    conn = c;
    c.on("data", (d) => {
      const req = JSON.parse(d.toString());
      c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { ok: true } }) + "\n");
    });
  });
  return new Promise((r) => server!.listen(sock, r));
}
const until = async (f: () => boolean) => { for (let i = 0; i < 100 && !f(); i++) await Bun.sleep(10); };

test("subscribe: events, invalid notification ignored, onClose", async () => {
  await serve();
  const got: string[] = [], errors: Error[] = [];
  let closed = 0, opened = 0;
  subscribe((e) => got.push(e.kind), { socket: sock, onOpen: () => opened++, onError: (e) => errors.push(e), onClose: () => closed++ });
  await until(() => opened === 1);
  conn!.write(JSON.stringify(ev("up")) + "\n" + JSON.stringify({ jsonrpc: "2.0", method: "event", params: { kind: "nope" } }) + "\n");
  conn!.write(JSON.stringify(ev("down")) + "\n");
  await until(() => got.length === 2);
  expect(got).toEqual(["up", "down"]);
  expect(errors.length).toBe(1);
  conn!.destroy();
  await until(() => closed === 1);
  expect(closed).toBe(1);
});

test("subscribe: no ack -> error and close", async () => {
  server = createServer((c) => { conn = c; }); // accepts, never answers
  await new Promise<void>((r) => server!.listen(sock, r));
  const errors: Error[] = [];
  let closed = 0;
  subscribe(() => {}, { socket: sock, onError: (e) => errors.push(e), onClose: () => closed++ });
  for (let i = 0; i < 70 && closed === 0; i++) await Bun.sleep(100); // ack timeout is 5 s
  expect(errors.map((e) => e.message)).toEqual(["subscription ack timed out"]);
}, 10_000);

test("subscribe: line > 64 KiB -> error and close; daemon absent -> onClose", async () => {
  await serve();
  let closed = 0, opened = 0;
  const errors: Error[] = [];
  subscribe(() => {}, { socket: sock, onOpen: () => opened++, onError: (e) => errors.push(e), onClose: () => closed++ });
  await until(() => opened === 1);
  conn!.write("x".repeat(70_000));
  await until(() => closed === 1);
  expect(errors.some((e) => /too large/.test(e.message))).toBe(true);

  let c2 = 0;
  subscribe(() => {}, { socket: join(dir, "absent.sock"), onClose: () => c2++ });
  await until(() => c2 === 1);
  expect(c2).toBe(1);
});

test("subscribe: close() closes and calls onClose", async () => {
  await serve();
  let closed = 0, opened = 0;
  const s = subscribe(() => {}, { socket: sock, onOpen: () => opened++, onClose: () => closed++ });
  await until(() => opened === 1);
  s.close();
  s.close();
  expect(closed).toBe(1);
});
