import { afterEach, beforeEach, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { clean, notifyLoop } from "./index";

let subConn: Socket, dir: string, sock: string, server: Server, conns: Socket[], subs: number, fake: string, out: string;
let prevCache: string | undefined;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "vpn-notify-"));
  sock = join(dir, "s.sock");
  out = join(dir, "args");
  fake = join(dir, "fake-notify");
  writeFileSync(fake, `#!/bin/sh\nprintf '%s\\n' "$@" >> ${out}\n`);
  chmodSync(fake, 0o755);
  prevCache = process.env.XDG_CACHE_HOME;
  process.env.XDG_CACHE_HOME = join(dir, "cache");
  conns = [];
  subs = 0;
  server = createServer((c) => {
    conns.push(c);
    c.on("data", (d) => {
      const req = JSON.parse(d.toString());
      if (req.method === "events_subscribe") {
        subs++;
        subConn = c;
        c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: { ok: true } }) + "\n");
      } else {
        const r = { state: "armed", profile: "thm", killswitch: true, lhost: "10.8.0.2", scope: [], since: null, reconnect: { attempt: 0, max: 5 }, interface: "tun0", rx_bytes: 0, tx_bytes: 0 };
        c.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: r }) + "\n");
      }
    });
  });
  await new Promise<void>((r) => server.listen(sock, r));
});
afterEach(() => {
  conns.forEach((c) => c.destroy());
  server.close();
  if (prevCache === undefined) delete process.env.XDG_CACHE_HOME;
  else process.env.XDG_CACHE_HOME = prevCache;
  rmSync(dir, { recursive: true, force: true });
});

const until = async (f: () => boolean) => {
  for (let i = 0; i < 200 && !f(); i++) await Bun.sleep(10);
  expect(f()).toBe(true);
};
const ev = (kind: string, detail = "") => ({ jsonrpc: "2.0", method: "event", params: { time: new Date().toISOString(), profile: "thm", state: "armed", kind, detail } });
const push = (e: unknown) => subConn.write(JSON.stringify(e) + "\n");
const args = () => (existsSync(out) ? readFileSync(out, "utf8").split("\n").filter(Boolean) : []);

test("drop -> critical, up -> normal, args propres, LHOST écrit", async () => {
  const ac = new AbortController();
  const loop = notifyLoop({ socket: sock, notifySend: fake, signal: ac.signal });
  await until(() => subs === 1);
  push(ev("drop", "bad\x1b[31m\x07 detail"));
  await until(() => args().length >= 7);
  expect(args().slice(0, 4)).toEqual(["-a", "vpn-tui", "-u", "critical"]);
  expect(args()[5]).toBe("VPN : tunnel perdu");
  push(ev("up"));
  await until(() => args().length >= 14);
  expect(args()[10]).toBe("normal");
  expect(args().join("")).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f]/);
  expect(readFileSync(join(dir, "cache", "vpn-tui", "lhost"), "utf8")).toBe("10.8.0.2\n");
  ac.abort();
  await loop;
});

test("fermeture du daemon -> réabonnement", async () => {
  const ac = new AbortController();
  const sleeps: number[] = [];
  const loop = notifyLoop({ socket: sock, notifySend: fake, signal: ac.signal, sleep: async (ms) => void sleeps.push(ms) });
  await until(() => subs === 1);
  subConn.destroy();
  await until(() => subs === 2);
  expect(sleeps[0]).toBe(2000);
  ac.abort();
  await loop;
});

test("notify-send absent -> un seul avertissement", async () => {
  const ac = new AbortController();
  const warns: string[] = [];
  const loop = notifyLoop({ socket: sock, notifySend: join(dir, "nope"), signal: ac.signal, warn: (s) => warns.push(s) });
  await until(() => subs === 1);
  push(ev("drop"));
  push(ev("lock"));
  await until(() => warns.length >= 1);
  await Bun.sleep(100);
  expect(warns.length).toBe(1);
  ac.abort();
  await loop;
});

test("clean : contrôle retirés, 200 max", () => {
  expect(clean("a\nb\x00c")).toBe("a b c");
  expect([...clean("é".repeat(300))].length).toBe(200);
});
