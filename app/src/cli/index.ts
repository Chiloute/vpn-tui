import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { call, RpcError, TransportError } from "../rpc/client";
import { detectType, extractSecrets, slugify } from "../import";
import { deleteSecrets, loadSecrets, storeSecrets } from "../keyring";
import { writeLhost } from "../lhost";
import { notifyCmd } from "../notify";

const USAGE = `Usage: vpn-tui status [--json]
        vpn-tui import <file> [--name NAME] [--id ID]
        vpn-tui list [--json]
        vpn-tui up <id>
        vpn-tui down
        vpn-tui lhost
        vpn-tui logs [--since 24h|7d|30m|DATE_RFC3339] [--json]
        vpn-tui panic-off [--yes]
        vpn-tui notify   (subscribes to events, sends notify-send notifications, updates LHOST)
        vpn-tui --help`;

type Status = {
  state: "disarmed" | "armed" | "reconnecting" | "locked";
  profile: string | null;
  killswitch: boolean;
  lhost: string | null;
  reconnect: { attempt: number; max: number };
};

export function formatStatus(s: Status): string {
  switch (s.state) {
    case "armed":
      return `● CONNECTED ${s.profile ?? "?"}  LHOST ${s.lhost ?? "-"}  KILLSWITCH ${s.killswitch ? "ON" : "OFF"}`;
    case "locked":
      return "■ LOCKED";
    case "reconnecting":
      return `◐ RECONNECTING ${s.reconnect.attempt}/${s.reconnect.max}`;
    default:
      return "○ DISCONNECTED";
  }
}

const EXIT = { armed: 0, disarmed: 1, locked: 2, reconnecting: 2 } as const;

export type IO = {
  out: (s: string) => void;
  err: (s: string) => void;
  ask?: (q: string) => Promise<string>;
  isTTY?: boolean;
};

const UNIT_MS = { m: 60_000, h: 3_600_000, d: 86_400_000 } as const;

/** Duration (30m, 24h, 7d) or RFC 3339 date -> RFC 3339; null if invalid. */
function parseSince(v: string, now = Date.now()): string | null {
  const m = /^(\d+)([mhd])$/.exec(v);
  if (m) return new Date(now - Number(m[1]) * UNIT_MS[m[2] as keyof typeof UNIT_MS]).toISOString();
  if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/i.test(v)) return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

type Ev = { time: string; profile: string | null; state: string; kind: string; detail: string };

const pad = (n: number) => String(n).padStart(2, "0");
function formatEvent(e: Ev): string {
  const d = new Date(e.time);
  const t = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  return `${t}  ${e.profile ?? "-"}  ${e.state}  ${e.kind}  ${e.detail}`.trimEnd();
}

async function logsCmd(since: string, json: boolean, io: IO, socket?: string): Promise<number> {
  const iso = parseSince(since);
  if (!iso) {
    io.err(`Invalid duration: ${since} (expected: 30m, 24h, 7d or an RFC 3339 date)`);
    return 1;
  }
  try {
    const { events } = (await call("logs", { since: iso }, { socket })) as unknown as { events: Ev[] };
    io.out(events.length === 0 ? (json ? "" : "No events") : events.map((e) => (json ? JSON.stringify(e) : formatEvent(e))).join("\n"));
    return 0;
  } catch (e) {
    return rpcFailure(e, io);
  }
}

async function defaultAsk(q: string): Promise<string> {
  const { createInterface } = await import("node:readline/promises");
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await rl.question(q);
  } finally {
    rl.close();
  }
}

async function panicOffCmd(yes: boolean, io: IO, socket?: string): Promise<number> {
  if (!yes) {
    if (!(io.isTTY ?? process.stdin.isTTY)) {
      io.err("panic-off: cannot confirm, use --yes when non-interactive");
      return 1;
    }
    const a = await (io.ask ?? defaultAsk)("Remove the kill switch and drop the tunnel? Type \"yes\": ");
    if (a !== "yes") {
      io.err("Cancelled");
      return 1;
    }
  }
  try {
    await call("panic_off", undefined, { socket });
    return statusAfter("Kill switch removed and tunnel dropped.\n", io, socket);
  } catch (e) {
    const code = rpcFailure(e, io);
    io.err("last resort (root): vpn-tuid --panic-off, or nft delete table inet vpn_tui");
    return code;
  }
}

function rpcFailure(e: unknown, io: IO): number {
  if (e instanceof RpcError) {
    io.err(e.code === -32001 ? `Access denied by the daemon: ${e.message}` : `Daemon error (${e.code}): ${e.message}`);
  } else if (e instanceof TransportError) {
    io.err(`Error: ${e.message}`);
  } else throw e;
  return 3;
}

type Profile = { id: string; name: string; type: string; tags: string[]; scope: { cidrs: string[] }; has_secrets: boolean };

function formatList(ps: Profile[]): string {
  if (ps.length === 0) return "No profiles";
  const rows = [
    ["ID", "NAME", "TYPE", "TAGS", "SCOPE", "SECRETS"],
    ...ps.map((p) => [p.id, p.name, p.type, p.tags.join(",") || "-", p.scope.cidrs.join(",") || "-", p.has_secrets ? "yes" : "no"]),
  ];
  const w = rows[0]!.map((_, c) => Math.max(...rows.map((r) => [...r[c]!].length)));
  return rows.map((r) => r.map((x, c) => x + " ".repeat(w[c]! - [...x].length)).join("  ").trimEnd()).join("\n");
}

async function importCmd(file: string, name: string | undefined, idOpt: string | undefined, io: IO, socket?: string) {
  let type, id, content, secrets, pname: string;
  try {
    const raw = readFileSync(file, "utf8");
    type = detectType(raw, file);
    ({ content, secrets } = extractSecrets(type, raw));
    pname = name ?? basename(file).replace(/\.[^.]*$/, "");
    id = idOpt ?? slugify(pname);
  } catch (e) {
    io.err(`Import failed: ${(e as Error).message}`);
    return 1;
  }
  const endpoint = type === "openvpn" ? /^\s*remote\s+(\S+(?:\s+\d+)?)/m.exec(content)?.[1] : /^\s*Endpoint\s*=\s*(\S+)/im.exec(content)?.[1];
  try {
    await call("profile_import", { type, name: pname, id, content }, { socket });
  } catch (e) {
    if (e instanceof RpcError && (e.code === -32006 || e.code === -32602)) {
      io.err(e.message);
      return 1;
    }
    return rpcFailure(e, io);
  }
  if (secrets) {
    try {
      await storeSecrets(id, secrets);
    } catch (e) {
      let extra = "";
      try {
        await call("profile_delete", { id }, { socket });
      } catch {
        extra = ` ; WARNING: profile "${id}" could not be removed from the daemon (delete it manually)`;
      }
      io.err(`Failed to store secrets in the keyring: ${(e as Error).message}${extra || " (import cancelled)"}`);
      return 1;
    }
  }
  io.out(
    [
      `Profile imported: ${pname}`,
      `  type    : ${type}`,
      `  id      : ${id}`,
      ...(endpoint ? [`  server  : ${endpoint}`] : []),
      `  secrets : ${secrets ? "moved to the keyring" : "none"}`,
    ].join("\n"),
  );
  return 0;
}

async function getStatus(io: IO, socket?: string): Promise<Status> {
  const s = (await call("status", undefined, { socket })) as unknown as Status;
  writeLhost(s.lhost, io.err);
  return s;
}

/** Prints the status after an action that already succeeded: a failing status call is a warning, not a failure. */
async function statusAfter(done: string, io: IO, socket?: string): Promise<number> {
  try {
    io.out(done + formatStatus(await getStatus(io, socket)));
  } catch (e) {
    if (done) io.out(done.trimEnd());
    io.err(`warning: cannot read the status after the action: ${(e as Error).message}`);
  }
  return 0;
}

async function upCmd(id: string, io: IO, socket?: string): Promise<number> {
  try {
    const { profiles } = (await call("list", undefined, { socket })) as unknown as { profiles: Profile[] };
    const p = profiles.find((x) => x.id === id);
    if (!p) {
      io.err(`Unknown profile: ${id}`);
      return 1;
    }
    let params: { id: string; secrets?: unknown } = { id };
    if (p.has_secrets) {
      let secrets;
      try {
        secrets = await loadSecrets(id);
      } catch (e) {
        io.err(`Cannot read the keyring for ${id}: ${(e as Error).message}`);
        return 1;
      }
      if (!secrets) {
        io.err(`secrets not found in the keyring for ${id}: re-import the profile`);
        return 1;
      }
      params = { id, secrets };
    }
    try {
      await call("up", params, { socket, timeoutMs: 90_000 });
    } catch (e) {
      if (!(e instanceof RpcError)) throw e;
      io.err(`Daemon error (${e.code}): ${e.message}`);
      return 1;
    }
    return statusAfter("", io, socket);
  } catch (e) {
    return rpcFailure(e, io);
  }
}

export async function main(argv: string[], io: IO, socket?: string): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        json: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        name: { type: "string" },
        id: { type: "string" },
        since: { type: "string" },
        yes: { type: "boolean" },
      },
    });
  } catch (e) {
    io.err(`${(e as Error).message}\n${USAGE}`);
    return 1;
  }
  const { values, positionals } = parsed;
  if (values.help) {
    io.out(USAGE);
    return 0;
  }
  if (positionals.length === 0) {
    io.err(`TUI not implemented\n${USAGE}`);
    return 1;
  }
  const [cmd, ...rest] = positionals;
  if (cmd === "import") {
    if (rest.length !== 1) {
      io.err(`import: exactly one file is required\n${USAGE}`);
      return 1;
    }
    return importCmd(rest[0]!, values.name, values.id, io, socket);
  }
  if (cmd === "list" && rest.length === 0) {
    try {
      const r = (await call("list", undefined, { socket })) as unknown as { profiles: Profile[] };
      io.out(values.json ? JSON.stringify(r) : formatList(r.profiles));
      return 0;
    } catch (e) {
      return rpcFailure(e, io);
    }
  }
  if (cmd === "up") {
    if (rest.length !== 1) {
      io.err(`up: exactly one profile id is required\n${USAGE}`);
      return 1;
    }
    return upCmd(rest[0]!, io, socket);
  }
  if (cmd === "down" && rest.length === 0) {
    try {
      await call("down", undefined, { socket });
      return statusAfter("", io, socket);
    } catch (e) {
      return rpcFailure(e, io);
    }
  }
  if (cmd === "notify" && rest.length === 0) return notifyCmd(socket);
  if (cmd === "logs" && rest.length === 0) return logsCmd(values.since ?? "24h", !!values.json, io, socket);
  if (cmd === "panic-off" && rest.length === 0) return panicOffCmd(!!values.yes, io, socket);
  if (cmd === "lhost" && rest.length === 0) {
    try {
      const s = await getStatus(io, socket);
      if (!s.lhost) return 1;
      io.out(s.lhost);
      return 0;
    } catch (e) {
      return rpcFailure(e, io);
    }
  }
  if (cmd !== "status" || rest.length > 0) {
    io.err(`Unknown command: ${positionals.join(" ")}\n${USAGE}`);
    return 1;
  }
  try {
    const s = await getStatus(io, socket);
    io.out(values.json ? JSON.stringify(s) : formatStatus(s));
    return EXIT[s.state];
  } catch (e) {
    return rpcFailure(e, io);
  }
}
