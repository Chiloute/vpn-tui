import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { call, RpcError, TransportError } from "../rpc/client";
import { detectType, extractSecrets, slugify } from "../import";
import { deleteSecrets, loadSecrets, storeSecrets } from "../keyring";
import { writeLhost } from "../lhost";

const USAGE = `Usage : vpn-tui status [--json]
        vpn-tui import <fichier> [--name NOM] [--id ID]
        vpn-tui list [--json]
        vpn-tui up <id>
        vpn-tui down
        vpn-tui lhost
        vpn-tui logs [--since 24h|7d|30m|DATE_RFC3339] [--json]
        vpn-tui panic-off [--yes]
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
      return `● CONNECTÉ ${s.profile ?? "?"}  LHOST ${s.lhost ?? "-"}  KILLSWITCH ${s.killswitch ? "ON" : "OFF"}`;
    case "locked":
      return "■ VERROUILLÉ";
    case "reconnecting":
      return `◐ RECONNEXION ${s.reconnect.attempt}/${s.reconnect.max}`;
    default:
      return "○ DÉCONNECTÉ";
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

/** Durée (30m, 24h, 7d) ou date RFC 3339 -> RFC 3339 ; null si invalide. */
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
    io.err(`Durée invalide : ${since} (attendu : 30m, 24h, 7d ou date RFC 3339)`);
    return 1;
  }
  try {
    const { events } = (await call("logs", { since: iso }, { socket })) as unknown as { events: Ev[] };
    io.out(events.length === 0 ? "Aucun événement" : events.map((e) => (json ? JSON.stringify(e) : formatEvent(e))).join("\n"));
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
      io.err("panic-off : confirmation impossible, utilisez --yes en non interactif");
      return 1;
    }
    const a = await (io.ask ?? defaultAsk)("Supprimer le kill switch et couper le tunnel ? Tapez « oui » : ");
    if (a !== "oui") {
      io.err("Annulé");
      return 1;
    }
  }
  try {
    await call("panic_off", undefined, { socket });
    const s = await getStatus(io, socket);
    io.out(`Kill switch supprimé et tunnel coupé.\n${formatStatus(s)}`);
    return 0;
  } catch (e) {
    const code = rpcFailure(e, io);
    io.err("en dernier recours (root) : vpn-tuid --panic-off, ou nft delete table inet vpn_tui");
    return code;
  }
}

function rpcFailure(e: unknown, io: IO): number {
  if (e instanceof RpcError) {
    io.err(e.code === -32001 ? `Accès refusé par le daemon : ${e.message}` : `Erreur du daemon (${e.code}) : ${e.message}`);
  } else if (e instanceof TransportError) {
    io.err(`Erreur : ${e.message}`);
  } else throw e;
  return 3;
}

type Profile = { id: string; name: string; type: string; tags: string[]; scope: { cidrs: string[] }; has_secrets: boolean };

function formatList(ps: Profile[]): string {
  if (ps.length === 0) return "Aucun profil";
  const rows = [
    ["ID", "NOM", "TYPE", "TAGS", "SCOPE", "SECRETS"],
    ...ps.map((p) => [p.id, p.name, p.type, p.tags.join(",") || "-", p.scope.cidrs.join(",") || "-", p.has_secrets ? "oui" : "non"]),
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
    io.err(`Import impossible : ${(e as Error).message}`);
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
        extra = ` ; ATTENTION : le profil "${id}" n'a pas pu être retiré du daemon (supprimez-le manuellement)`;
      }
      io.err(`Échec du stockage des secrets dans le keyring : ${(e as Error).message}${extra || " (import annulé)"}`);
      return 1;
    }
  }
  io.out(
    [
      `Profil importé : ${pname}`,
      `  type    : ${type}`,
      `  id      : ${id}`,
      ...(endpoint ? [`  serveur : ${endpoint}`] : []),
      `  secrets : ${secrets ? "extraits vers le keyring" : "aucun"}`,
    ].join("\n"),
  );
  return 0;
}

async function getStatus(io: IO, socket?: string): Promise<Status> {
  const s = (await call("status", undefined, { socket })) as unknown as Status;
  writeLhost(s.lhost, io.err);
  return s;
}

async function upCmd(id: string, io: IO, socket?: string): Promise<number> {
  try {
    const { profiles } = (await call("list", undefined, { socket })) as unknown as { profiles: Profile[] };
    const p = profiles.find((x) => x.id === id);
    if (!p) {
      io.err(`Profil inconnu : ${id}`);
      return 1;
    }
    let params: { id: string; secrets?: unknown } = { id };
    if (p.has_secrets) {
      let secrets;
      try {
        secrets = await loadSecrets(id);
      } catch (e) {
        io.err(`Lecture du keyring impossible pour ${id} : ${(e as Error).message}`);
        return 1;
      }
      if (!secrets) {
        io.err(`secrets introuvables dans le keyring pour ${id} : réimportez le profil`);
        return 1;
      }
      params = { id, secrets };
    }
    try {
      await call("up", params, { socket, timeoutMs: 90_000 });
    } catch (e) {
      if (!(e instanceof RpcError)) throw e;
      io.err(`Erreur du daemon (${e.code}) : ${e.message}`);
      return 1;
    }
    io.out(formatStatus(await getStatus(io, socket)));
    return 0;
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
    io.err(`TUI non implémenté\n${USAGE}`);
    return 1;
  }
  const [cmd, ...rest] = positionals;
  if (cmd === "import") {
    if (rest.length !== 1) {
      io.err(`import : un fichier est requis (et un seul)\n${USAGE}`);
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
      io.err(`up : un identifiant de profil est requis (et un seul)\n${USAGE}`);
      return 1;
    }
    return upCmd(rest[0]!, io, socket);
  }
  if (cmd === "down" && rest.length === 0) {
    try {
      await call("down", undefined, { socket });
      io.out(formatStatus(await getStatus(io, socket)));
      return 0;
    } catch (e) {
      return rpcFailure(e, io);
    }
  }
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
    io.err(`Commande inconnue : ${positionals.join(" ")}\n${USAGE}`);
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
