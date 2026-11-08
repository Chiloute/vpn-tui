import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { call, RpcError, TransportError } from "../rpc/client";
import { detectType, extractSecrets, slugify } from "../import";
import { deleteSecrets, storeSecrets } from "../keyring";

const USAGE = `Usage : vpn-tui status [--json]
        vpn-tui import <fichier> [--name NOM] [--id ID]
        vpn-tui list [--json]
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

export type IO = { out: (s: string) => void; err: (s: string) => void };

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
  if (cmd !== "status" || rest.length > 0) {
    io.err(`Commande inconnue : ${positionals.join(" ")}\n${USAGE}`);
    return 1;
  }
  try {
    const s = (await call("status", undefined, { socket })) as unknown as Status;
    io.out(values.json ? JSON.stringify(s) : formatStatus(s));
    return EXIT[s.state];
  } catch (e) {
    return rpcFailure(e, io);
  }
}
