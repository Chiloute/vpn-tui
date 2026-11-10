import { parseArgs } from "node:util";
import { call, RpcError, TransportError } from "../rpc/client";

const USAGE = `Usage : vpn-tui status [--json]
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

export async function main(argv: string[], io: IO, socket?: string): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: { json: { type: "boolean" }, help: { type: "boolean", short: "h" } },
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
  if (positionals[0] !== "status" || positionals.length > 1) {
    io.err(`Commande inconnue : ${positionals.join(" ")}\n${USAGE}`);
    return 1;
  }
  try {
    const s = (await call("status", undefined, { socket })) as unknown as Status;
    io.out(values.json ? JSON.stringify(s) : formatStatus(s));
    return EXIT[s.state];
  } catch (e) {
    if (e instanceof RpcError) {
      io.err(e.code === -32001 ? `Accès refusé par le daemon : ${e.message}` : `Erreur du daemon (${e.code}) : ${e.message}`);
    } else if (e instanceof TransportError) {
      io.err(`Erreur : ${e.message}`);
    } else throw e;
    return 3;
  }
}
