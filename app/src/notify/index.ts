import { spawn } from "node:child_process";
import { call, subscribe, type RpcEvent } from "../rpc/client";
import { writeLhost } from "../lhost";

const TITLES: Record<string, [string, "critical" | "normal"]> = {
  up: ["VPN connected", "normal"],
  down: ["VPN disconnected", "normal"],
  drop: ["VPN: tunnel lost", "critical"],
  reconnect: ["VPN: reconnecting", "normal"],
  lock: ["VPN locked", "critical"],
  panic_off: ["VPN: panic-off", "critical"],
  scope_learned: ["VPN: scope learned", "normal"],
};

/** Strips control characters, truncates to 200 characters. */
export function clean(s: string, max = 200): string {
  return [...s.replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ").trim()].slice(0, max).join("");
}

/** notify-send arguments for an event, or null if it is not notifiable. */
export function notifyArgs(e: RpcEvent): string[] | null {
  const t = TITLES[e.kind];
  if (!t) return null;
  const body = clean([e.profile ?? "", e.detail].filter(Boolean).join(": "));
  return ["-a", "vpn-tui", "-u", t[1], "--", t[0], body];
}

export type NotifyOpts = {
  socket?: string;
  notifySend?: string;
  sleep?: (ms: number) => Promise<void>;
  signal?: AbortSignal;
  warn?: (s: string) => void;
};

/** Subscription loop; only returns when the signal is aborted. */
export async function notifyLoop(o: NotifyOpts = {}): Promise<void> {
  const bin = o.notifySend ?? process.env.VPN_TUI_NOTIFY_SEND ?? "notify-send";
  const sleep = o.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms)));
  const warn = o.warn ?? console.error;
  const signal = o.signal ?? new AbortController().signal;
  const aborted = new Promise<void>((r) => signal.addEventListener("abort", () => r(), { once: true }));
  let warned = false;
  const refresh = () =>
    call("status", undefined, { socket: o.socket }).then(
      (s) => writeLhost(s.lhost as string | null, warn),
      () => {},
    );
  const send = (args: string[]) => {
    const p = spawn(bin, args, { stdio: "ignore" });
    p.on("error", (e) => {
      if (warned) return;
      warned = true;
      warn(`Warning: ${bin} not found or unusable (${e.message}), notifications disabled`);
    });
    p.unref();
  };

  let delay = 2000;
  while (!signal.aborted) {
    await refresh();
    let opened = false;
    await new Promise<void>((resolve) => {
      const sub = subscribe(
        (e) => {
          const args = notifyArgs(e);
          if (args) send(args);
          void refresh();
        },
        { socket: o.socket, onOpen: () => ((opened = true), void refresh()), onClose: resolve },
      );
      if (signal.aborted) return sub.close();
      signal.addEventListener("abort", () => sub.close(), { once: true });
    });
    if (signal.aborted) break;
    if (opened) delay = 2000;
    await Promise.race([sleep(delay), aborted]);
    if (!opened) delay = Math.min(delay * 2, 30000);
  }
}

/** `vpn-tui notify` subcommand: SIGINT/SIGTERM -> clean exit. */
export async function notifyCmd(socket?: string): Promise<number> {
  const ac = new AbortController();
  const stop = () => ac.abort();
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  await notifyLoop({ socket, signal: ac.signal });
  return 0;
}
