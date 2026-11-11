import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { call as rpcCall, subscribe as rpcSubscribe, RpcError, type RpcEvent, type SubscribeOpts } from "../rpc/client";
import { detectType, extractSecrets, slugify, type Secrets } from "../import";
import { deleteSecrets, loadSecrets, storeSecrets } from "../keyring";
import { writeLhost } from "../lhost";
import { bannerModel, type Banner, type Busy, type Profile, type Sample, type Status } from "./banner";
import { buildContent, formSecrets, type ProfileForm } from "./forms";

export * from "./banner";
export * from "./forms";

export type Deps = {
  call: (method: string, params?: unknown, opts?: { socket?: string; timeoutMs?: number }) => Promise<Record<string, unknown>>;
  subscribe: (onEvent: (e: RpcEvent) => void, opts?: SubscribeOpts) => { close(): void };
  loadSecrets: (id: string) => Promise<Secrets | null>;
  storeSecrets: (id: string, s: Secrets) => Promise<void>;
  deleteSecrets: (id: string) => Promise<void>;
  writeLhost: (ip: string | null, warn?: (s: string) => void) => void;
  readFile: (path: string) => string;
  socket?: string;
  retryMs?: number;
  now?: () => number;
};
const defaultDeps: Deps = {
  call: rpcCall, subscribe: rpcSubscribe, loadSecrets, storeSecrets, deleteSecrets, writeLhost,
  readFile: (p) => readFileSync(p, "utf8"),
};

export type PendingScope = { profile: string; cidrs: string[]; added: string[]; existing: string[] };
export type State = {
  status: Status | null;
  profiles: Profile[];
  events: RpcEvent[];
  pendingScope: PendingScope | null;
  busy: Busy;
  daemonReachable: boolean;
  lastError: string | null;
};
export type ImportInput = { filename: string; content: string; name?: string; id?: string };
export type ImportPreview = { type: string; id: string; name: string; endpoint?: string; hasSecrets: boolean };

const MAX_EVENTS = 500;
const DAY = 86_400_000;

function parseImport({ filename, content: raw, name, id }: ImportInput) {
  const type = detectType(raw, filename);
  const { content, secrets } = extractSecrets(type, raw);
  const pname = name ?? basename(filename).replace(/\.[^.]*$/, "");
  const pid = id ?? slugify(pname);
  const endpoint = type === "openvpn" ? /^\s*remote\s+(\S+(?:\s+\d+)?)/m.exec(content)?.[1] : /^\s*Endpoint\s*=\s*(\S+)/im.exec(content)?.[1];
  return { type, content, secrets, pname, pid, endpoint };
}

/** Local preview, nothing is sent; never returns a secret. */
export function previewImport(input: ImportInput): { preview: ImportPreview } | { error: string } {
  try {
    const r = parseImport(input);
    return { preview: { type: r.type, id: r.pid, name: r.pname, endpoint: r.endpoint, hasSecrets: !!r.secrets } };
  } catch (e) {
    return { error: (e as Error).message };
  }
}

export function createStore(overrides: Partial<Deps> = {}) {
  const d: Deps = { ...defaultDeps, ...overrides };
  const now = d.now ?? Date.now;
  const sock = d.socket ? { socket: d.socket } : {};
  let state: State = { status: null, profiles: [], events: [], pendingScope: null, busy: null, daemonReachable: false, lastError: null };
  const listeners = new Set<(s: State) => void>();
  const set = (p: Partial<State>) => {
    state = { ...state, ...p };
    for (const l of [...listeners]) l(state);
  };
  let samples: { prev: Sample | null; cur: Sample | null } = { prev: null, cur: null };

  const redact = (m: string, secrets: string[]) => secrets.reduce((a, s) => a.split(s).join("***"), m);
  const describe = (e: unknown) =>
    e instanceof RpcError
      ? e.code === -32001 ? `Access denied by the daemon: ${e.message}` : `Daemon error (${e.code}): ${e.message}`
      : e instanceof Error ? e.message : "unknown error";

  let refreshSeq = 0;
  async function refresh(): Promise<void> {
    const my = ++refreshSeq;
    try {
      const s = (await d.call("status", undefined, sock)) as unknown as Status;
      const { profiles } = (await d.call("list", undefined, sock)) as unknown as { profiles: Profile[] };
      if (my !== refreshSeq) return; // a newer refresh is in flight: do not overwrite fresh state with this snapshot
      samples = { prev: samples.cur, cur: { rx: s.rx_bytes, tx: s.tx_bytes, at: now() } };
      d.writeLhost(s.lhost, () => {});
      set({ status: s, profiles, daemonReachable: true });
    } catch (e) {
      if (!(e instanceof RpcError)) set({ daemonReachable: false });
      set({ lastError: describe(e) });
    }
  }

  async function act<T>(kind: Exclude<Busy, null>, fn: () => Promise<T>, secrets: string[] = []): Promise<T | undefined> {
    if (state.busy && kind !== "panic") return undefined; // one action at a time; panic-off always goes through
    set({ busy: kind, lastError: null });
    try {
      return await fn();
    } catch (e) {
      set({ lastError: redact(describe(e), secrets) });
    } finally {
      set({ busy: null });
    }
  }

  async function up(id: string) {
    const { profiles } = (await d.call("list", undefined, sock)) as unknown as { profiles: Profile[] };
    const p = profiles.find((x) => x.id === id);
    if (!p) throw new Error(`Unknown profile: ${id}`);
    let params: { id: string; secrets?: unknown } = { id };
    if (p.has_secrets) {
      let secrets;
      try {
        secrets = await d.loadSecrets(id);
      } catch (e) {
        throw new Error(`Cannot read the keyring for ${id}: ${(e as Error).message}`);
      }
      if (!secrets) throw new Error(`secrets not found in the keyring for ${id}: re-import the profile`);
      params = { id, secrets };
    }
    await d.call("up", params, { ...sock, timeoutMs: 90_000 });
    await refresh();
  }

  async function doImport(input: ImportInput) {
    const r = parseImport(input);
    await d.call("profile_import", { type: r.type, name: r.pname, id: r.pid, content: r.content }, sock);
    if (r.secrets) {
      try {
        await d.storeSecrets(r.pid, r.secrets);
      } catch (e) {
        let more = " (import cancelled)";
        try {
          await d.call("profile_delete", { id: r.pid }, sock);
        } catch {
          more = ` ; WARNING: profile "${r.pid}" could not be removed from the daemon (delete it manually)`;
        }
        throw new Error(`Failed to store secrets in the keyring: ${(e as Error).message}${more}`);
      }
    }
    await refresh();
    return r.pid;
  }

  function onEvent(e: RpcEvent) {
    set({ events: [...state.events, e].slice(-MAX_EVENTS) });
    if (e.kind === "scope_learned" && e.profile) {
      const cidrs = e.detail.split(",").map((c) => c.trim()).filter(Boolean);
      const cur = state.profiles.find((p) => p.id === e.profile)?.scope.cidrs ?? [];
      set({ pendingScope: { profile: e.profile, cidrs, added: cidrs.filter((c) => !cur.includes(c)), existing: cidrs.filter((c) => cur.includes(c)) } });
    }
    void refresh();
  }

  let stopped = true;
  let sub: { close(): void } | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  function connect() {
    if (stopped) return;
    let opened = false;
    sub = d.subscribe(onEvent, {
      ...sock,
      onOpen: () => {
        opened = true;
        set({ daemonReachable: true });
        void refresh(); // catches up on anything missed during the cut
      },
      onError: () => {
        if (!opened) set({ daemonReachable: false });
      },
      onClose: () => {
        set({ daemonReachable: false });
        if (!stopped) timer = setTimeout(connect, d.retryMs ?? 2000);
      },
    });
  }

  return {
    getState: () => state,
    onChange(l: (s: State) => void) {
      listeners.add(l);
      return () => void listeners.delete(l);
    },
    refresh,
    /** Refresh, 7-day history, then subscription (reconnected automatically). */
    async start() {
      if (!stopped) return;
      stopped = false;
      await refresh();
      try {
        const since = new Date(now() - 7 * DAY).toISOString();
        const { events } = (await d.call("logs", { since }, sock)) as unknown as { events: RpcEvent[] };
        set({ events: events.slice(-MAX_EVENTS) });
      } catch (e) {
        set({ lastError: describe(e) });
      }
      connect();
    },
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      sub?.close();
    },
    toggle(id: string) {
      const active = state.status?.profile === id && state.status.state !== "disarmed";
      // "reconnect": switch from another active profile
      const kind = active ? "down" : state.status?.state === "armed" ? "reconnect" : "up";
      return act(kind, async () => {
        if (active) await d.call("down", undefined, sock);
        else return up(id);
        await refresh();
      });
    },
    down: () => act("down", async () => { await d.call("down", undefined, sock); await refresh(); }),
    panicOff: () => act("panic", async () => { await d.call("panic_off", undefined, sock); await refresh(); }),
    previewImport,
    importProfile: (input: ImportInput) => act("import", () => doImport(input)),
    importFile: (path: string, o: { name?: string; id?: string } = {}) =>
      act("import", () => doImport({ filename: path, content: d.readFile(path), ...o })),
    createProfile(form: ProfileForm) {
      const secrets = formSecrets(form);
      return act("import", async () => {
        const b = buildContent(form);
        return doImport({ filename: b.filename, content: b.content, name: form.name, id: form.id });
      }, secrets);
    },
    updateProfile: (id: string, patch: Record<string, unknown>) =>
      act("import", async () => { await d.call("profile_update", { id, ...patch }, sock); await refresh(); }),
    deleteProfile: (id: string) =>
      act("import", async () => {
        await d.call("profile_delete", { id }, sock);
        try {
          await d.deleteSecrets(id);
        } catch (e) {
          throw new Error(`Profile deleted, but the keyring could not be cleaned: ${(e as Error).message}`);
        } finally {
          await refresh();
        }
      }),
    acceptScope: () =>
      act("import", async () => {
        const p = state.pendingScope;
        if (!p) return;
        await d.call("scope_learn_accept", { id: p.profile, cidrs: p.cidrs }, sock);
        set({ pendingScope: null });
        await refresh();
      }),
    lhost: () => state.status?.lhost ?? null,
    banner: (): Banner => bannerModel(state.status, state.profiles, state.busy, { prev: samples.prev, now: now() }),
  };
}
export type Store = ReturnType<typeof createStore>;
