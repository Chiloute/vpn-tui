export type Status = {
  state: "disarmed" | "armed" | "reconnecting" | "locked";
  profile: string | null;
  killswitch: boolean;
  lhost: string | null;
  scope: string[];
  since: string | null;
  reconnect: { attempt: number; max: number };
  interface: string | null;
  rx_bytes: number;
  tx_bytes: number;
};
export type Profile = {
  id: string;
  name: string;
  type: string;
  tags: string[];
  color: string;
  scope: { cidrs: string[]; exclude: string[]; learned: string[] };
  killswitch: { enabled: boolean; allow_internet: boolean; block_ipv6: boolean };
  dns: { servers: string[]; force: boolean };
  has_secrets: boolean;
};
export type Busy = null | "up" | "down" | "reconnect" | "import" | "panic";
export type Sample = { rx: number; tx: number; at: number };

export type Banner = {
  label: string;
  tone: "ok" | "warn" | "danger" | "neutral";
  killswitch: boolean;
  lhost: string | null;
  scope: { cidrs: string[]; warning: string | null };
  uptime: string | null; // HH:MM:SS
  rate: { rx: number; tx: number } | null; // octets/s
};

const p2 = (n: number) => String(n).padStart(2, "0");

/** Pure. `ctx.prev` = échantillon rx/tx du status précédent ; `ctx.now` en ms. `busy` n'altère pas le bandeau. */
export function bannerModel(
  s: Status | null,
  profiles: Profile[],
  _busy: Busy,
  ctx: { prev?: Sample | null; now?: number } = {},
): Banner {
  const now = ctx.now ?? Date.now();
  if (!s) {
    return { label: "○ DÉCONNECTÉ", tone: "neutral", killswitch: false, lhost: null, scope: { cidrs: [], warning: null }, uptime: null, rate: null };
  }
  let label = "○ DÉCONNECTÉ";
  let tone: Banner["tone"] = "neutral";
  if (s.state === "armed") {
    label = `● CONNECTÉ ${s.profile ?? "?"}`;
    tone = s.killswitch ? "ok" : "danger";
  } else if (s.state === "reconnecting") {
    label = `◐ RECONNEXION ${s.reconnect.attempt}/${s.reconnect.max}`;
    tone = "warn";
  } else if (s.state === "locked") {
    label = "■ VERROUILLÉ";
    tone = "danger";
  }
  const active = s.state === "armed" || s.state === "reconnecting";
  const prof = profiles.find((p) => p.id === s.profile);
  const cidrs = s.scope.length ? s.scope : (prof?.scope.cidrs ?? []);
  const warning = active && s.profile && cidrs.length === 0 ? "pas de scope" : null;

  let uptime: string | null = null;
  const t = s.since ? Date.parse(s.since) : NaN;
  if (active && !Number.isNaN(t)) {
    const sec = Math.max(0, Math.floor((now - t) / 1000));
    uptime = `${p2(Math.floor(sec / 3600))}:${p2(Math.floor(sec / 60) % 60)}:${p2(sec % 60)}`;
  }
  let rate: Banner["rate"] = null;
  const pv = ctx.prev;
  if (active && pv && now > pv.at && s.rx_bytes >= pv.rx && s.tx_bytes >= pv.tx) {
    const dt = (now - pv.at) / 1000;
    rate = { rx: (s.rx_bytes - pv.rx) / dt, tx: (s.tx_bytes - pv.tx) / dt };
  }
  return { label, tone, killswitch: s.killswitch, lhost: s.lhost, scope: { cidrs, warning }, uptime, rate };
}
