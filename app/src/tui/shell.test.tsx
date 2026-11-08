import "ilovetui/solid";
import { afterEach, expect, spyOn, test } from "bun:test";
import { testRender } from "@opentui/solid";
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { theme } from "ilovetui";
import { dismiss, notifications } from "ilovetui/context";
import { resolveBindings } from "../help";
import type { Profile, Status } from "../store";
import { currentView, setCurrentView } from "./shell";
import { Shell } from "./shell";
import { fakeStore, emptyBanner } from "./fake-store";
import { registerTuiViews } from "./views";

const keybinds = parse(readFileSync(new URL("../../config/default.yaml", import.meta.url), "utf8")).keybinds;
const bindings = resolveBindings({ keybinds });
registerTuiViews();

const prof = (id: string, o: Partial<Profile> = {}): Profile => ({
  id, name: id.toUpperCase(), type: "wireguard", tags: ["htb"], color: "base0D",
  scope: { cidrs: ["10.0.0.0/8"], exclude: [], learned: [] }, killswitch: { enabled: true, allow_internet: true, block_ipv6: true }, dns: { servers: ["1.1.1.1"], force: true }, has_secrets: false, ...o,
});
const status = (o: Partial<Status> = {}): Status => ({
  state: "armed", profile: "a", killswitch: true, lhost: "10.10.14.2", scope: ["10.0.0.0/8"], since: null,
  reconnect: { attempt: 0, max: 5 }, interface: "wg0", rx_bytes: 0, tx_bytes: 0, ...o,
});

let t: Awaited<ReturnType<typeof testRender>> | undefined;
afterEach(() => { t?.renderer.destroy(); t = undefined; setCurrentView("profiles"); for (const n of notifications()) dismiss(n.id); });

async function frames(n = 5) {
  await Bun.sleep(20);
  for (let i = 0; i < n; i++) await t!.renderOnce();
}
async function mount(store: ReturnType<typeof fakeStore>, size = { width: 100, height: 30 }) {
  t = await testRender(() => <Shell bindings={bindings} store={store} />, size);
  await frames(2);
  return t;
}
const press = async (k: string) => { if (k === "enter") t!.mockInput.pressEnter(); else if (k === "escape") t!.mockInput.pressEscape(); else t!.mockInput.pressKey(k); await frames(); };
const type = async (s: string) => { await t!.mockInput.typeText(s); await frames(); };
const frame = () => t!.captureCharFrame();
/** Couleur de fond du premier span contenant `text`. */
function bgOf(text: string) {
  for (const l of t!.captureSpans().lines) for (const s of l.spans) if (s.text.includes(text)) return s.bg.toInts().slice(0, 3);
}
const ints = (hex: string) => { const n = parseInt(hex.slice(1), 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255]; };

const sizes = [{ width: 100, height: 30 }, { width: 80, height: 24 }];

for (const size of sizes) {
  const tag = `${size.width}x${size.height}`;

  test(`bandeau par état ${tag}`, async () => {
    const ok = { ...emptyBanner, label: "● CONNECTÉ a", tone: "ok" as const, killswitch: true, lhost: "10.10.14.2", scope: { cidrs: ["10.0.0.0/8"], warning: null }, uptime: "00:01:02", rate: { rx: 2048, tx: 10 } };
    const s = fakeStore({ profiles: [prof("a")] }, ok);
    await mount(s, size);
    expect(frame()).toContain("● CONNECTÉ a");
    expect(frame()).toContain("KILLSWITCH ON");
    expect(frame()).toContain("LHOST 10.10.14.2");
    expect(bgOf("CONNECTÉ")).toEqual(ints(theme.success));
    expect(frame()).toContain("00:01:02");

    s.set({}, { ...ok, label: "◐ RECONNEXION 2/5", tone: "warn" });
    await frames();
    expect(bgOf("RECONNEXION")).toEqual(ints(theme.warning));

    s.set({}, { ...ok, label: "■ VERROUILLÉ", tone: "danger" });
    await frames();
    expect(bgOf("VERROUILLÉ")).toEqual(ints(theme.error));

    s.set({}, { ...ok, label: "● CONNECTÉ a", tone: "danger", killswitch: false });
    await frames();
    expect(frame()).toContain("KILLSWITCH OFF");
    expect(bgOf("CONNECTÉ")).toEqual(ints(theme.error));

    s.set({}, emptyBanner);
    await frames();
    expect(bgOf("DÉCONNECTÉ")).toEqual(ints(theme.muted));

    s.set({}, { ...ok, scope: { cidrs: [], warning: "pas de scope" } });
    await frames();
    expect(frame()).toContain("aucun scope");

    s.set({ daemonReachable: false, lastError: "connect ENOENT" });
    await frames();
    expect(frame()).toContain("daemon injoignable");
    expect(bgOf("daemon injoignable")).toEqual(ints(theme.error));
  });

  test(`liste, navigation, toggle, détail ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof("a"), prof("b")], status: status() });
    await mount(s, size);
    expect(frame()).toContain("A (a)");
    expect(frame()).toContain("B (b)");
    expect(frame()).toContain("▶ A (a)");
    await press("enter");
    expect(s.toggle).toHaveBeenLastCalledWith("a");
    await press("j");
    await press("enter");
    expect(s.toggle).toHaveBeenLastCalledWith("b");
    await press("k");
    await press("d");
    expect(currentView()).toBe("detail");
    expect(frame()).toContain("Kill switch");
    await press("escape");
    expect(currentView()).toBe("profiles");
  });

  test(`x : confirmation et annulation ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof("a")] });
    await mount(s, size);
    await press("x");
    expect(frame()).toContain("Supprimer le profil a et ses secrets ?");
    await press("n");
    expect(s.deleteProfile).not.toHaveBeenCalled();
    expect(frame()).not.toContain("Supprimer le profil");
    await press("x");
    await press("o");
    expect(s.deleteProfile).toHaveBeenCalledWith("a");
  });

  test(`! : exige « oui » ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof("a")] });
    await mount(s, size);
    await press("!");
    expect(frame()).toContain("Kill switch");
    await press("enter");
    expect(s.panicOff).not.toHaveBeenCalled();
    await type("oui");
    await press("enter");
    expect(s.panicOff).toHaveBeenCalledTimes(1);
  });

  test(`s : acceptScope après confirmation seulement ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof("a")] });
    await mount(s, size);
    await press("s");
    await press("o");
    expect(s.acceptScope).not.toHaveBeenCalled(); // pas de pendingScope
    s.set({ pendingScope: { profile: "a", cidrs: ["10.1.0.0/16", "10.0.0.0/8"], added: ["10.1.0.0/16"], existing: ["10.0.0.0/8"] } });
    await frames();
    await press("d");
    expect(frame()).toContain("+ 10.1.0.0/16");
    expect(frame()).toContain("= 10.0.0.0/8");
    await press("s");
    expect(s.acceptScope).not.toHaveBeenCalled();
    await press("n");
    expect(s.acceptScope).not.toHaveBeenCalled();
    await press("s");
    await press("o");
    expect(s.acceptScope).toHaveBeenCalledTimes(1);
  });

  test(`L ouvre les logs, escape revient ${tag}`, async () => {
    const e = (kind: string) => ({ time: "2026-01-01T10:00:00Z", profile: "a", state: "armed", kind, detail: `d-${kind}` });
    const s = fakeStore({ profiles: [prof("a")], events: [e("up"), e("drop")] });
    await mount(s, size);
    t!.mockInput.pressKey("l", { shift: true }); await frames();
    expect(currentView()).toBe("logs");
    expect(frame()).toContain("d-drop");
    await press("j");
    await press("pageup");
    await press("escape");
    expect(currentView()).toBe("profiles");
  });

  test(`y copie le LHOST ${tag}`, async () => {
    const s = fakeStore({}, { ...emptyBanner, lhost: "10.10.14.2" });
    await mount(s, size);
    const spy = spyOn(t!.renderer, "copyToClipboardOSC52").mockReturnValue(true);
    await press("y");
    expect(spy).toHaveBeenCalledWith("10.10.14.2");
  });

  test(`? : aide défilable jusqu'au recours ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof("a")] });
    await mount(s, size);
    await press("?");
    expect(frame()).toContain("Liste des profils");
    for (let i = 0; i < 40 && !frame().includes("nft delete table"); i++) await press("j");
    expect(frame()).toContain("nft delete table");
    await press("escape");
    expect(frame()).not.toContain("Kill switch");
  });
}

test("spinner : libellé pendant busy", async () => {
  const s = fakeStore({ profiles: [prof("a")], busy: "up" });
  await mount(s);
  expect(frame()).toContain("Connexion…");
  s.set({ busy: null, status: status({ state: "reconnecting", reconnect: { attempt: 2, max: 5 } }) });
  await frames();
  expect(frame()).toContain("Reconnexion 2/5…");
});
