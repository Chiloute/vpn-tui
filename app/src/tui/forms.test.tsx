import "ilovetui/solid";
import { afterEach, beforeAll, expect, test } from "bun:test";
import { testRender } from "@opentui/solid";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { dismiss, notifications } from "ilovetui/context";
import { resolveBindings } from "../help";
import type { Profile } from "../store";
import { fakeStore } from "./fake-store";
import { completePath, listEntries, pickEntry } from "./import-view";
import { currentView, setCurrentView, Shell } from "./shell";
import { registerTuiViews } from "./views";

const keybinds = parse(readFileSync(new URL("../../config/default.yaml", import.meta.url), "utf8")).keybinds;
const bindings = resolveBindings({ keybinds });
beforeAll(registerTuiViews);

const prof = (o: Partial<Profile> = {}): Profile => ({
  id: "a", name: "A", type: "wireguard", tags: ["htb"], color: "base0D",
  scope: { cidrs: ["10.0.0.0/8"], exclude: [], learned: [] },
  killswitch: { enabled: true, allow_internet: false, block_ipv6: false },
  dns: { servers: ["1.1.1.1"], force: true }, has_secrets: false, ...o,
});

let t: Awaited<ReturnType<typeof testRender>> | undefined;
afterEach(() => { t?.renderer.destroy(); t = undefined; setCurrentView("profiles"); for (const n of notifications()) dismiss(n.id); });

const frames = async (n = 5) => { await Bun.sleep(20); for (let i = 0; i < n; i++) await t!.renderOnce(); };
async function mount(store: ReturnType<typeof fakeStore>, size: { width: number; height: number }) {
  t = await testRender(() => <Shell bindings={bindings} store={store} />, size);
  await frames(2);
}
const press = async (k: "enter" | "escape" | "tab" | "stab" | "ctrl+s" | "right" | string) => {
  const m = t!.mockInput;
  if (k === "enter") m.pressEnter();
  else if (k === "escape") m.pressEscape();
  else if (k === "tab") m.pressTab();
  else if (k === "stab") m.pressTab({ shift: true });
  else if (k === "ctrl+s") m.pressKey("s", { ctrl: true });
  else if (k === "right" || k === "up" || k === "down") m.pressArrow(k);
  else m.pressKey(k);
  await frames();
};
const type = async (s: string) => { await t!.mockInput.typeText(s); await frames(); };
const tabs = async (n: number) => { for (let i = 0; i < n; i++) await press("tab"); };
const frame = () => t!.captureCharFrame();

const sizes = [{ width: 100, height: 30 }, { width: 80, height: 24 }];

const OVPN = (extra = "") => `client\ndev tun\nproto udp\nremote thm.example.org 1194\n${extra}<ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</ca>\n<auth-user-pass>\ndeadUser\nbeefPass\n</auth-user-pass>\n`;
function fixture(name: string, content: string) {
  const dir = mkdtempSync(join(tmpdir(), "vpn-tui-imp-"));
  const path = join(dir, name);
  writeFileSync(path, content);
  return { dir, path };
}

test("completePath completes a unique name and the common prefix", () => {
  const { dir } = fixture("thm-a.ovpn", "x");
  writeFileSync(join(dir, "thm-b.ovpn"), "x");
  mkdirSync(join(dir, "sous"));
  expect(completePath(join(dir, "sou"))).toBe(join(dir, "sous") + "/");
  expect(completePath(join(dir, "th"))).toBe(join(dir, "thm-"));
  expect(completePath(join(dir, "zzz"))).toBe(join(dir, "zzz"));
});

test("listEntries filters on the typed prefix, directories first; pickEntry keeps the style", () => {
  const { dir } = fixture("thm-a.ovpn", "x");
  writeFileSync(join(dir, ".hidden"), "x");
  mkdirSync(join(dir, "sous"));
  expect(listEntries(dir + "/").entries).toEqual([{ name: "..", dir: true }, { name: "sous", dir: true }, { name: "thm-a.ovpn", dir: false }]);
  expect(listEntries(join(dir, "th")).entries).toEqual([{ name: "thm-a.ovpn", dir: false }]);
  expect(listEntries(join(dir, ".h")).entries).toEqual([{ name: ".hidden", dir: false }]);
  expect(listEntries(join(dir, "nope") + "/").entries).toEqual([]);
  expect(pickEntry(dir + "/", { name: "sous", dir: true })).toBe(join(dir, "sous") + "/");
  expect(pickEntry(join(dir, "th"), { name: "thm-a.ovpn", dir: false })).toBe(join(dir, "thm-a.ovpn"));
  expect(pickEntry(dir + "/", { name: "..", dir: true })).toBe(dirname(dir) + "/");
  expect(pickEntry("", { name: "..", dir: true })).toBe(dirname(homedir()) + "/");
  expect(pickEntry("~/", { name: ".config", dir: true })).toBe("~/.config/");
});

test("import: explorer picks a file with the arrows and Enter", async () => {
  const { dir } = fixture("thm.ovpn", OVPN());
  mkdirSync(join(dir, "sous"));
  const s = fakeStore({ profiles: [prof()] });
  await mount(s, sizes[0]!);
  await press("i");
  await type(dir + "/");
  let f = frame();
  expect(f).toContain("sous/");
  expect(f).toContain("thm.ovpn");
  await press("down"); // .. -> sous/
  await press("enter");
  expect(frame()).not.toContain("thm.ovpn"); // inside the empty sous/
  await press("up"); // on ..
  await press("enter");
  await press("down"); await press("down"); // thm.ovpn
  await press("enter");
  f = frame();
  expect(f).toContain("Type: openvpn");
  expect(f).not.toContain("sous/"); // the explorer hides once the preview is shown
});

for (const size of sizes) {
  const tag = `${size.width}x${size.height}`;

  test(`import: valid file, preview without secret, confirmation ${tag}`, async () => {
    const { dir, path } = fixture("thm.ovpn", OVPN());
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("i");
    expect(currentView()).toBe("import");
    await type(join(dir, "th"));
    await press("tab"); // completes the name
    expect(frame()).toContain("thm.ovpn");
    await press("enter");
    const f = frame();
    expect(f).toContain("Type: openvpn");
    expect(f).toContain("thm.example.org 1194");
    expect(f).toContain("moved to the keyring");
    expect(f).not.toContain("dead");
    expect(f).not.toContain("beef");
    expect(s.importProfile).not.toHaveBeenCalled();
    await press("enter"); // name -> id
    await press("enter"); // id -> button
    await press("enter"); // Importer
    expect(s.importProfile).toHaveBeenCalledTimes(1);
    const arg = s.importProfile.mock.calls[0]![0] as { filename: string; name: string; id: string };
    expect(arg).toMatchObject({ filename: path, name: "thm", id: "thm" });
    expect(currentView()).toBe("profiles");
  });

  test(`import: local parser rejection, nothing imported ${tag}`, async () => {
    const { dir } = fixture("bad.ovpn", "client\nremote x 1194\nauth-user-pass /etc/secret\n");
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("i");
    await type(join(dir, "bad.ovpn"));
    await press("enter");
    expect(frame()).toContain("auth-user-pass <file>");
    expect(s.importProfile).not.toHaveBeenCalled();
    expect(currentView()).toBe("import");
  });

  test(`import: daemon rejection (up /bin/sh) shown ${tag}`, async () => {
    const { dir } = fixture("evil.ovpn", "client\nremote x 1194\nup /bin/sh\n");
    const s = fakeStore({ profiles: [prof()] });
    s.importProfile.mockImplementation(async () => { s.set({ lastError: "Daemon error (-32006): directive interdite : up" }); return undefined; });
    await mount(s, size);
    await press("i");
    await type(join(dir, "evil.ovpn"));
    await press("enter");
    await tabs(2); // name -> id -> button
    await press("enter");
    expect(s.importProfile).toHaveBeenCalledTimes(1);
    expect(frame()).toContain("directive interdite : up");
    expect(currentView()).toBe("import");
  });

  test(`import: escape goes back without doing anything ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("i");
    await press("escape");
    expect(currentView()).toBe("profiles");
    expect(s.importProfile).not.toHaveBeenCalled();
  });

  test(`valid OpenVPN creation, secrets masked ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("n");
    expect(currentView()).toBe("edit");
    await tabs(1); await type("lab");
    await tabs(2); await type("vpn.example.org");
    await tabs(3); await type("CAPEM");
    await tabs(1); await type("CERTPEM");
    await tabs(1); await type("SECRETKEY123");
    await tabs(1); await t!.mockInput.pasteBracketedText("TLSCRYPTSECRET"); await frames();
    await tabs(2); await type("bob");
    await tabs(1); await type("hunter2pass");
    for (const secret of ["SECRETKEY123", "TLSCRYPTSECRET", "hunter2pass"]) expect(frame()).not.toContain(secret);
    expect(frame()).toContain("•");
    await press("ctrl+s");
    expect(s.createProfile).toHaveBeenCalledTimes(1);
    expect(s.createProfile.mock.calls[0]![0]).toMatchObject({
      name: "lab", remote: "vpn.example.org", port: 1194, proto: "udp", ca: "CAPEM", cert: "CERTPEM",
      key: "SECRETKEY123", tlsCrypt: "TLSCRYPTSECRET", username: "bob", password: "hunter2pass",
    });
    expect(currentView()).toBe("profiles");
  });

  test(`invalid creation: per-field errors, no call ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("n");
    await press("ctrl+s");
    expect(s.createProfile).not.toHaveBeenCalled();
    expect(frame()).toContain("required");
    await press("stab"); // back to the type choice
    await press("right"); // WireGuard
    await tabs(1); await type("wg");
    await tabs(2); await type("10.8.0.2/32");
    await tabs(1); await type("10.8.0.1");
    await tabs(1); await type("abc"); // invalid private key
    await tabs(1); await type("B".repeat(43) + "=");
    await tabs(1); await type("wg.example.org:51820");
    await tabs(1); await type("10.10.0.0/16");
    await press("ctrl+s");
    expect(s.createProfile).not.toHaveBeenCalled();
    expect(frame()).toContain("44-character base64");
    expect(frame()).not.toContain("abc");
  });

  test(`valid WireGuard creation ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("n");
    await press("right");
    await tabs(1); await type("wg");
    await tabs(2); await type("10.8.0.2/32");
    await tabs(1); await type("10.8.0.1");
    await tabs(1); await type("A".repeat(43) + "=");
    expect(frame()).not.toContain("AAAAAAAA");
    await tabs(1); await type("B".repeat(43) + "=");
    await tabs(1); await type("wg.example.org:51820");
    await tabs(1); await type("10.10.0.0/16, 10.129.0.0/16");
    await tabs(2); await type("25");
    await press("ctrl+s");
    expect(s.createProfile).toHaveBeenCalledTimes(1);
    expect(s.createProfile.mock.calls[0]![0]).toEqual({
      name: "wg", id: undefined, address: "10.8.0.2/32", dns: ["10.8.0.1"], privateKey: "A".repeat(43) + "=",
      peer: { publicKey: "B".repeat(43) + "=", endpoint: "wg.example.org:51820", allowedIPs: ["10.10.0.0/16", "10.129.0.0/16"], presharedKey: undefined, keepalive: 25 },
    });
  });

  test(`edit: block_ipv6 and scope only ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("e");
    expect(currentView()).toBe("edit");
    expect(frame()).toContain("re-import");
    await tabs(3); // cidrs
    await type("10.1.0.0/16"); // the cursor is at the start of the field
    await press("enter");
    await tabs(4); // exclude, ks_enabled, allow_internet, block_ipv6
    await press("enter"); // bascule
    await press("ctrl+s");
    expect(s.updateProfile).toHaveBeenCalledTimes(1);
    expect(s.updateProfile).toHaveBeenCalledWith("a", {
      scope: { cidrs: ["10.1.0.0/16", "10.0.0.0/8"], exclude: [], learned: [] },
      killswitch: { enabled: true, allow_internet: false, block_ipv6: true },
    });
    expect(currentView()).toBe("detail");
  });

  test(`edit: kill switch warning, invalid CIDR, confirmed cancel ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("e");
    await tabs(5); // ks_enabled
    expect(frame()).not.toContain("will not be protected");
    await press("enter");
    expect(frame()).toContain("the scope will not be protected");
    await press("stab"); await press("stab"); // cidrs
    await type("zzz");
    await press("ctrl+s");
    expect(s.updateProfile).not.toHaveBeenCalled();
    expect(frame()).toContain("invalid CIDR");
    await press("escape");
    expect(frame()).toContain("Discard");
    await press("n");
    expect(currentView()).toBe("edit");
    await press("escape");
    await press("y");
    expect(currentView()).toBe("detail");
  });

  test(`typing: x, q, ? trigger no shortcut ${tag}`, async () => {
    const s = fakeStore({ profiles: [prof()] });
    await mount(s, size);
    await press("n");
    await tabs(1);
    await type("xq?!yL");
    expect(t!.renderer.isDestroyed).toBe(false);
    expect(currentView()).toBe("edit");
    expect(s.deleteProfile).not.toHaveBeenCalled();
    expect(s.panicOff).not.toHaveBeenCalled();
    expect(frame()).toContain("xq?!yL");
    expect(frame()).not.toContain("Delete profile");
    // import: same guard in the path field
    await press("escape");
    await press("y"); // form modified: confirmation
    await press("i");
    await type("xq");
    expect(currentView()).toBe("import");
    expect(frame()).toContain("xq");
  });
}

test("banner: connecting to daemon… before the first refresh, then unreachable", async () => {
  const s = fakeStore({ daemonReachable: false });
  await mount(s, sizes[0]!);
  expect(frame()).toContain("connecting to daemon…");
  expect(frame()).not.toContain("daemon unreachable");
  s.set({ lastError: "connect ENOENT" });
  await frames();
  expect(frame()).toContain("daemon unreachable");
});
