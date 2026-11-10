import { expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "yaml";
import { globalCommands, killswitch, resolveBindings, views } from "./index";
import { renderKeysMd } from "./markdown";

const yamlPath = new URL("../../config/default.yaml", import.meta.url);
const defaults = parse(readFileSync(yamlPath, "utf8")).keybinds as Record<string, string>;

test("chaque vue a rôle, commandes et section kill switch", () => {
  for (const v of Object.values(views)) {
    expect(v.role.length).toBeGreaterThan(10);
    expect(v.commands.length).toBeGreaterThan(0);
  }
  expect(killswitch.states.map((s) => s.label)).toEqual(["DISARMED", "ARMED", "LOCKED", "RECONNECTING"]);
  expect(killswitch.panicOff).toContain("nft delete table inet vpn_tui");
});

test("default.yaml est aligné sur la table", () => {
  const all = [...globalCommands, ...Object.values(views).flatMap((v) => v.commands)];
  expect(Object.keys(defaults).sort()).toEqual(all.map((c) => c.name).sort());
  for (const c of all) expect(defaults[c.name]).toBe(c.defaultKey);
});

test("resolveBindings : défauts et surcharge", () => {
  const r = resolveBindings({ keybinds: defaults });
  expect(r.profiles.find((c) => c.name === "profiles.import")?.key).toBe("i");
  const o = resolveBindings({ keybinds: { ...defaults, "profiles.import": "a" } });
  expect(o.profiles.find((c) => c.name === "profiles.import")?.key).toBe("a");
});

test("conflit de touches vue + global détecté", () => {
  expect(() => resolveBindings({ keybinds: { ...defaults, "profiles.import": "q" } })).toThrow(/Key conflict.*"q"/);
});

test("surcharge utilisateur via loadMergedProjectConfig", async () => {
  const dir = mkdtempSync(join(tmpdir(), "vpn-tui-"));
  mkdirSync(join(dir, "vpn-tui"));
  writeFileSync(join(dir, "vpn-tui", "config.yaml"), "keybinds:\n  profiles.import: a\n");
  process.env.XDG_CONFIG_HOME = dir;
  const { loadConfig } = await import("../config");
  expect(resolveBindings(loadConfig()).profiles.find((c) => c.name === "profiles.import")?.key).toBe("a");
});

test("docs/keys.md est à jour", () => {
  expect(readFileSync(new URL("../../../docs/keys.md", import.meta.url), "utf8")).toBe(renderKeysMd());
});
