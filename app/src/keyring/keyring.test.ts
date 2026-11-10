import { afterAll, beforeAll, expect, test } from "bun:test";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deleteSecrets, keyringRef, loadSecrets, storeSecrets } from ".";

let dir: string;
const old = process.env.VPN_TUI_SECRET_TOOL;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "fake-st-"));
  const bin = join(dir, "secret-tool");
  writeFileSync(
    bin,
    `#!/bin/sh
D="${dir}"
echo "$@" >> "$D/args.log"
case "$1" in
  store) cat > "$D/store" ;;
  lookup) [ -f "$D/store" ] && cat "$D/store" || exit 1 ;;
  clear) rm -f "$D/store" ;;
esac
`,
  );
  chmodSync(bin, 0o755);
  process.env.VPN_TUI_SECRET_TOOL = bin;
});
afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
  if (old === undefined) delete process.env.VPN_TUI_SECRET_TOOL;
  else process.env.VPN_TUI_SECRET_TOOL = old;
});

test("aller-retour store/lookup/clear sans secret dans argv", async () => {
  expect(keyringRef("thm")).toBe("vpn-tui/thm");
  expect(await loadSecrets("thm")).toBeNull();
  const s = { username: "u-secret-name", password: "p-secret-word" };
  await storeSecrets("thm", s);
  expect(await loadSecrets("thm")).toEqual(s);
  await deleteSecrets("thm");
  expect(await loadSecrets("thm")).toBeNull();
  const args = readFileSync(join(dir, "args.log"), "utf8");
  expect(args).toContain("store --label vpn-tui thm service vpn-tui profile thm");
  expect(args).not.toContain("secret-name");
  expect(args).not.toContain("secret-word");
});

test("id invalide, forme invalide, binaire absent", async () => {
  await expect(loadSecrets("../x")).rejects.toThrow(/invalid/);
  writeFileSync(join(dir, "store"), '{"foo":1}');
  await expect(loadSecrets("thm")).rejects.toThrow(/invalid shape/);
  writeFileSync(join(dir, "store"), "pas du json");
  await expect(loadSecrets("thm")).rejects.toThrow(/JSON/);
  process.env.VPN_TUI_SECRET_TOOL = join(dir, "absent");
  await expect(loadSecrets("thm")).rejects.toThrow("secret-tool not found: install libsecret");
});
