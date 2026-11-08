import { createSolidTransformPlugin } from "@opentui/solid/bun-plugin";

const outfile = process.argv[2] ?? "dist/vpn-tui";
const arch = process.arch === "arm64" ? "arm64" : "x64";
const otherArch = arch === "arm64" ? "x64" : "arm64";

const result = await Bun.build({
  entrypoints: ["./src/index.ts"],
  plugins: [createSolidTransformPlugin()],
  external: ["@opentui/core-*-musl", "@opentui/core-darwin-*", "@opentui/core-win32-*", `@opentui/core-linux-${otherArch}`],
  compile: { target: `bun-linux-${arch}`, outfile, autoloadBunfig: false },
});
if (!result.success) {
  for (const l of result.logs) console.error(l);
  process.exit(1);
}
