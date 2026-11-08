#!/usr/bin/env bun
import { main } from "./cli";

if (process.argv.length <= 2) {
  try {
    await (await import("./tui/main")).runTui();
  } catch (e) {
    console.error(e instanceof Error ? e.message : e);
    process.exit(1);
  }
} else {
  process.exit(
    await main(process.argv.slice(2), {
      out: (s) => console.log(s),
      err: (s) => console.error(s),
    }),
  );
}
