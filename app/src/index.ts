#!/usr/bin/env bun
import { main } from "./cli";

process.exit(
  await main(process.argv.slice(2), {
    out: (s) => console.log(s),
    err: (s) => console.error(s),
  }),
);
