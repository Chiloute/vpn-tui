import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export function lhostPath(): string {
  return join(process.env.XDG_CACHE_HOME || join(homedir(), ".cache"), "vpn-tui", "lhost");
}

/** Writes "IP\n" (or empty) atomically, only if the content changes. Never throws. */
export function writeLhost(ip: string | null, warn: (s: string) => void = console.error): void {
  const path = lhostPath();
  const content = ip ? `${ip}\n` : "";
  try {
    try {
      if (readFileSync(path, "utf8") === content) return;
    } catch {}
    mkdirSync(join(path, ".."), { recursive: true, mode: 0o700 });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, content);
    renameSync(tmp, path);
  } catch (e) {
    warn(`Warning: cannot write ${path}: ${(e as Error).message}`);
  }
}
