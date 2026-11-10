import { z } from "zod";
import { keybindsSchema } from "ilovetui/project-config";
import { ThemeConfigSchema } from "ilovetui";
import { globalCommands, views, type Cmd, type ViewId } from "./table";

export * from "./table";

export const commandNames = [...globalCommands, ...Object.values(views).flatMap((v) => v.commands)].map((c) => c.name);

export const configSchema = z
  .object({ keybinds: keybindsSchema(commandNames, true), theme: ThemeConfigSchema.optional() })
  .strict();
export type AppConfig = z.infer<typeof configSchema>;

export type ResolvedCommand = Cmd & { key: string; scope: "view" | "global" };

const keysOf = (key: string) => key.split(",").map((k) => k.trim());

/** For each view: its commands then the global commands, with the effective key. */
export function resolveBindings(config: Pick<AppConfig, "keybinds">): Record<ViewId, ResolvedCommand[]> {
  const key = (c: Cmd) => (config.keybinds as Record<string, string>)[c.name] ?? c.defaultKey;
  const out = {} as Record<ViewId, ResolvedCommand[]>;
  for (const view of Object.values(views)) {
    const seen = new Map<string, string>();
    out[view.id] = [
      ...view.commands.map((c) => ({ ...c, key: key(c), scope: "view" as const })),
      ...globalCommands.map((c) => ({ ...c, key: key(c), scope: "global" as const })),
    ];
    for (const c of out[view.id]) {
      for (const k of keysOf(c.key)) {
        const prev = seen.get(k);
        if (prev) throw new Error(`Key conflict in view "${view.id}": "${k}" is used by ${prev} and ${c.name}`);
        seen.set(k, c.name);
      }
    }
  }
  return out;
}
