import { theme } from "ilovetui";
import { ListRow, usePane } from "ilovetui/components";
import { notify } from "ilovetui/context";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createMemo, createSignal, For, Show } from "solid-js";
import { createStore } from "solid-js/store";
import type { ImportPreview } from "../store";
import { Header, setSelectedId } from "./common";
import { useTui } from "./ctx";
import { activateField, createFormNav, Form, type Field } from "./form";
import { bindCommands, dir, setCurrentView } from "./shell";

const MAX_BYTES = 1_000_000;
export const expandHome = (p: string) => (p === "~" || p.startsWith("~/") ? homedir() + p.slice(1) : p);

/** Completes `input` with the matching directory's names (common prefix); returns `input` if there is nothing to complete. */
export function completePath(input: string): string {
  const full = expandHome(input);
  const dir = full.endsWith("/") ? full : dirname(full);
  const base = full.endsWith("/") ? "" : basename(full);
  let names: string[];
  try {
    names = readdirSync(dir).filter((n) => n.startsWith(base));
  } catch {
    return input;
  }
  if (!names.length) return input;
  let common = names[0]!;
  for (const n of names) while (!n.startsWith(common)) common = common.slice(0, -1);
  const out = join(dir, common);
  const prefix = input.startsWith("~") ? "~" + out.slice(homedir().length) : input.startsWith("./") ? "./" + out : out;
  let isDir = false;
  try { isDir = names.length === 1 && statSync(out).isDirectory(); } catch { /* ignored */ }
  return prefix + (isDir ? "/" : "");
}

export type Entry = { name: string; dir: boolean };
const ROWS = 8;

/** Explorer listing for `input` (empty = home): entries of its directory whose names start with its last component, directories first. */
export function listEntries(input: string): { dir: string; entries: Entry[] } {
  const full = expandHome(input || "~/");
  const dir = full.endsWith("/") ? full : dirname(full);
  const base = full.endsWith("/") ? "" : basename(full);
  let entries: Entry[];
  try {
    entries = readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.name.startsWith(base) && (base.startsWith(".") || !d.name.startsWith(".")))
      .map((d) => ({ name: d.name, dir: d.isDirectory() })) // shortcut: a symlink to a directory lists as a file, follow it if someone asks
      .sort((a, b) => Number(b.dir) - Number(a.dir) || a.name.localeCompare(b.name));
  } catch {
    return { dir, entries: [] };
  }
  if (base === "" && dir !== "/") entries.unshift({ name: "..", dir: true });
  return { dir, entries };
}

/** The input to show once `e` (from listEntries(input)) is picked: keeps the ~ or ./ style, adds / to a directory. */
export function pickEntry(input: string, e: Entry): string {
  const { dir } = listEntries(input);
  const out = e.name === ".." ? dirname(dir) : join(dir, e.name);
  const home = homedir();
  const shown = (input === "" || input.startsWith("~")) && (out === home || out.startsWith(home + "/")) ? "~" + out.slice(home.length)
    : input.startsWith("./") ? "./" + out : out;
  return shown + (e.dir && !shown.endsWith("/") ? "/" : "");
}

export function ImportView() {
  const { store, bindings } = useTui();
  const [values, setValues] = createStore<Record<string, string>>({ path: "", name: "", id: "" });
  const [preview, setPreview] = createSignal<ImportPreview | null>(null);
  const [errors, setErrors] = createSignal<string[]>([]);
  const [cursor, setCursor] = createSignal(0);
  let content = "";

  const set = (id: string, v: string) => {
    setValues(id, v);
    if (id === "path") { setPreview(null); setCursor(0); } // the preview only applies to the file read
  };
  const entries = createMemo(() => listEntries(values.path!));
  const start = () => Math.max(0, Math.min(cursor() - Math.floor(ROWS / 2), entries().entries.length - ROWS));
  const visible = () => entries().entries.slice(start(), start() + ROWS);
  const has = () => preview() !== null;
  const fields: Field[] = [
    { kind: "text", id: "path", label: "File", placeholder: "~/vpn/profile.ovpn (Tab to complete)" },
    { kind: "note", text: () => `Type: ${preview()!.type}`, color: theme.text, when: has },
    { kind: "note", text: () => `Server: ${preview()!.endpoint ?? "?"}`, color: theme.text, when: has },
    { kind: "note", text: () => `Secrets: ${preview()!.hasSecrets ? "moved to the keyring" : "none"}`, color: theme.text, when: has },
    { kind: "text", id: "name", label: "Name", when: has },
    { kind: "text", id: "id", label: "Id", when: has },
    { kind: "button", id: "go", label: "Import", when: has },
  ];
  const nav = createFormNav(fields);
  const lines = (m: string) => m.split("\n").filter((l) => l.trim());

  function confirmPath() {
    const e = entries().entries[cursor()];
    if (!e) return readPreview();
    const next = pickEntry(values.path!, e);
    set("path", next);
    if (!e.dir) readPreview();
  }

  function readPreview() {
    const path = expandHome(values.path!.trim());
    setPreview(null);
    if (!path) return setErrors(["Enter the path of an .ovpn or .conf file"]);
    try {
      if (statSync(path).size > MAX_BYTES) return setErrors([`File too large (> ${MAX_BYTES / 1_000_000} MB)`]);
      content = readFileSync(path, "utf8");
    } catch (e) {
      return setErrors([`Cannot read file: ${(e as Error).message}`]);
    }
    const r = store.previewImport({ filename: path, content });
    if ("error" in r) return setErrors(lines(r.error));
    setErrors([]);
    setPreview(r.preview);
    setValues({ name: r.preview.name, id: r.preview.id });
    nav.setCur("name");
  }

  async function doImport() {
    const p = preview();
    if (!p || store.getState().busy) return;
    const input = { filename: expandHome(values.path!.trim()), content, name: values.name!.trim() || undefined, id: values.id!.trim() || undefined };
    const local = store.previewImport(input);
    if ("error" in local) return setErrors(lines(local.error));
    setErrors([]);
    const pid = await store.importProfile(input);
    if (!pid) return setErrors(lines(store.getState().lastError ?? "Import rejected by the daemon"));
    notify(`Profile ${pid} imported`, { kind: "success" });
    setSelectedId(pid);
    setCurrentView("profiles");
  }

  bindCommands(bindings.import, {
    "import.confirm": () => (nav.cur() === "path" ? confirmPath() : nav.cur() === "go" ? void doImport() : activateField(nav, values, set, () => {})),
    "import.nav": (key) => {
      if (nav.cur() !== "path") return nav.move(dir(key));
      setCursor(Math.max(0, Math.min(entries().entries.length - 1, cursor() + dir(key))));
    },
    "import.next": () => {
      if (nav.cur() === "path") {
        const c = completePath(values.path!);
        if (c !== values.path) return set("path", c);
      }
      nav.move(1);
    },
    "import.prev": () => nav.move(-1),
    "import.cancel": () => setCurrentView("profiles"),
  }, usePane().target);

  return (
    <>
      <Header title="Import" />
      <For each={errors()}>{(l) => <text flexShrink={0} fg={theme.error}>{l}</text>}</For>
      <Form fields={fields} nav={nav} values={values} set={set} errors={{}} />
      <Show when={nav.cur() === "path" && !has()}>
        <For each={visible()}>{(e, i) => <ListRow label={e.dir ? e.name + "/" : e.name} selected={start() + i() === cursor()} onClick={() => { setCursor(start() + i()); confirmPath(); }} />}</For>
      </Show>
    </>
  );
}
