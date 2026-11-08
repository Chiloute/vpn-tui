import { theme } from "ilovetui";
import { usePane } from "ilovetui/components";
import { notify } from "ilovetui/context";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createSignal, For } from "solid-js";
import { createStore } from "solid-js/store";
import type { ImportPreview } from "../store";
import { Header, setSelectedId } from "./common";
import { useTui } from "./ctx";
import { activateField, createFormNav, Form, type Field } from "./form";
import { bindCommands, setCurrentView } from "./shell";

const MAX_BYTES = 1_000_000;
export const expandHome = (p: string) => (p === "~" || p.startsWith("~/") ? homedir() + p.slice(1) : p);

/** Complète `input` avec les noms du dossier correspondant (préfixe commun) ; renvoie `input` s'il n'y a rien à compléter. */
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
  try { isDir = names.length === 1 && statSync(out).isDirectory(); } catch { /* ignoré */ }
  return prefix + (isDir ? "/" : "");
}

export function ImportView() {
  const { store, bindings } = useTui();
  const [values, setValues] = createStore<Record<string, string>>({ path: "", name: "", id: "" });
  const [preview, setPreview] = createSignal<ImportPreview | null>(null);
  const [errors, setErrors] = createSignal<string[]>([]);
  let content = "";

  const set = (id: string, v: string) => {
    setValues(id, v);
    if (id === "path") setPreview(null); // l'aperçu ne vaut que pour le fichier lu
  };
  const has = () => preview() !== null;
  const fields: Field[] = [
    { kind: "text", id: "path", label: "Fichier", placeholder: "~/vpn/profil.ovpn (Tab pour compléter)" },
    { kind: "note", text: () => `Type : ${preview()!.type}`, color: theme.text, when: has },
    { kind: "note", text: () => `Serveur : ${preview()!.endpoint ?? "?"}`, color: theme.text, when: has },
    { kind: "note", text: () => `Secrets : ${preview()!.hasSecrets ? "extraits vers le keyring" : "aucun"}`, color: theme.text, when: has },
    { kind: "text", id: "name", label: "Nom", when: has },
    { kind: "text", id: "id", label: "Identifiant", when: has },
    { kind: "button", id: "go", label: "Importer", when: has },
  ];
  const nav = createFormNav(fields);
  const lines = (m: string) => m.split("\n").filter((l) => l.trim());

  function readPreview() {
    const path = expandHome(values.path!.trim());
    setPreview(null);
    if (!path) return setErrors(["Indiquez le chemin d'un fichier .ovpn ou .conf"]);
    try {
      if (statSync(path).size > MAX_BYTES) return setErrors([`Fichier trop volumineux (> ${MAX_BYTES / 1_000_000} Mo)`]);
      content = readFileSync(path, "utf8");
    } catch (e) {
      return setErrors([`Lecture impossible : ${(e as Error).message}`]);
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
    if (!pid) return setErrors(lines(store.getState().lastError ?? "Import refusé par le daemon"));
    notify(`Profil ${pid} importé`, { kind: "success" });
    setSelectedId(pid);
    setCurrentView("profiles");
  }

  bindCommands(bindings.import, {
    "import.confirm": () => (nav.cur() === "path" ? readPreview() : nav.cur() === "go" ? void doImport() : activateField(nav, values, set, () => {})),
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
    </>
  );
}
