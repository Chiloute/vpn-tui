import { theme } from "ilovetui";
import { usePane } from "ilovetui/components";
import { notify } from "ilovetui/context";
import { createSignal, For, Show, type Accessor } from "solid-js";
import { createStore } from "solid-js/store";
import type { Profile } from "../store";
import { Confirm, formMode, Header, selectedId, setSelectedId } from "./common";
import { useTui } from "./ctx";
import { activateField, createFormNav, Form, type Field, type Values } from "./form";
import { bindCommands, setCurrentView } from "./shell";
import { buildForm, checkEdit, type Errors } from "./validate";

const same = (a: string[], b: string[]) => a.length === b.length && a.every((x, i) => x === b[i]);

/** Shared create / edit wiring: navigation, confirmed cancel if modified, per-field and daemon errors. */
function useFormView(o: { fields: Field[]; values: Values; set: (id: string, v: string) => void; submit: () => void; leave: () => void }) {
  const { bindings } = useTui();
  const nav = createFormNav(o.fields);
  const initial = JSON.stringify(o.values);
  const [askDiscard, setAskDiscard] = createSignal(false);
  bindCommands(bindings.edit, {
    "edit.next": () => nav.move(1),
    "edit.prev": () => nav.move(-1),
    "edit.submit": () => activateField(nav, o.values, o.set, o.submit),
    "edit.save": o.submit,
    "edit.cancel": () => (JSON.stringify(o.values) === initial ? o.leave() : setAskDiscard(true)),
  }, usePane().target);
  const discard = (
    <Confirm open={askDiscard()} message="Discard unsaved changes?" onNo={() => setAskDiscard(false)} onYes={() => { setAskDiscard(false); o.leave(); }} />
  );
  return { nav, discard };
}

function ErrorLines(props: { lines: Accessor<string[]> }) {
  return <For each={props.lines()}>{(l) => <text flexShrink={0} fg={theme.error}>{l}</text>}</For>;
}

const split = (m: string) => m.split("\n").filter((l) => l.trim());

function CreateForm() {
  const { store } = useTui();
  const [values, setValues] = createStore<Values>({ type: "openvpn", proto: "udp", port: "1194" });
  const [errors, setErrors] = createSignal<Errors>({});
  const [daemonErr, setDaemonErr] = createSignal<string[]>([]);
  const ovpn = () => values.type === "openvpn";
  const wg = () => values.type === "wireguard";
  const proto = [{ value: "udp", label: "udp" }, { value: "tcp", label: "tcp" }];
  const fields: Field[] = [
    { kind: "tabs", id: "type", label: "Type", items: [{ value: "openvpn", label: "OpenVPN" }, { value: "wireguard", label: "WireGuard" }] },
    { kind: "text", id: "name", label: "Name" },
    { kind: "text", id: "id", label: "Id (opt.)", placeholder: "derived from the name" },
    { kind: "text", id: "remote", label: "Server", when: ovpn },
    { kind: "text", id: "port", label: "Port", when: ovpn },
    { kind: "choice", id: "proto", label: "Protocol", items: proto, when: ovpn },
    { kind: "area", id: "ca", label: "ca (PEM)", when: ovpn },
    { kind: "area", id: "cert", label: "cert (PEM)", when: ovpn },
    { kind: "secret", id: "key", label: "key (PEM)", placeholder: "paste the PEM block (masked)", when: ovpn },
    { kind: "secret", id: "tlsCrypt", label: "tls-crypt (opt.)", placeholder: "paste the block (masked)", when: ovpn },
    { kind: "secret", id: "tlsAuth", label: "tls-auth (opt.)", placeholder: "paste the block (masked)", when: ovpn },
    { kind: "text", id: "username", label: "Username (opt.)", when: ovpn },
    { kind: "secret", id: "password", label: "Password (opt.)", when: ovpn },
    { kind: "text", id: "address", label: "Address", placeholder: "10.8.0.2/32", when: wg },
    { kind: "text", id: "dns", label: "DNS (opt.)", placeholder: "10.8.0.1", when: wg },
    { kind: "secret", id: "privateKey", label: "Private key", when: wg },
    { kind: "text", id: "publicKey", label: "Peer public key", when: wg },
    { kind: "text", id: "endpoint", label: "Endpoint", placeholder: "vpn.example.org:51820", when: wg },
    { kind: "text", id: "allowedIPs", label: "Allowed IPs", placeholder: "10.10.0.0/16, 10.129.0.0/16", when: wg },
    { kind: "secret", id: "presharedKey", label: "Preshared (opt.)", when: wg },
    { kind: "text", id: "keepalive", label: "Keepalive (opt.)", placeholder: "25", when: wg },
    { kind: "button", id: "go", label: "Create profile" },
  ];
  const set = (id: string, v: string) => { setValues(id, v); if (errors()[id]) setErrors({ ...errors(), [id]: "" }); };
  async function submit() {
    if (store.getState().busy) return;
    setDaemonErr([]);
    const r = buildForm({ ...values });
    setErrors(r.errors);
    if (!r.form) {
      const first = view.nav.order().find((f) => r.errors[f.id]);
      if (first) view.nav.setCur(first.id);
      return;
    }
    const pid = await store.createProfile(r.form);
    if (!pid) return setDaemonErr(split(store.getState().lastError ?? "Creation rejected by the daemon"));
    notify(`Profile ${pid} created`, { kind: "success" });
    setSelectedId(pid);
    setCurrentView("profiles");
  }
  const view = useFormView({ fields, values, set, submit: () => void submit(), leave: () => setCurrentView("profiles") });
  return (
    <>
      <Header title="New profile" />
      <ErrorLines lines={daemonErr} />
      <Form fields={fields} nav={view.nav} values={values} set={set} errors={errors()} />
      {view.discard}
    </>
  );
}

type Ks = { enabled: boolean; allow_internet: boolean; block_ipv6: boolean };
// The daemon returns an object; the TS type in store/banner.ts declares a boolean.
const ksOf = (p: Profile): Ks => {
  const k = p.killswitch as unknown;
  return typeof k === "object" && k ? (k as Ks) : { enabled: !!k, allow_internet: false, block_ipv6: false };
};
const flag = (b: boolean) => (b ? "1" : "0");

function EditForm() {
  const { store, state } = useTui();
  const p = state().profiles.find((x) => x.id === selectedId());
  if (!p) return <><Header title="Edit" /><text fg={theme.muted}>Profile not found.</text></>;
  const ks = ksOf(p);
  const [values, setValues] = createStore<Values>({
    name: p.name, tags: p.tags.join(", "), color: p.color,
    cidrs: p.scope.cidrs.join("\n"), exclude: p.scope.exclude.join("\n"),
    ks_enabled: flag(ks.enabled), ks_allow: flag(ks.allow_internet), ks_ipv6: flag(ks.block_ipv6),
    dns: p.dns.servers.join(", "), force: flag(p.dns.force),
  });
  const [errors, setErrors] = createSignal<Errors>({});
  const [daemonErr, setDaemonErr] = createSignal<string[]>([]);
  const list = (a: string[]) => (a.length ? a.join(", ") : "none");
  const manual = p.scope.cidrs.filter((c) => !p.scope.learned.includes(c));
  const fields: Field[] = [
    { kind: "note", text: () => `Type ${p.type} and configuration cannot be changed: re-import the file to change them.` },
    { kind: "text", id: "name", label: "Name" },
    { kind: "text", id: "tags", label: "Tags", placeholder: "comma-separated" },
    { kind: "color", id: "color", label: "Color" },
    { kind: "area", id: "cidrs", label: "Scope cidrs", rows: 3 },
    { kind: "note", text: () => `manual: ${list(manual)} | learned: ${list(p.scope.learned)}` },
    { kind: "area", id: "exclude", label: "Scope exclude", rows: 2 },
    { kind: "toggle", id: "ks_enabled", label: "Kill switch" },
    { kind: "note", text: () => "Kill switch disabled: the scope will not be protected.", color: theme.warning, when: () => values.ks_enabled !== "1" },
    { kind: "toggle", id: "ks_allow", label: "allow_internet" },
    { kind: "toggle", id: "ks_ipv6", label: "block_ipv6" },
    { kind: "text", id: "dns", label: "DNS servers", placeholder: "comma-separated" },
    { kind: "toggle", id: "force", label: "DNS force" },
    { kind: "button", id: "go", label: "Save" },
  ];
  const set = (id: string, v: string) => { setValues(id, v); if (errors()[id]) setErrors({ ...errors(), [id]: "" }); };
  async function submit() {
    if (store.getState().busy) return;
    setDaemonErr([]);
    const c = checkEdit({ ...values });
    setErrors(c.errors);
    const bad = view.nav.order().find((f) => c.errors[f.id]);
    if (bad) return view.nav.setCur(bad.id);
    const patch: Record<string, unknown> = {};
    if (values.name!.trim() !== p!.name) patch.name = values.name!.trim();
    if (!same(c.tags, p!.tags)) patch.tags = c.tags;
    if (values.color !== p!.color) patch.color = values.color;
    if (!same(c.cidrs, p!.scope.cidrs) || !same(c.exclude, p!.scope.exclude)) patch.scope = { cidrs: c.cidrs, exclude: c.exclude, learned: p!.scope.learned };
    if (values.ks_enabled !== flag(ks.enabled) || values.ks_allow !== flag(ks.allow_internet) || values.ks_ipv6 !== flag(ks.block_ipv6)) {
      patch.killswitch = { enabled: values.ks_enabled === "1", allow_internet: values.ks_allow === "1", block_ipv6: values.ks_ipv6 === "1" };
    }
    if (!same(c.servers, p!.dns.servers) || values.force !== flag(p!.dns.force)) patch.dns = { servers: c.servers, force: values.force === "1" };
    if (Object.keys(patch).length) {
      await store.updateProfile(p!.id, patch);
      const err = store.getState().lastError;
      if (err) return setDaemonErr(split(err));
      notify(`Profile ${p!.id} updated`, { kind: "success" });
    }
    setCurrentView("detail");
  }
  const view = useFormView({ fields, values, set, submit: () => void submit(), leave: () => setCurrentView("detail") });
  return (
    <>
      <Header title={`Edit: ${p.name}`} />
      <ErrorLines lines={daemonErr} />
      <Form fields={fields} nav={view.nav} values={values} set={set} errors={errors()} />
      {view.discard}
    </>
  );
}

export function EditView() {
  return <Show when={formMode() === "create"} fallback={<EditForm />}><CreateForm /></Show>;
}
