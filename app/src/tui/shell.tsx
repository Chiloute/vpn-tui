import { CliRenderEvents, EditBufferRenderable, InputRenderable, TextareaRenderable, TextAttributes, type BoxRenderable, type Renderable, type ScrollBoxRenderable } from "@opentui/core";
import { Dynamic, useRenderer, useTerminalDimensions } from "@opentui/solid";
import { notify } from "ilovetui/context";
import { MinSizeGuard, Modal } from "ilovetui/components";
import { NotificationHost } from "ilovetui/components";
import { HelpBar } from "ilovetui/components/help";
import { KeymapProvider, useBindings } from "ilovetui/keymap";
import { createEffect, createMemo, createSignal, on, onCleanup, onMount, Show, type Accessor, type Component } from "solid-js";
import { killswitch, prettyKey, views, type ResolvedCommand, type ViewId } from "../help";
import type { RpcEvent } from "../rpc/client";
import { Banner } from "./banner";
import { TuiContext, useTui, type StoreLike } from "./ctx";

const registry = new Map<ViewId, Component>();
const [currentView, setCurrentView] = createSignal<ViewId>("profiles");
export { currentView, setCurrentView };

/** Registers a view's component; `id` is a key of the help table. */
export function registerView(id: ViewId, component: Component): void {
  registry.set(id, component);
}

/** True if `key` should go to the focused field (typing) rather than to the command. */
export function keyGoesToField(r: Renderable | null, key: string): boolean {
  if (!r) return false;
  const keys = key.split(",").map((k) => k.trim());
  const typing = r instanceof EditBufferRenderable || r.id.startsWith("mask-");
  if (typing && keys.some((k) => /^(shift\+)?.$/.test(k) || k === "space")) return true;
  return r instanceof TextareaRenderable && !(r instanceof InputRenderable) && keys.includes("return"); // newline
}

/**
 * Registers via useBindings the table commands that have a handler.
 * `target`: layer limited to this renderable (e.g. `usePane().target`); handlers receive the pressed key name.
 * Typing keys (letters, ?, !…) are suspended while a text field has focus.
 */
export function bindCommands(
  cmds: ResolvedCommand[],
  handlers: Record<string, (key: string) => void>,
  target?: Accessor<Renderable | undefined>,
): void {
  const renderer = useRenderer();
  const active = cmds.filter((c) => handlers[c.name]);
  useBindings(() => ({
    ...(target ? { target } : {}),
    commands: active.map((c) => ({
      name: c.name, desc: c.desc, shortHelp: c.shortHelp === true,
      enabled: () => !keyGoesToField(renderer.currentFocusedRenderable, c.key),
      run: (ctx: { event: { name: string } }) => handlers[c.name]!(ctx.event.name),
    })),
    bindings: active.map((c) => ({ key: c.key, cmd: c.name })),
  }));
}

const PRESS: Record<string, number> = { up: -1, k: -1, down: 1, j: 1, pageup: -1, pagedown: 1 };
export const dir = (key: string) => PRESS[key] ?? 0;

function HelpModal(props: { open: boolean; onDismiss: () => void; bindings: ResolvedCommand[] }) {
  const dims = useTerminalDimensions();
  let box: ScrollBoxRenderable | undefined;
  const bold = TextAttributes.BOLD;
  const v = () => views[currentView()];
  // Usable Modal height: height - 4 (margin) - 4 (border + padding)
  const h = () => Math.max(1, dims().height - 8);
  const { bindings } = useTui();
  const own = bindings.help;
  const key = (n: string) => own.find((c) => c.name === n)!.key;
  return (
    <Modal
      open={props.open}
      onDismiss={props.onDismiss}
      width={80}
      commands={[
        { name: "help.scroll", desc: "scroll", run: (ctx) => void box?.scrollBy(dir(ctx.event.name)) },
        { name: "help.page", desc: "page", run: (ctx) => void box?.scrollBy(dir(ctx.event.name), "viewport") },
      ]}
      bindings={[{ key: key("help.scroll"), cmd: "help.scroll" }, { key: key("help.page"), cmd: "help.page" }]}
    >
      <scrollbox ref={(e: ScrollBoxRenderable) => (box = e)} maxHeight={h()} flexShrink={1} scrollY scrollX={false} focusable={false}>
        <text flexShrink={0} attributes={bold}>{v().title}</text>
        <text flexShrink={0}>{[v().role, ...v().actions, ...v().warnings.map((w) => `Warning: ${w}`)].join("\n")}</text>
        <text flexShrink={0}> </text>
        <text flexShrink={0}>{props.bindings.map((c) => `${prettyKey(c.key).padEnd(14)}${c.desc}`).join("\n")}</text>
        <text flexShrink={0}> </text>
        <text flexShrink={0} attributes={bold}>{killswitch.title}</text>
        <text flexShrink={0}>
          {[killswitch.intro, ...killswitch.states.map((s) => `${s.label}: ${s.desc}`), killswitch.panicOff].join("\n")}
        </text>
      </scrollbox>
    </Modal>
  );
}

function PanicModal(props: { open: boolean; onDismiss: () => void }) {
  const { store } = useTui();
  let input: Renderable | undefined;
  const [value, setValue] = createSignal("");
  const submit = () => {
    if (value().trim().toLowerCase() !== "yes") return notify("Type \"yes\" to confirm panic-off", { kind: "warning" });
    props.onDismiss();
    void store.panicOff();
  };
  createEffect(() => props.open && setValue(""));
  return (
    <Modal open={props.open} onDismiss={props.onDismiss} width={70} accentColor="red" onOpen={() => queueMicrotask(() => setTimeout(() => input?.focus()))}>
      <text flexShrink={0} attributes={TextAttributes.BOLD}>Panic-off</text>
      <text flexShrink={0}>
        {"Removes the kill switch nftables table and drops the tunnel: traffic flows outside the VPN, unprotected.\n" +
          "See the Kill switch section in the help (?).\nLast resort (root): vpn-tuid --panic-off, or nft delete table inet vpn_tui\nType yes then Enter to confirm, Esc to cancel."}
      </text>
      <input ref={(e: Renderable) => (input = e)} value={value()} onInput={setValue} onSubmit={submit} placeholder="yes" />
    </Modal>
  );
}

const NOTIFY_KINDS = new Set(["drop", "lock", "scope_learned"]);

function Body() {
  const renderer = useRenderer();
  const { store, state, bindings } = useTui();
  const [helpOpen, setHelpOpen] = createSignal(false);
  const [panicOpen, setPanicOpen] = createSignal(false);
  const [root, setRoot] = createSignal<BoxRenderable>();
  // Global commands are limited to the root: modals (Portal) take focus and cut them off.
  bindCommands(bindings.profiles.filter((c) => c.scope === "global"), {
    "global.help": () => setHelpOpen((o) => !o),
    "global.quit": () => renderer.destroy(),
    "global.panic": () => setPanicOpen(true),
    "global.logs": () => setCurrentView("logs"),
    "global.copyLhost": () => {
      const ip = store.lhost();
      if (!ip) return notify("No LHOST to copy", { kind: "error" });
      if (renderer.copyToClipboardOSC52(ip)) notify(`LHOST copied: ${ip}`, { kind: "success" });
      else notify("Cannot copy: terminal lacks OSC52", { kind: "error" });
    },
  }, root);
  onMount(() => root()?.focus());

  createEffect(on(() => state().lastError, (e) => e && notify(e, { kind: "error", duration: 6000 }), { defer: true }));
  const startedAt = Date.now();
  const seen = new WeakSet<RpcEvent>();
  createEffect(() => {
    for (const e of state().events) {
      if (seen.has(e)) continue;
      seen.add(e);
      if (!NOTIFY_KINDS.has(e.kind) || Date.parse(e.time) < startedAt - 2000) continue;
      notify(`${e.profile ?? "-"}: ${e.kind} ${e.detail}`.trim(), { kind: e.kind === "scope_learned" ? "info" : "error" });
    }
  });

  return (
    <box ref={setRoot} focusable position="absolute" top={0} left={0} width="100%" height="100%" flexDirection="column">
      <Banner />
      <box flexGrow={1} flexDirection="column">
        <Show when={registry.get(currentView())}>{(c) => <Dynamic component={c()} />}</Show>
      </box>
      <HelpBar />
      <NotificationHost />
      <HelpModal open={helpOpen()} onDismiss={() => setHelpOpen(false)} bindings={bindings[currentView()]} />
      <PanicModal open={panicOpen()} onDismiss={() => setPanicOpen(false)} />
    </box>
  );
}

export function Shell(props: { bindings: Record<ViewId, ResolvedCommand[]>; store: StoreLike }) {
  const renderer = useRenderer();
  const [state, setState] = createSignal(props.store.getState());
  const [tick, setTick] = createSignal(0);
  onCleanup(props.store.onChange(setState));
  const timer = setInterval(() => setTick((t) => t + 1), 1000);
  onCleanup(() => clearInterval(timer));
  renderer.once(CliRenderEvents.DESTROY, () => props.store.stop());
  const banner = createMemo(() => (state(), tick(), props.store.banner()));
  return (
    <TuiContext.Provider value={{ store: props.store, state, banner, bindings: props.bindings }}>
      <MinSizeGuard>
        <KeymapProvider>
          <Body />
        </KeymapProvider>
      </MinSizeGuard>
    </TuiContext.Provider>
  );
}
