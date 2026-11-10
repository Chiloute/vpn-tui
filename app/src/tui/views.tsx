import type { ScrollBoxRenderable } from "@opentui/core";
import { theme } from "ilovetui";
import { KeyValue, ListRow, usePane } from "ilovetui/components";
import { notify } from "ilovetui/context";
import { createMemo, createSignal, For, Show } from "solid-js";
import type { RpcEvent } from "../rpc/client";
import type { Profile, State } from "../store";
import { Confirm, Header, ViewPane, selectedId, setFormMode, setSelectedId } from "./common";
import { useTui } from "./ctx";
import { EditView } from "./edit-view";
import { ImportView } from "./import-view";
import { bindCommands, dir, registerView, setCurrentView } from "./shell";
export { loadingLabel } from "./common";

const isActive = (s: State, id: string) => s.status?.profile === id && s.status.state !== "disarmed";
const dot = (p: Profile) => (theme as unknown as Record<string, string>)[p.color.toLowerCase()] ?? theme.primary;

function Profiles() {
  const { store, state, bindings } = useTui();
  const [askDelete, setAskDelete] = createSignal(false);
  const [askScope, setAskScope] = createSignal(false);
  const profiles = () => state().profiles;
  const idx = createMemo(() => Math.max(0, profiles().findIndex((p) => p.id === selectedId())));
  const cur = () => profiles()[idx()];
  const move = (key: string) => {
    const p = profiles()[Math.min(profiles().length - 1, Math.max(0, idx() + dir(key)))];
    if (p) setSelectedId(p.id);
  };
  const withCur = (f: (p: Profile) => void) => () => { const p = cur(); if (p) f(p); };
  const wantScope = () => (state().pendingScope ? setAskScope(true) : void notify("No learned scope pending", { kind: "info" }));
  bindCommands(bindings.profiles, {
    "profiles.nav": move,
    "profiles.toggle": withCur((p) => void store.toggle(p.id)),
    "profiles.detail": withCur((p) => { setSelectedId(p.id); setCurrentView("detail"); }),
    "profiles.import": () => setCurrentView("import"),
    "profiles.new": () => { setFormMode("create"); setCurrentView("edit"); },
    "profiles.edit": withCur((p) => { setSelectedId(p.id); setFormMode("edit"); setCurrentView("edit"); }),
    "profiles.delete": withCur(() => setAskDelete(true)),
    "profiles.scope": wantScope,
  }, usePane().target);
  return (
    <>
      <Header title="Profiles" />
      <Show when={profiles().length} fallback={<text fg={theme.muted}>No profiles. Press i to import one.</text>}>
        <For each={profiles()}>
          {(p, i) => (
            <ListRow
              label={`${isActive(state(), p.id) ? "▶" : " "} ${p.name} (${p.id})`}
              selected={i() === idx()}
              bold={isActive(state(), p.id)}
              onClick={() => setSelectedId(p.id)}
              right={(tone) => (
                <>
                  <text fg={tone(theme.muted)} wrapMode="none">{p.tags.join(" ")} </text>
                  <text fg={dot(p)}>●</text>
                </>
              )}
            />
          )}
        </For>
      </Show>
      <Confirm
        open={askDelete()}
        message={`Delete profile ${cur()?.id} and its secrets?`}
        onNo={() => setAskDelete(false)}
        onYes={() => { setAskDelete(false); const p = cur(); if (p) void store.deleteProfile(p.id); }}
      />
      <Confirm
        open={askScope()}
        message={`Accept the learned scope for ${state().pendingScope?.profile} (${state().pendingScope?.added.length ?? 0} added)?`}
        onNo={() => setAskScope(false)}
        onYes={() => { setAskScope(false); void store.acceptScope(); }}
      />
    </>
  );
}

function Detail() {
  const { store, state, bindings } = useTui();
  const [askScope, setAskScope] = createSignal(false);
  const p = () => state().profiles.find((x) => x.id === selectedId());
  const pending = () => (state().pendingScope?.profile === p()?.id ? state().pendingScope : null);
  const list = (a: string[] | undefined) => (a?.length ? a.join(", ") : "none");
  const extra = (k: string) => (p() as unknown as Record<string, unknown> | undefined)?.[k] as string | undefined;
  const manual = () => p()?.scope.cidrs.filter((c) => !p()!.scope.learned.includes(c));
  bindCommands(bindings.detail, {
    "detail.scope": () => (pending() ? setAskScope(true) : void notify("No learned scope pending", { kind: "info" })),
    "detail.edit": () => { setFormMode("edit"); setCurrentView("edit"); },
    "detail.back": () => setCurrentView("profiles"),
  }, usePane().target);
  return (
    <>
      <Header title={`Detail: ${p()?.name ?? "?"}`} />
      <Show when={p()} fallback={<text fg={theme.muted}>Profile not found.</text>}>
        {(pr) => (
          <>
            <KeyValue label="Type" value={pr().type} />
            <Show when={extra("endpoint") ?? extra("remote")}>{(e) => <KeyValue label="Endpoint" value={e()} />}</Show>
            <KeyValue label="Tags" value={list(pr().tags)} />
            <KeyValue label="Scope (manual)" value={list(manual())} />
            <KeyValue label="Scope (learned)" value={list(pr().scope.learned)} />
            <KeyValue label="Exclusions" value={list(pr().scope.exclude)} />
            <KeyValue label="Kill switch" value={pr().killswitch.enabled ? `enabled · internet ${pr().killswitch.allow_internet ? "allowed" : "blocked"} · IPv6 ${pr().killswitch.block_ipv6 ? "blocked" : "allowed"}` : "disabled (scope unprotected)"} />
            <KeyValue label="DNS" value={`${list(pr().dns.servers)}${pr().dns.force ? " (forced)" : ""}`} />
          </>
        )}
      </Show>
      <Show when={pending()}>
        {(ps) => (
          <box border borderStyle={theme.borderStyle} borderColor={theme.warning} flexDirection="column" paddingLeft={1} marginTop={1} flexShrink={0}>
            <text fg={theme.warning}>Learned scope pending (s to accept)</text>
            <For each={ps().added}>{(c) => <text fg={theme.success}>{`+ ${c}`}</text>}</For>
            <For each={ps().existing}>{(c) => <text fg={theme.muted}>{`= ${c}`}</text>}</For>
          </box>
        )}
      </Show>
      <Confirm
        open={askScope()}
        message={`Accept the learned scope for ${pending()?.profile} (${pending()?.added.length ?? 0} added)?`}
        onNo={() => setAskScope(false)}
        onYes={() => { setAskScope(false); void store.acceptScope(); }}
      />
    </>
  );
}

const pad = (n: number) => String(n).padStart(2, "0");
const localTime = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(+d) ? iso : `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};
export function eventColor(kind: string): string {
  if (kind === "drop" || kind === "lock" || kind === "error") return theme.error;
  if (kind === "reconnect") return theme.warning;
  return kind === "up" ? theme.success : theme.text;
}
const line = (e: RpcEvent) => `${localTime(e.time)} ${(e.profile ?? "-").padEnd(10)} ${e.state.padEnd(12)} ${e.kind.padEnd(10)} ${e.detail}`;

function Logs() {
  const { state, bindings } = useTui();
  let box: ScrollBoxRenderable | undefined;
  bindCommands(bindings.logs, {
    "logs.nav": (k) => box?.scrollBy(dir(k)),
    "logs.page": (k) => box?.scrollBy(dir(k), "viewport"),
    "logs.back": () => setCurrentView("profiles"),
  }, usePane().target);
  return (
    <>
      <Header title="Logs (7 days)" />
      <scrollbox ref={(e: ScrollBoxRenderable) => (box = e)} flexGrow={1} scrollY scrollX={false} focusable={false} stickyScroll stickyStart="bottom">
        <For each={state().events} fallback={<text fg={theme.muted}>No events.</text>}>
          {(e) => <text flexShrink={0} fg={eventColor(e.kind)} wrapMode="none">{line(e)}</text>}
        </For>
      </scrollbox>
    </>
  );
}

const wrap = (C: () => unknown) => () => <ViewPane>{C() as never}</ViewPane>;

export function registerTuiViews(): void {
  registerView("profiles", wrap(() => <Profiles />));
  registerView("detail", wrap(() => <Detail />));
  registerView("logs", wrap(() => <Logs />));
  registerView("import", wrap(() => <ImportView />));
  registerView("edit", wrap(() => <EditView />));
}
