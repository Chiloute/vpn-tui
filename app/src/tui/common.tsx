import { theme } from "ilovetui";
import { Modal, Pane, type PaneHandle } from "ilovetui/components";
import { SectionHeader } from "ilovetui/components/section-header";
import { createSignal, onMount, type ParentProps } from "solid-js";
import type { State } from "../store";
import { useTui } from "./ctx";

export const [selectedId, setSelectedId] = createSignal<string | null>(null);
/** "edit" view: create a profile (n) or edit the selected profile (e). */
export const [formMode, setFormMode] = createSignal<"create" | "edit">("edit");

/** SectionHeader spinner label depending on busy / reconnecting, null if nothing in progress. */
export function loadingLabel(s: State): string | null {
  switch (s.busy) {
    case "up": return "Connecting…";
    case "down": return "Disconnecting…";
    case "reconnect": return "Switching…";
    case "panic": return "Panic-off…";
    case "import": return "Saving…";
  }
  const r = s.status;
  return r?.state === "reconnecting" ? `Reconnecting ${r.reconnect.attempt}/${r.reconnect.max}…` : null;
}

export function Header(props: { title: string }) {
  const { state } = useTui();
  return <SectionHeader title={props.title} loading={loadingLabel(state()) !== null} loadingLabel={loadingLabel(state()) ?? undefined} />;
}

export function ViewPane(props: ParentProps) {
  let h!: PaneHandle;
  onMount(() => h.focus());
  return <Pane handle={(x) => (h = x)} focusable flexGrow={1} flexDirection="column" paddingLeft={1} paddingRight={1}>{props.children}</Pane>;
}

export function Confirm(props: { open: boolean; message: string; onYes: () => void; onNo: () => void }) {
  const { bindings } = useTui();
  const key = (n: string) => bindings.confirm.find((c) => c.name === n)!.key;
  return (
    <Modal
      open={props.open}
      onDismiss={props.onNo}
      dismissKey={false}
      width={60}
      commands={[
        { name: "confirm.yes", desc: "yes", run: props.onYes },
        { name: "confirm.no", desc: "no", run: props.onNo },
      ]}
      bindings={[{ key: key("confirm.yes"), cmd: "confirm.yes" }, { key: key("confirm.no"), cmd: "confirm.no" }]}
    >
      <text>{props.message}</text>
      <text fg={theme.muted}>{`(${key("confirm.yes")}/${key("confirm.no").split(",")[0]})`}</text>
    </Modal>
  );
}
