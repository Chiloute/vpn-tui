import { TextAttributes, type InputRenderable, type TextareaRenderable, type KeyEvent, type Renderable, type ScrollBoxRenderable } from "@opentui/core";
import { presets, theme } from "ilovetui";
import { stepTabValue, Tabs, Toggle, type TabItem } from "ilovetui/components";
import { createEffect, createSignal, For, Show, untrack, type JSX } from "solid-js";

type Common = { when?: () => boolean };
/** Un champ de formulaire ; `when` masque le champ et le retire de la navigation. Les valeurs sont des chaînes ("1"/"0" pour les bascules). */
export type Field = Common &
  (
    | { kind: "text"; id: string; label: string; placeholder?: string }
    | { kind: "area"; id: string; label: string; rows?: number }
    | { kind: "secret"; id: string; label: string; placeholder?: string }
    | { kind: "toggle"; id: string; label: string }
    | { kind: "tabs" | "choice"; id: string; label: string; items: TabItem[] }
    | { kind: "color"; id: string; label: string }
    | { kind: "button"; id: string; label: string }
    | { kind: "note"; text: () => string; color?: string }
  );
type Focusable = Exclude<Field, { kind: "note" }>;
export type Values = Record<string, string>;

export const COLORS = Array.from({ length: 16 }, (_, i) => `base0${i.toString(16).toUpperCase()}`);
export const colorOf = (name: string): string => (theme as unknown as Record<string, string>)[name.toLowerCase()] ?? theme.primary;
const LABEL_W = 22;

export function createFormNav(fields: Field[]) {
  const order = () => fields.filter((f): f is Focusable => f.kind !== "note" && (f.when?.() ?? true));
  const [cur, setCur] = createSignal(order()[0]?.id ?? "");
  const field = () => order().find((f) => f.id === cur());
  const move = (d: number) => {
    const o = order();
    if (o.length) setCur(o[(Math.max(0, o.findIndex((f) => f.id === cur())) + d + o.length) % o.length]!.id);
  };
  return { cur, setCur, move, field, order };
}
export type FormNav = ReturnType<typeof createFormNav>;

/** Action de la touche Entrée selon le champ : bouton = valider, bascule/choix = changer, sinon champ suivant. */
export function activateField(nav: FormNav, values: Values, set: (id: string, v: string) => void, submit: () => void): void {
  const f = nav.field();
  if (!f) return;
  if (f.kind === "button") submit();
  else if (f.kind === "toggle") set(f.id, values[f.id] === "1" ? "0" : "1");
  else if (f.kind === "tabs" || f.kind === "choice") set(f.id, stepTabValue(f.items, values[f.id] ?? "", 1));
  else nav.move(1);
}

type Props = { fields: Field[]; nav: FormNav; values: Values; set: (id: string, v: string) => void; errors: Record<string, string | undefined> };

export function Form(props: Props) {
  const refs = new Map<string, Renderable>();
  let box: ScrollBoxRenderable | undefined;
  createEffect(() => {
    const id = props.nav.cur();
    const el = refs.get(id);
    // différé : le focus initial du ViewPane passe avant celui du champ
    if (el) queueMicrotask(() => { if (!el.isDestroyed) { el.focus(); box?.scrollChildIntoView(`f-${id}`); } });
  });
  const val = (id: string) => props.values[id] ?? "";
  const focused = (id: string) => props.nav.cur() === id;
  const reg = (id: string) => (e: Renderable) => void refs.set(id, e);
  const keys = (f: { id: string; items: TabItem[] }) => (k: KeyEvent) => {
    if (k.name === "left" || k.name === "right") props.set(f.id, stepTabValue(f.items, val(f.id), k.name === "left" ? -1 : 1));
  };

  function control(f: Focusable): JSX.Element {
    switch (f.kind) {
      case "text": {
        let el: InputRenderable | undefined;
        createEffect(() => { // valeur modifiée hors saisie (complétion de chemin)
          const v = val(f.id);
          if (el && el.value !== v) { el.value = v; el.cursorOffset = v.length; }
        });
        return <input ref={(e: InputRenderable) => { el = e; reg(f.id)(e); }} flexGrow={1} value={untrack(() => val(f.id))} placeholder={f.placeholder} onInput={(v: string) => props.set(f.id, v)} />;
      }
      case "area": {
        let el: TextareaRenderable | undefined;
        return <textarea ref={(e: TextareaRenderable) => { el = e; reg(f.id)(e); }} flexGrow={1} height={f.rows ?? 3} initialValue={untrack(() => val(f.id))} onContentChange={() => el && props.set(f.id, el.plainText)} />;
      }
      case "secret": // l'input OpenTUI ne sait pas masquer : champ maison qui n'affiche que des •
        return (
          <box
            id={`mask-${f.id}`} ref={reg(f.id)} focusable flexGrow={1} height={1}
            backgroundColor={focused(f.id) ? presets.input.focusedBackgroundColor : presets.input.backgroundColor}
            onKeyDown={(k: KeyEvent) => {
              if (k.ctrl || k.meta) return;
              if (k.name === "backspace") props.set(f.id, val(f.id).slice(0, -1));
              else if (k.sequence.length === 1 && k.sequence >= " ") props.set(f.id, val(f.id) + k.sequence);
            }}
            onPaste={(e: { bytes: Uint8Array; preventDefault(): void }) => {
              e.preventDefault();
              props.set(f.id, val(f.id) + new TextDecoder().decode(e.bytes).replace(/\r/g, ""));
            }}
          >
            <text wrapMode="none" fg={val(f.id) ? theme.text : theme.muted}>
              {val(f.id) ? `${"•".repeat(Math.min(val(f.id).length, 24))} (${val(f.id).length} car.)` : (f.placeholder ?? "(masqué)")}{focused(f.id) ? "▏" : ""}
            </text>
          </box>
        );
      case "toggle": {
        const flip = () => props.set(f.id, val(f.id) === "1" ? "0" : "1");
        return (
          <box ref={reg(f.id)} focusable height={1} flexDirection="row" onKeyDown={(k: KeyEvent) => k.name === "space" && flip()}>
            <Toggle on={val(f.id) === "1"} onToggle={flip} />
          </box>
        );
      }
      case "tabs":
        return (
          <box ref={reg(f.id)} focusable flexDirection="column" onKeyDown={keys(f)}>
            <Tabs items={f.items} value={val(f.id)} onChange={(v) => props.set(f.id, v)} focused={focused(f.id)} />
          </box>
        );
      case "choice":
        return (
          <box ref={reg(f.id)} focusable height={1} onKeyDown={keys(f)}>
            <text wrapMode="none" fg={focused(f.id) ? theme.primary : theme.text}>
              {f.items.map((i) => `${i.value === val(f.id) ? "(•)" : "( )"} ${i.label}`).join("  ")}
            </text>
          </box>
        );
      case "color":
        return (
          <box flexDirection="row" gap={1}>
            <select
              ref={reg(f.id)} height={4} flexGrow={1} showDescription={false}
              options={COLORS.map((c) => ({ name: c, description: "", value: c }))}
              selectedIndex={Math.max(0, COLORS.indexOf(untrack(() => val(f.id))))}
              onChange={(_i: number, o: { value?: string } | null) => o?.value && props.set(f.id, o.value)}
            />
            <text fg={colorOf(val(f.id))}>●</text>
          </box>
        );
      case "button":
        return (
          <box ref={reg(f.id)} focusable height={1}>
            <text attributes={TextAttributes.BOLD} fg={focused(f.id) ? theme.primary : theme.text}>{`[ ${f.label} ]`}</text>
          </box>
        );
    }
  }

  return (
    <scrollbox ref={(e: ScrollBoxRenderable) => (box = e)} flexGrow={1} scrollY scrollX={false} focusable={false}>
      <For each={props.fields}>
        {(f) => (
          <Show when={f.when?.() ?? true}>
            {f.kind === "note" ? (
              <text flexShrink={0} fg={f.color ?? theme.muted}>{f.text()}</text>
            ) : (
              <box id={`f-${f.id}`} flexShrink={0} flexDirection="column">
                <box flexDirection="row" flexShrink={0}>
                  <box width={LABEL_W} flexShrink={0}>
                    <text wrapMode="none" fg={focused(f.id) ? theme.primary : theme.muted}>{`${focused(f.id) ? "›" : " "} ${f.kind === "button" ? "" : f.label}`}</text>
                  </box>
                  <box flexGrow={1}>{control(f)}</box>
                </box>
                <Show when={props.errors[f.id]}>{(e) => <text flexShrink={0} fg={theme.error} marginLeft={LABEL_W}>{e()}</text>}</Show>
              </box>
            )}
          </Show>
        )}
      </For>
    </scrollbox>
  );
}
