import { TextAttributes } from "@opentui/core";
import { theme } from "ilovetui";
import { Badge } from "ilovetui/components";
import { Show } from "solid-js";
import { useTui } from "./ctx";

const fmtRate = (n: number) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)}M` : n >= 1024 ? `${(n / 1024).toFixed(1)}K` : `${Math.round(n)}B`) + "/s";

export function Banner() {
  const { state, banner } = useTui();
  const b = banner;
  const color = () => ({ ok: theme.success, warn: theme.warning, danger: theme.error, neutral: theme.muted })[b().tone];
  const ksColor = () => (b().killswitch ? theme.success : b().tone === "neutral" ? theme.muted : theme.error);
  const scope = () => {
    const c = b().scope.cidrs;
    return c.length > 2 ? `${c.slice(0, 2).join(",")} +${c.length - 2}` : c.join(",");
  };
  return (
    <box flexShrink={0} flexDirection="row" gap={1} height={1} overflow="hidden" paddingLeft={1} paddingRight={1}>
      <Show
        when={state().daemonReachable}
        fallback={
          <box flexShrink={0}>
            {/* avant tout refresh : ni status ni erreur reçus, le daemon n'est pas encore jugé injoignable */}
            <Show when={state().status === null && state().lastError === null} fallback={<Badge label="daemon unreachable" color={theme.error} />}>
              <Badge label="connecting to daemon…" color={theme.muted} />
            </Show>
          </box>
        }
      >
        <box flexShrink={0}><Badge label={b().label} color={color()} /></box>
      </Show>
      <text fg={ksColor()} attributes={TextAttributes.BOLD} wrapMode="none" flexShrink={0}>{`KILLSWITCH ${b().killswitch ? "ON" : "OFF"}`}</text>
      <text fg={theme.text} wrapMode="none" flexShrink={0}>{`LHOST ${b().lhost ?? "-"}`}</text>
      <Show when={b().scope.warning} fallback={<Show when={scope()}><text fg={theme.text} wrapMode="none" flexShrink={0}>{`scope ${scope()}`}</text></Show>}>
        <text fg={theme.warning} wrapMode="none" flexShrink={0}>⚠ no scope</text>
      </Show>
      <Show when={b().uptime}>{(u) => <text fg={theme.muted} wrapMode="none" flexShrink={0}>{u()}</text>}</Show>
      <Show when={b().rate}>
        {(r) => <text fg={theme.muted} wrapMode="none" flexShrink={0}>{`↓${fmtRate(r().rx)} ↑${fmtRate(r().tx)}`}</text>}
      </Show>
    </box>
  );
}
