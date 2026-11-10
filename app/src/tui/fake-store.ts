import { mock } from "bun:test";
import { previewImport, type Banner, type ProfileForm, type State } from "../store";
import type { StoreLike } from "./ctx";

export const emptyBanner: Banner = { label: "○ DISCONNECTED", tone: "neutral", killswitch: false, lhost: null, scope: { cidrs: [], warning: null }, uptime: null, rate: null };

/** Fake store: same signatures, state editable via set(). */
export function fakeStore(init: Partial<State> = {}, banner: Banner = emptyBanner) {
  let state: State = { status: null, profiles: [], events: [], pendingScope: null, busy: null, daemonReachable: true, lastError: null, ...init };
  let b = banner;
  const ls = new Set<(s: State) => void>();
  const store = {
    getState: () => state,
    onChange: (l: (s: State) => void) => (ls.add(l), () => void ls.delete(l)),
    start: mock(async () => {}),
    stop: mock(() => {}),
    toggle: mock(async (_id: string) => {}),
    down: mock(async () => {}),
    panicOff: mock(async () => {}),
    deleteProfile: mock(async (_id: string) => {}),
    acceptScope: mock(async () => {}),
    previewImport,
    importProfile: mock(async (i: { id?: string; name?: string }): Promise<string | undefined> => i.id ?? i.name),
    createProfile: mock(async (f: ProfileForm): Promise<string | undefined> => f.id ?? f.name),
    updateProfile: mock(async (_id: string, _patch: Record<string, unknown>): Promise<void> => {}),
    lhost: () => b.lhost,
    banner: () => b,
    set(p: Partial<State>, nb?: Banner) {
      state = { ...state, ...p };
      if (nb) b = nb;
      for (const l of ls) l(state);
    },
  };
  return store satisfies StoreLike & { set: unknown };
}
