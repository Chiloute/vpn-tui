import { createContext, useContext } from "solid-js";
import type { Banner, State, Store } from "../store";
import type { ResolvedCommand, ViewId } from "../help";

/** Surface du store utilisée par le TUI (permet un store factice dans les tests). */
export type StoreLike = Pick<
  Store,
  "getState" | "onChange" | "start" | "stop" | "toggle" | "down" | "panicOff" | "deleteProfile" | "acceptScope" | "lhost" | "banner" | "previewImport" | "importProfile" | "createProfile" | "updateProfile"
>;

export type TuiCtx = {
  store: StoreLike;
  state: () => State;
  banner: () => Banner;
  bindings: Record<ViewId, ResolvedCommand[]>;
};

export const TuiContext = createContext<TuiCtx>();
export const useTui = (): TuiCtx => {
  const c = useContext(TuiContext);
  if (!c) throw new Error("useTui hors du Shell");
  return c;
};
