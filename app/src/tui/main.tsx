import "ilovetui/solid";
import { render } from "@opentui/solid";
import { loadConfig } from "../config";
import { resolveBindings } from "../help";
import { createStore } from "../store";
import { Shell } from "./shell";
import { registerTuiViews } from "./views";

export async function runTui(): Promise<void> {
  const bindings = resolveBindings(loadConfig());
  const store = createStore();
  registerTuiViews();
  void store.start(); // re-reads the daemon's real state on each launch; stop() is called by Shell on exit
  await render(() => <Shell bindings={bindings} store={store} />);
}
