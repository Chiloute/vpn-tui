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
  void store.start(); // relit l'état réel du daemon à chaque lancement ; stop() est appelé par Shell à la sortie
  await render(() => <Shell bindings={bindings} store={store} />);
}
