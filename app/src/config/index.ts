import { loadMergedProjectConfig } from "ilovetui/project-config";
import { configureTheme } from "ilovetui";
import { configSchema, resolveBindings, type AppConfig } from "../help";
import defaultConfigPath from "../../config/default.yaml" with { type: "file" };

/** Charge défauts + ~/.config/vpn-tui/config.yaml, applique le thème, lève si conflit de touches. */
export function loadConfig(): AppConfig {
  const config = loadMergedProjectConfig({ projectName: "vpn-tui", defaultConfigPath, schema: configSchema });
  resolveBindings(config);
  configureTheme(config.theme);
  return config;
}
