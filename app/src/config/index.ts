import { loadMergedProjectConfig } from "ilovetui/project-config";
import { configureTheme } from "ilovetui";
import { configSchema, resolveBindings, type AppConfig } from "../help";
import defaultConfigPath from "../../config/default.yaml" with { type: "file" };

/** Loads defaults + ~/.config/vpn-tui/config.yaml, applies the theme, throws on key conflicts. */
export function loadConfig(): AppConfig {
  const config = loadMergedProjectConfig({ projectName: "vpn-tui", defaultConfigPath, schema: configSchema });
  resolveBindings(config);
  configureTheme(config.theme);
  return config;
}
