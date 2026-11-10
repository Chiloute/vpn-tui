import { renderKeysMd } from "../src/help/markdown";

await Bun.write(new URL("../../docs/keys.md", import.meta.url), renderKeysMd());
