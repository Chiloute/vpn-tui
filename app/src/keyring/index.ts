import type { Secrets } from "../import";

export const keyringRef = (id: string) => `vpn-tui/${id}`;

const ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;

async function run(id: string, args: string[], stdin?: string) {
  if (!ID_RE.test(id)) throw new Error(`identifiant de profil invalide : "${id}"`);
  const bin = process.env.VPN_TUI_SECRET_TOOL || "secret-tool";
  try {
    const p = Bun.spawn([bin, ...args], {
      stdin: stdin === undefined ? "ignore" : new Blob([stdin]),
      stdout: "pipe",
      stderr: "pipe",
    });
    const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited]);
    return { out, err, code };
  } catch (e: any) {
    if (e?.code === "ENOENT") throw new Error("secret-tool introuvable : installez libsecret");
    throw e;
  }
}

export async function storeSecrets(id: string, s: Secrets): Promise<void> {
  const r = await run(id, ["store", "--label", `vpn-tui ${id}`, "service", "vpn-tui", "profile", id], JSON.stringify(s));
  if (r.code !== 0) throw new Error(`secret-tool store a échoué (${r.code}) : ${r.err.trim()}`);
}

export async function loadSecrets(id: string): Promise<Secrets | null> {
  const r = await run(id, ["lookup", "service", "vpn-tui", "profile", id]);
  if (r.code !== 0 && r.out === "") return null;
  if (r.code !== 0) throw new Error(`secret-tool lookup a échoué (${r.code})`);
  let v: any;
  try {
    v = JSON.parse(r.out);
  } catch {
    throw new Error("secret du keyring illisible (JSON invalide)");
  }
  const str = (x: unknown) => typeof x === "string" && x !== "";
  const ok =
    v && typeof v === "object" &&
    ((str(v.username) && str(v.password)) ||
      (str(v.private_key) && (v.preshared_key === undefined || str(v.preshared_key))));
  if (!ok) throw new Error("secret du keyring de forme invalide");
  return v;
}

export async function deleteSecrets(id: string): Promise<void> {
  const r = await run(id, ["clear", "service", "vpn-tui", "profile", id]);
  if (r.code !== 0) throw new Error(`secret-tool clear a échoué (${r.code}) : ${r.err.trim()}`);
}
