import { expect, test } from "bun:test";
import { detectType, extractSecrets, slugify } from ".";

const K1 = "A".repeat(43) + "=";
const K2 = "B".repeat(43) + "=";
const K3 = "C".repeat(43) + "=";

const ovpn = (block: string) => `client
dev tun
remote 10.0.0.1 1194
auth-user-pass
${block}
<ca>
CERT
</ca>
`;

test("openvpn: extraction and block removal", () => {
  const src = ovpn("<auth-user-pass>\n00000000000000000000dead  \n0000000000000000000000000000beef\n</auth-user-pass>");
  const r = extractSecrets("openvpn", src);
  expect(r.secrets).toEqual({ username: "00000000000000000000dead", password: "0000000000000000000000000000beef" });
  expect(r.content).not.toContain("dead");
  expect(r.content).not.toContain("beef");
  expect(r.content).not.toContain("<auth-user-pass>");
  expect(r.content).toContain("auth-user-pass\n");
  expect(r.content).toContain("<ca>");
});

test("openvpn: errors and missing block", () => {
  expect(extractSecrets("openvpn", "client\n").secrets).toBeNull();
  expect(() => extractSecrets("openvpn", "auth-user-pass creds.txt\n")).toThrow(/not supported/);
  expect(() => extractSecrets("openvpn", ovpn("<auth-user-pass>\nonly\n</auth-user-pass>"))).toThrow(/malformed/);
  expect(() => extractSecrets("openvpn", ovpn("<auth-user-pass>\na\nb\nc\n</auth-user-pass>"))).toThrow(/malformed/);
  expect(() => extractSecrets("openvpn", ovpn("<auth-user-pass>\na\nb\n"))).toThrow(/unclosed/);
});

const wg = (psk?: string, extraPeer = "") => `[Interface]
PrivateKey = ${K1}
Address = 10.0.0.2/32

[Peer]
PublicKey = ${K3}
${psk ? `PresharedKey = ${psk}\n` : ""}Endpoint = 1.2.3.4:51820
${extraPeer}`;

test("wireguard: with and without PSK", () => {
  let r = extractSecrets("wireguard", wg());
  expect(r.secrets).toEqual({ private_key: K1 });
  expect(r.content).toBe(wg().replace(K1, "@keyring"));
  r = extractSecrets("wireguard", wg(K2));
  expect(r.secrets).toEqual({ private_key: K1, preshared_key: K2 });
  expect(r.content).not.toContain(K1);
  expect(r.content).not.toContain(K2);
  expect(r.content).toContain("PresharedKey = @keyring");
  expect(r.content).toContain(K3); // PublicKey unchanged
});

test("wireguard: errors", () => {
  expect(() => extractSecrets("wireguard", wg().replace(/PrivateKey.*\n/, ""))).toThrow(/missing/);
  expect(() => extractSecrets("wireguard", wg().replace(K1, "court"))).toThrow(/invalid/);
  expect(() => extractSecrets("wireguard", wg(K2, `[Peer]\nPresharedKey = ${K3}\n`))).toThrow(/multiple/);
  expect(extractSecrets("wireguard", wg(K2, `[Peer]\nPresharedKey = ${K2}\n`)).secrets).toBeTruthy();
});

test("detectType", () => {
  expect(detectType("x", "a.ovpn")).toBe("openvpn");
  expect(detectType("[Interface]\nPrivateKey=x", "a.conf")).toBe("wireguard");
  expect(detectType("[Interface]\n")).toBe("wireguard");
  expect(detectType("client\nremote a 1")).toBe("openvpn");
  expect(() => detectType("nothing", "a.conf")).toThrow();
  expect(() => detectType("nothing")).toThrow();
});

test("slugify", () => {
  expect(slugify("THM Room_1")).toBe("thm-room-1");
  expect(slugify("  Été -- Vpn ")).toBe("ete-vpn");
  expect(slugify("a".repeat(50))).toBe("a".repeat(32));
  expect(() => slugify("***")).toThrow();
});
