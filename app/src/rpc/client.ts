import { createConnection } from "node:net";
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import schema from "../../../proto/rpc.schema.json" with { type: "json" };

export const DEFAULT_SOCKET = "/run/vpn-tui/vpn-tuid.sock";

/** JSON-RPC error returned by the daemon. */
export class RpcError extends Error {
  constructor(public code: number, message: string) {
    super(message);
  }
}
/** Daemon unreachable, timeout, or out-of-contract message. */
export class TransportError extends Error {}

const ajv = new Ajv2020({ allErrors: false });
addFormats(ajv);
ajv.addSchema(schema);
const ref = (def: string) => `${schema.$id}#/$defs/${def}`;
const validator = (def: string) => {
  const v = ajv.getSchema(ref(def));
  if (!v) throw new Error(`unknown schema: ${def}`);
  return v;
};
const validateRequest = validator("request");
const validateResponse = validator("response");

let nextId = 1;

export async function call(
  method: string,
  params?: unknown,
  opts: { socket?: string; timeoutMs?: number } = {},
): Promise<Record<string, unknown>> {
  const id = nextId++;
  const req: Record<string, unknown> = { jsonrpc: "2.0", id, method };
  if (params !== undefined) req.params = params;
  if (!validateRequest(req)) {
    throw new TransportError(`invalid request: ${ajv.errorsText(validateRequest.errors)}`);
  }
  const path = opts.socket ?? process.env.VPN_TUI_SOCKET ?? DEFAULT_SOCKET;
  const line = await exchange(path, JSON.stringify(req) + "\n", opts.timeoutMs ?? 5000);

  let res: any;
  try {
    res = JSON.parse(line);
  } catch {
    throw new TransportError("response is not JSON");
  }
  if (!validateResponse(res)) {
    throw new TransportError(`invalid response: ${ajv.errorsText(validateResponse.errors)}`);
  }
  if (res.error) throw new RpcError(res.error.code, res.error.message);
  const validateResult = validator(`result_${method}`);
  if (!validateResult(res.result)) {
    throw new TransportError(`invalid result: ${ajv.errorsText(validateResult.errors)}`);
  }
  return res.result;
}

/** Sends a line, returns the first line received (max 64 KiB, see contract). */
function exchange(path: string, data: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = "";
    const sock = createConnection(path);
    const fail = (msg: string) => {
      sock.destroy();
      reject(new TransportError(msg));
    };
    sock.setTimeout(timeoutMs, () => fail("timed out"));
    sock.setEncoding("utf8");
    sock.on("error", (e) => fail(`daemon unreachable (${path}): ${e.message}`));
    sock.on("connect", () => sock.write(data));
    sock.on("data", (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl >= 0) {
        sock.destroy();
        resolve(buf.slice(0, nl));
      } else if (buf.length > 65536) fail("response too large");
    });
    sock.on("close", () => fail("connection closed without a response")); // no-op if already settled
  });
}

const validateNotification = validator("event_notification");
export type RpcEvent = { time: string; profile: string | null; state: string; kind: string; detail: string };
export type SubscribeOpts = {
  socket?: string;
  onOpen?: () => void; // ack {ok:true} received
  onError?: (e: Error) => void; // transport, rejected ack or invalid notification (ignored)
  onClose?: () => void; // called once, whatever the cause
};

/** events_subscribe: ack then one `event` notification per line, on the same connection, no read timeout. */
export function subscribe(onEvent: (e: RpcEvent) => void, opts: SubscribeOpts = {}): { close(): void } {
  const path = opts.socket ?? process.env.VPN_TUI_SOCKET ?? DEFAULT_SOCKET;
  const req = { jsonrpc: "2.0", id: nextId++, method: "events_subscribe" };
  const sock = createConnection(path);
  let buf = "";
  let acked = false;
  let closed = false;
  const err = (m: string) => opts.onError?.(new TransportError(m));
  const shutdown = () => {
    if (closed) return;
    closed = true;
    sock.destroy();
    opts.onClose?.();
  };
  const fatal = (m: string) => {
    if (!closed) err(m);
    shutdown();
  };
  const line = (l: string) => {
    let msg: any;
    try {
      msg = JSON.parse(l);
    } catch {
      return err("non-JSON line ignored");
    }
    if (!acked) {
      if (!validateResponse(msg) || msg.id !== req.id) return fatal("invalid subscription response");
      if (msg.error) return fatal(`subscription refused (${msg.error.code}): ${msg.error.message}`);
      if (!validator("result_events_subscribe")(msg.result)) return fatal("invalid subscription ack");
      acked = true;
      return opts.onOpen?.();
    }
    if (!validateNotification(msg)) return err(`invalid notification ignored: ${ajv.errorsText(validateNotification.errors)}`);
    onEvent(msg.params as RpcEvent);
  };
  sock.setEncoding("utf8");
  sock.on("error", (e) => fatal(`daemon unreachable (${path}): ${e.message}`));
  sock.on("connect", () => sock.write(JSON.stringify(req) + "\n"));
  sock.on("data", (chunk: string) => {
    buf += chunk;
    let nl: number;
    while (!closed && (nl = buf.indexOf("\n")) >= 0) {
      const l = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (l.length > 65536) return fatal("line too large");
      line(l);
    }
    if (!closed && buf.length > 65536) fatal("line too large");
  });
  sock.on("close", shutdown);
  return { close: shutdown };
}
