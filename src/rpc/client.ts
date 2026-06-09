import { OctraRpcError } from "../core/errors.js";

interface RpcRequest {
  jsonrpc: "2.0";
  id: number;
  method: string;
  params: unknown[];
}

interface RpcResponse<T> {
  jsonrpc: "2.0";
  id: number;
  result?: T;
  error?: { code: number; message: string; data?: unknown };
}

export interface OctraClientOptions {
  timeoutMs?: number;
  retries?: number;
}

export class OctraClient {
  readonly endpoint: string;
  private _id = 0;
  private readonly _timeoutMs: number;
  private readonly _retries: number;

  constructor(endpoint: string, opts: OctraClientOptions = {}) {
    this.endpoint = endpoint.replace(/\/$/, "");
    this._timeoutMs = opts.timeoutMs ?? 30_000;
    this._retries = opts.retries ?? 0;
  }

  async call<T = unknown>(method: string, params: unknown[] = []): Promise<T> {
    const id = ++this._id;
    const body: RpcRequest = { jsonrpc: "2.0", id, method, params };

    let lastError: Error | undefined;
    for (let attempt = 0; attempt <= this._retries; attempt++) {
      let res: Response;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this._timeoutMs);
        try {
          res = await globalThis.fetch(this.endpoint + "/rpc", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: controller.signal,
          });
        } finally {
          clearTimeout(timer);
        }
      } catch (err) {
        // Network/timeout error — retryable
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < this._retries) continue;
        break;
      }

      if (!res.ok) {
        // HTTP transport error — retryable
        lastError = new OctraRpcError(res.status, `HTTP ${res.status} ${res.statusText}`);
        if (attempt < this._retries) continue;
        break;
      }

      const json = (await res.json()) as RpcResponse<T>;

      if (json.error) {
        // RPC application error — not retryable
        throw new OctraRpcError(json.error.code, json.error.message, json.error.data);
      }

      if (json.result === undefined) {
        throw new OctraRpcError(-32603, "RPC response missing result field");
      }

      return json.result as T;
    }

    throw lastError ?? new Error("Unknown RPC error");
  }
}
