/* HTTP client for docs/API.md: XEdDSA request signing, unidentified sends, and
   the Transport abstraction (WebSocket in production, a fake in tests). */

import type { ConnectionState, EnvelopeWire, PreKeyBundleWire } from "../types";
import { b64Encode, nowSeconds, sha256Hex, toArrayBuffer, utf8Encode } from "./util";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface RequestSigner {
  username: string;
  deviceId: number;
  /** XEdDSA over the utf-8 signing string; returns the 64-byte signature. */
  sign: (message: Uint8Array) => Promise<Uint8Array>;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export const EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** The exact string that gets signed (API.md "Identity and authentication"). */
export function signingString(method: string, path: string, ts: string, bodyHashHex: string): string {
  return `${method.toUpperCase()}\n${path}\n${ts}\n${bodyHashHex}`;
}

export async function bodyHash(body?: Uint8Array | ArrayBuffer | string | null): Promise<string> {
  if (body === undefined || body === null) return EMPTY_BODY_SHA256;
  const bytes = typeof body === "string" ? utf8Encode(body) : body;
  return sha256Hex(bytes);
}

export async function buildAuthorization(
  signer: RequestSigner,
  method: string,
  path: string,
  body?: Uint8Array | ArrayBuffer | string | null,
  ts: string = String(nowSeconds()),
): Promise<{ header: string; ts: string; sig: string; signed: string }> {
  const signed = signingString(method, path, ts, await bodyHash(body));
  const sig = b64Encode(await signer.sign(utf8Encode(signed)));
  return { header: `Signal ${signer.username}:${signer.deviceId}:${ts}:${sig}`, ts, sig, signed };
}

export interface OutgoingMessage {
  destinationDeviceId: number;
  type: number;
  content: string;
}

export interface RegisterBody {
  username: string;
  inviteCode: string;
  identityKey: string;
  registrationId: number;
  deliveryToken: string;
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  oneTimePreKeys: Array<{ keyId: number; publicKey: string }>;
  /* Post-quantum half (docs/POSTQUANTUM.md). Optional at the API level but sent by every
     current client; all-or-nothing (the server 400s a partial upgrade). */
  pqIdentityKey?: string;
  pqSignedPreKey?: { keyId: number; publicKey: string; signature: string; pqSignature: string };
  pqOneTimePreKeys?: Array<{ keyId: number; publicKey: string }>;
}

export interface PushSubscriptionWire {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

export interface ApiClientOptions {
  baseUrl: string;
  fetch?: FetchLike;
}

interface RequestOptions {
  body?: unknown;                 // JSON-encoded unless `raw`
  raw?: Uint8Array | ArrayBuffer; // octet-stream body
  auth?: boolean;                 // default true
  unidentifiedToken?: string;     // Unidentified-Access instead of Authorization
}

export class ApiClient {
  readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private signer: RequestSigner | null = null;

  constructor(opts: ApiClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    const f = opts.fetch ?? (globalThis.fetch as FetchLike | undefined);
    if (!f) throw new Error("fetch is not available");
    this.fetchImpl = (input, init) => f(input, init);
  }

  setSigner(s: RequestSigner | null): void {
    this.signer = s;
  }

  getSigner(): RequestSigner | null {
    return this.signer;
  }

  /** Path without query string, as signed. */
  private pathOf(path: string): string {
    const q = path.indexOf("?");
    return q === -1 ? path : path.slice(0, q);
  }

  async request(method: string, path: string, opts: RequestOptions = {}): Promise<Response> {
    const headers: Record<string, string> = {};
    let body: string | ArrayBuffer | undefined;
    if (opts.raw !== undefined) {
      body = toArrayBuffer(opts.raw);
      headers["Content-Type"] = "application/octet-stream";
    } else if (opts.body !== undefined) {
      body = JSON.stringify(opts.body);
      headers["Content-Type"] = "application/json";
    }
    if (opts.unidentifiedToken !== undefined) {
      headers["Unidentified-Access"] = opts.unidentifiedToken;
    } else if (opts.auth !== false) {
      if (!this.signer) throw new ApiError(401, "unauthenticated", "no identity to sign with");
      const a = await buildAuthorization(this.signer, method, this.pathOf(path), body);
      headers.Authorization = a.header;
    }
    let res: Response;
    try {
      res = await this.fetchImpl(this.baseUrl + path, { method, headers, body });
    } catch (e) {
      throw new ApiError(0, "network", (e as Error).message || "network error");
    }
    if (!res.ok) {
      let code = `http_${res.status}`;
      let message = res.statusText || code;
      try {
        const j = (await res.json()) as { error?: string; message?: string };
        if (j && typeof j.error === "string") code = j.error;
        if (j && typeof j.message === "string") message = j.message;
      } catch {
        /* non-JSON error body */
      }
      throw new ApiError(res.status, code, message);
    }
    return res;
  }

  private async json<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
    const res = await this.request(method, path, opts);
    return (await res.json()) as T;
  }

  /* ----- endpoints ----- */

  register(body: RegisterBody): Promise<{ username: string; deviceId: number }> {
    return this.json("POST", "/v1/register", { body });
  }

  getBundle(username: string): Promise<PreKeyBundleWire> {
    return this.json("GET", `/v1/keys/${encodeURIComponent(username)}`);
  }

  putKeys(body: {
    signedPreKey?: { keyId: number; publicKey: string; signature: string };
    oneTimePreKeys?: Array<{ keyId: number; publicKey: string }>;
    pqSignedPreKey?: { keyId: number; publicKey: string; signature: string; pqSignature: string };
    pqOneTimePreKeys?: Array<{ keyId: number; publicKey: string }>;
  }): Promise<{ oneTimePreKeyCount: number; pqOneTimePreKeyCount?: number }> {
    return this.json("PUT", "/v1/keys", { body });
  }

  keysCount(): Promise<{ oneTimePreKeyCount: number; pqOneTimePreKeyCount?: number }> {
    return this.json("GET", "/v1/keys/count");
  }

  putProfile(deliveryToken: string): Promise<unknown> {
    return this.json("PUT", "/v1/profile", { body: { deliveryToken } });
  }

  /* No timestamp is sent. When a message was written travels inside the
     ciphertext, where only the recipient can read it; putting it in the
     request body as well would leak a plaintext clock to the server and to
     anything watching the connection. */
  sendMessages(
    username: string,
    messages: OutgoingMessage[],
    unidentifiedToken?: string,
  ): Promise<{ needsSync: boolean }> {
    return this.json("POST", `/v1/messages/${encodeURIComponent(username)}`, {
      body: { messages },
      unidentifiedToken,
    });
  }

  drain(): Promise<{ envelopes: EnvelopeWire[]; more: boolean }> {
    return this.json("GET", "/v1/messages");
  }

  async ack(id: string): Promise<void> {
    await this.request("DELETE", `/v1/messages/${encodeURIComponent(id)}`);
  }

  uploadAttachment(ciphertext: Uint8Array): Promise<{ id: string }> {
    return this.json("POST", "/v1/attachments", { raw: ciphertext });
  }

  async downloadAttachment(id: string): Promise<Uint8Array> {
    const res = await this.request("GET", `/v1/attachments/${encodeURIComponent(id)}`, { auth: false });
    return new Uint8Array(await res.arrayBuffer());
  }

  mintInvite(): Promise<{ code: string; expiresAt: number }> {
    return this.json("POST", "/v1/invites");
  }

  putPush(sub: PushSubscriptionWire): Promise<unknown> {
    return this.json("PUT", "/v1/push", { body: sub });
  }

  async deletePush(): Promise<void> {
    await this.request("DELETE", "/v1/push");
  }

  /** Optional endpoint; returns null when the server does not offer it. */
  async getVapidPublicKey(): Promise<string | null> {
    try {
      const j = await this.json<{ publicKey?: string; vapidPublicKey?: string }>("GET", "/v1/push/vapid", { auth: false });
      return j.publicKey ?? j.vapidPublicKey ?? null;
    } catch (e) {
      if (e instanceof ApiError && e.status !== 0) return null;
      throw e;
    }
  }

  async health(): Promise<boolean> {
    try {
      const j = await this.json<{ ok?: boolean }>("GET", "/v1/health", { auth: false });
      return j.ok === true;
    } catch {
      return false;
    }
  }

  /** Query parameters for the WebSocket handshake (GET /v1/ws, empty body). */
  async wsAuthParams(): Promise<{ u: string; d: string; ts: string; sig: string }> {
    if (!this.signer) throw new ApiError(401, "unauthenticated", "no identity to sign with");
    const a = await buildAuthorization(this.signer, "GET", "/v1/ws");
    return { u: this.signer.username, d: String(this.signer.deviceId), ts: a.ts, sig: a.sig };
  }
}

/* ---------- transport ---------- */

export interface TransportAuth {
  username: string;
  deviceId: number;
  /** Signs GET /v1/ws with an empty body hash and returns the query values. */
  params: () => Promise<{ u: string; d: string; ts: string; sig: string }>;
}

export interface TransportHandlers {
  /** Resolve once the envelope is durably processed; the transport then acks it. Reject to leave it queued. */
  onEnvelope: (env: EnvelopeWire) => Promise<void>;
  onState: (state: ConnectionState) => void;
  /** The server flushed its backlog (WebSocket "queue-empty"). */
  onQueueEmpty?: () => void;
}

export interface Transport {
  connect(auth: TransportAuth, handlers: TransportHandlers): void;
  disconnect(): void;
  /** Acknowledge an envelope over the live connection; returns false if not connected (caller falls back to HTTP). */
  ack(id: string): boolean;
  isConnected(): boolean;
}

export interface WebSocketTransportOptions {
  baseUrl: string;
  WebSocketImpl?: typeof WebSocket;
  minBackoffMs?: number;
  maxBackoffMs?: number;
  pingIntervalMs?: number;
}

/** Real transport: `wss://host/v1/ws?u=&d=&ts=&sig=` with exponential backoff reconnect. */
export class WebSocketTransport implements Transport {
  private ws: WebSocket | null = null;
  private auth: TransportAuth | null = null;
  private handlers: TransportHandlers | null = null;
  private attempts = 0;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private stopped = true;
  private chain: Promise<void> = Promise.resolve();
  private readonly wsUrl: string;
  private readonly WS: typeof WebSocket | undefined;
  private readonly minBackoff: number;
  private readonly maxBackoff: number;
  private readonly pingInterval: number;

  constructor(opts: WebSocketTransportOptions) {
    this.wsUrl = opts.baseUrl.replace(/\/+$/, "").replace(/^http/i, "ws") + "/v1/ws";
    this.WS = opts.WebSocketImpl ?? (globalThis as { WebSocket?: typeof WebSocket }).WebSocket;
    this.minBackoff = opts.minBackoffMs ?? 1000;
    this.maxBackoff = opts.maxBackoffMs ?? 30_000;
    this.pingInterval = opts.pingIntervalMs ?? 25_000;
  }

  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === 1;
  }

  connect(auth: TransportAuth, handlers: TransportHandlers): void {
    this.auth = auth;
    this.handlers = handlers;
    this.stopped = false;
    this.attempts = 0;
    void this.open();
  }

  disconnect(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = null;
    this.stopPing();
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    }
    this.handlers?.onState("offline");
  }

  ack(id: string): boolean {
    if (!this.isConnected() || !this.ws) return false;
    try {
      this.ws.send(JSON.stringify({ type: "ack", id }));
      return true;
    } catch {
      return false;
    }
  }

  private async open(): Promise<void> {
    if (this.stopped || !this.auth || !this.handlers) return;
    if (!this.WS) {
      this.handlers.onState("offline");
      return;
    }
    this.handlers.onState("connecting");
    let url: string;
    try {
      const p = await this.auth.params();
      url = `${this.wsUrl}?u=${encodeURIComponent(p.u)}&d=${encodeURIComponent(p.d)}&ts=${encodeURIComponent(p.ts)}&sig=${encodeURIComponent(p.sig)}`;
    } catch {
      this.scheduleReconnect();
      return;
    }
    if (this.stopped) return;
    let ws: WebSocket;
    try {
      ws = new this.WS(url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      if (this.ws !== ws) return;
      this.attempts = 0;
      this.handlers?.onState("online");
      this.startPing();
    };
    ws.onmessage = (ev: MessageEvent) => {
      if (this.ws !== ws) return;
      this.handleFrame(ws, typeof ev.data === "string" ? ev.data : "");
    };
    ws.onclose = () => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.stopPing();
      this.handlers?.onState("offline");
      this.scheduleReconnect();
    };
    ws.onerror = () => {
      /* onclose follows */
    };
  }

  private handleFrame(ws: WebSocket, data: string): void {
    let frame: { type?: string; envelope?: EnvelopeWire };
    try {
      frame = JSON.parse(data) as typeof frame;
    } catch {
      return;
    }
    if (frame.type === "envelope" && frame.envelope) {
      const env = frame.envelope;
      // Process strictly in order; ack after the handler resolves.
      this.chain = this.chain
        .then(() => this.handlers?.onEnvelope(env))
        .then(() => {
          if (this.ws === ws && ws.readyState === 1) ws.send(JSON.stringify({ type: "ack", id: env.id }));
        })
        .catch(() => {
          /* left queued for redelivery */
        });
    } else if (frame.type === "queue-empty") {
      this.chain = this.chain.then(() => this.handlers?.onQueueEmpty?.());
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer) return;
    const base = Math.min(this.maxBackoff, this.minBackoff * 2 ** Math.min(this.attempts, 10));
    const delay = Math.round(base / 2 + Math.random() * (base / 2));
    this.attempts++;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.open();
    }, delay);
  }

  private startPing(): void {
    this.stopPing();
    this.pingTimer = setInterval(() => {
      if (this.isConnected()) {
        try {
          this.ws?.send(JSON.stringify({ type: "ping" }));
        } catch {
          /* ignore */
        }
      }
    }, this.pingInterval);
  }

  private stopPing(): void {
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = null;
  }
}
