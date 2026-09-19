/* An in-memory server implementing docs/API.md closely enough for the core to be tested
   against it: request signing (XEdDSA), prekey bundles that consume one-time prekeys,
   identified and unidentified (sealed) delivery, a per-user envelope queue, attachments,
   invites and push subscriptions. Exposes its internals so tests can assert on what the
   "server" actually saw (envelope types, presence of `from`, queue contents). */

import type { EnvelopeWire, PreKeyBundleWire } from "../../src/types";
import type { FetchLike, PushSubscriptionWire, RegisterBody, Transport, TransportAuth, TransportHandlers } from "../../src/core/api";
import { xeddsaVerify } from "../../src/core/signal";
import { b64Decode, b64Encode, hexEncode, randomBytes, sha256Hex, utf8Decode, utf8Encode } from "../../src/core/util";

interface MailboxRecord {
  username: string;
  identityKey: Uint8Array;
  registrationId: number;
  deliveryToken: string;
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  oneTimePreKeys: Map<number, string>;
  queue: EnvelopeWire[];
  pushSubscription?: PushSubscriptionWire;
  /* Post-quantum half (docs/POSTQUANTUM.md / docs/API.md); absent for a pre-PQ account. */
  pqIdentityKey?: string;
  pqSignedPreKey?: { keyId: number; publicKey: string; signature: string; pqSignature: string };
  pqOneTimePreKeys: Map<number, string>;
}

interface InviteRecord {
  code: string;
  creator: string;
  expiresAt: number;
  used: boolean;
}

class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

function headerOf(headers: HeadersInit | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const lower = name.toLowerCase();
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (Array.isArray(headers)) {
    for (const [k, v] of headers) if (k.toLowerCase() === lower) return v;
    return undefined;
  }
  for (const [k, v] of Object.entries(headers)) if (k.toLowerCase() === lower) return v;
  return undefined;
}

function bodyToBytes(body: BodyInit | null | undefined): Uint8Array {
  if (body === undefined || body === null) return new Uint8Array();
  if (typeof body === "string") return utf8Encode(body);
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  throw new Error("fakeServer: unsupported request body type");
}

function json(status: number, obj: unknown): Response {
  return new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
}

function errResponse(status: number, code: string, message: string): Response {
  return json(status, { error: code, message });
}

const AUTH_RE = /^Signal ([a-z0-9_]{3,32}):(\d+):(\d+):(.+)$/;

export class FakeTransport implements Transport {
  private handlers: TransportHandlers | null = null;
  private auth: TransportAuth | null = null;
  private connected = false;

  constructor(private readonly server: FakeServer) {}

  isConnected(): boolean {
    return this.connected;
  }

  connect(auth: TransportAuth, handlers: TransportHandlers): void {
    this.auth = auth;
    this.handlers = handlers;
    this.connected = true;
    this.server.registerLive(auth.username, this);
    handlers.onState("online");
    void this.flushBacklog();
  }

  disconnect(): void {
    if (this.auth) this.server.unregisterLive(this.auth.username, this);
    this.connected = false;
    this.handlers?.onState("offline");
  }

  ack(id: string): boolean {
    if (!this.connected || !this.auth) return false;
    this.server.ack(this.auth.username, id);
    return true;
  }

  /** Called by the server for a live push; resolves once the handler has durably processed
   *  (and this then acks) the envelope, mirroring WebSocketTransport's real behaviour. */
  async push(env: EnvelopeWire): Promise<void> {
    if (!this.handlers || !this.auth) return;
    await this.handlers.onEnvelope(env);
    this.server.ack(this.auth.username, env.id);
  }

  /** Test-only: deliver one envelope straight to this connection, bypassing the server's
   *  normal oldest-first backlog order. Used to simulate out-of-order transport delivery. */
  async simulate(env: EnvelopeWire): Promise<void> {
    await this.push(env);
  }

  private async flushBacklog(): Promise<void> {
    if (!this.auth) return;
    const backlog = this.server.drain(this.auth.username);
    for (const env of backlog) {
      if (!this.connected) return;
      await this.push(env);
    }
    this.handlers?.onQueueEmpty?.();
  }
}

export class FakeServer {
  readonly bootstrapInvite = "BOOTSTRAP";
  private readonly mailboxes = new Map<string, MailboxRecord>();
  private readonly invites = new Map<string, InviteRecord>();
  private readonly attachments = new Map<string, Uint8Array>();
  private readonly live = new Map<string, FakeTransport>();
  private readonly sentTo = new Map<string, EnvelopeWire[]>();
  private counter = 0;

  readonly fetch: FetchLike = (input, init) => this.handle(String(input), init);

  transport(): FakeTransport {
    return new FakeTransport(this);
  }

  /* ---------- test-facing introspection ---------- */

  mailboxOf(username: string): Readonly<MailboxRecord> | undefined {
    return this.mailboxes.get(username);
  }

  /** Envelopes still queued (unacked) for a user, oldest first. */
  queueOf(username: string): EnvelopeWire[] {
    return [...(this.mailboxes.get(username)?.queue ?? [])];
  }

  /** Every envelope ever routed to a user, in send order, regardless of ack state. */
  sentEnvelopesTo(username: string): EnvelopeWire[] {
    return [...(this.sentTo.get(username) ?? [])];
  }

  attachmentBytes(id: string): Uint8Array | undefined {
    return this.attachments.get(id);
  }

  /** Test-only: simulate a server that strips (or never had) the post-quantum half of a
   *  bundle, e.g. to exercise downgrade-detection. */
  stripPqKeys(username: string): void {
    const mb = this.mailboxes.get(username);
    if (!mb) return;
    mb.pqIdentityKey = undefined;
    mb.pqSignedPreKey = undefined;
    mb.pqOneTimePreKeys = new Map();
  }

  /* ---------- used by FakeTransport ---------- */

  registerLive(username: string, t: FakeTransport): void {
    this.live.set(username, t);
  }

  unregisterLive(username: string, t: FakeTransport): void {
    if (this.live.get(username) === t) this.live.delete(username);
  }

  ack(username: string, envelopeId: string): void {
    const mb = this.mailboxes.get(username);
    if (!mb) return;
    mb.queue = mb.queue.filter((e) => e.id !== envelopeId);
  }

  drain(username: string): EnvelopeWire[] {
    const mb = this.mailboxes.get(username);
    return mb ? [...mb.queue] : [];
  }

  /* ---------- internals ---------- */

  /* Mirrors the real server: a sequence number with random padding and no
     clock anywhere in it. Putting Date.now() here, as an earlier version did,
     would let these tests pass while the real wire format leaked a timestamp. */
  private nextEnvelopeId(): string {
    this.counter += 1;
    const random = Array.from({ length: 8 }, () => Math.floor(Math.random() * 36).toString(36)).join("");
    return `${String(this.counter).padStart(10, "0")}${random}`;
  }

  private async deliver(to: string, from: { username: string; deviceId: number } | undefined, type: number, content: string): Promise<void> {
    const mb = this.mailboxes.get(to);
    if (!mb) throw new HttpError(404, "not_found", "unknown recipient");
    if (content.length > 64 * 1024) throw new HttpError(413, "too_large", "message too large");
    const env: EnvelopeWire = { id: this.nextEnvelopeId(), from, type, content };
    mb.queue.push(env);
    if (mb.queue.length > 1000) mb.queue.shift();
    const log = this.sentTo.get(to) ?? [];
    log.push(env);
    this.sentTo.set(to, log);
    const liveT = this.live.get(to);
    if (liveT) await liveT.push(env);
  }

  private async verifyAuth(method: string, path: string, headers: HeadersInit | undefined, bodyBytes: Uint8Array): Promise<MailboxRecord> {
    const header = headerOf(headers, "authorization");
    if (!header) throw new HttpError(401, "unauthenticated", "missing Authorization");
    const m = AUTH_RE.exec(header);
    if (!m) throw new HttpError(401, "unauthenticated", "malformed Authorization header");
    const [, username, , tsStr, sigB64] = m as unknown as [string, string, string, string, string];
    const mb = this.mailboxes.get(username);
    if (!mb) throw new HttpError(401, "unauthenticated", "unknown user");
    const ts = parseInt(tsStr, 10);
    if (!Number.isFinite(ts) || Math.abs(Math.floor(Date.now() / 1000) - ts) > 300) {
      throw new HttpError(401, "unauthenticated", "stale timestamp");
    }
    const bodyHashHex = await sha256Hex(bodyBytes);
    const message = `${method.toUpperCase()}\n${path}\n${tsStr}\n${bodyHashHex}`;
    const ok = await xeddsaVerify(mb.identityKey, utf8Encode(message), b64Decode(sigB64));
    if (!ok) throw new HttpError(401, "unauthenticated", "bad signature");
    return mb;
  }

  private async handle(input: string, init?: RequestInit): Promise<Response> {
    const url = new URL(input);
    const pathname = url.pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    const bodyBytes = bodyToBytes(init?.body as BodyInit | null | undefined);
    try {
      // ---- unauthenticated ----
      if (method === "GET" && pathname === "/v1/health") return json(200, { ok: true });

      if (method === "GET" && pathname.startsWith("/v1/attachments/")) {
        const id = decodeURIComponent(pathname.slice("/v1/attachments/".length));
        const blob = this.attachments.get(id);
        if (!blob) return errResponse(404, "not_found", "unknown attachment");
        const buf = blob.buffer.slice(blob.byteOffset, blob.byteOffset + blob.byteLength) as ArrayBuffer;
        return new Response(buf, { status: 200, headers: { "content-type": "application/octet-stream" } });
      }

      if (method === "POST" && pathname === "/v1/register") {
        return await this.handleRegister(headers(init), bodyBytes);
      }

      // ---- identified or unidentified ----
      if (method === "POST" && pathname.startsWith("/v1/messages/")) {
        return await this.handleSend(pathname, headers(init), bodyBytes);
      }

      // ---- everything below requires Authorization ----
      if (method === "GET" && pathname === "/v1/keys/count") {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        return json(200, { oneTimePreKeyCount: mb.oneTimePreKeys.size, pqOneTimePreKeyCount: mb.pqOneTimePreKeys.size });
      }
      if (method === "GET" && pathname.startsWith("/v1/keys/")) {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        void mb;
        const target = this.mailboxes.get(decodeURIComponent(pathname.slice("/v1/keys/".length)));
        if (!target) return errResponse(404, "not_found", "unknown user");
        let preKey: { keyId: number; publicKey: string } | undefined;
        const first = target.oneTimePreKeys.entries().next();
        if (!first.done) {
          const [keyId, publicKey] = first.value;
          target.oneTimePreKeys.delete(keyId);
          preKey = { keyId, publicKey };
        }
        // One ML-KEM one-time prekey consumed per fetch, independently of the classical one
        // (docs/API.md GET /v1/keys/:username).
        let pqPreKey: { keyId: number; publicKey: string } | undefined;
        const pqFirst = target.pqOneTimePreKeys.entries().next();
        if (!pqFirst.done) {
          const [keyId, publicKey] = pqFirst.value;
          target.pqOneTimePreKeys.delete(keyId);
          pqPreKey = { keyId, publicKey };
        }
        const bundle: PreKeyBundleWire = {
          username: target.username,
          deviceId: 1,
          identityKey: b64Encode(target.identityKey),
          registrationId: target.registrationId,
          signedPreKey: target.signedPreKey,
          preKey,
        };
        if (target.pqIdentityKey && target.pqSignedPreKey) {
          bundle.pqIdentityKey = target.pqIdentityKey;
          bundle.pqSignedPreKey = target.pqSignedPreKey;
          bundle.pqPreKey = pqPreKey;
        }
        return json(200, bundle);
      }
      if (method === "PUT" && pathname === "/v1/keys") {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        const body = JSON.parse(utf8Decode(bodyBytes)) as {
          signedPreKey?: { keyId: number; publicKey: string; signature: string };
          oneTimePreKeys?: Array<{ keyId: number; publicKey: string }>;
          pqSignedPreKey?: { keyId: number; publicKey: string; signature: string; pqSignature: string };
          pqOneTimePreKeys?: Array<{ keyId: number; publicKey: string }>;
        };
        if (body.signedPreKey) mb.signedPreKey = body.signedPreKey;
        if (body.oneTimePreKeys) {
          if (mb.oneTimePreKeys.size + body.oneTimePreKeys.length > 200) return errResponse(400, "bad_request", "too many prekeys");
          for (const k of body.oneTimePreKeys) mb.oneTimePreKeys.set(k.keyId, k.publicKey);
        }
        if (body.pqSignedPreKey) mb.pqSignedPreKey = body.pqSignedPreKey;
        if (body.pqOneTimePreKeys) {
          if (mb.pqOneTimePreKeys.size + body.pqOneTimePreKeys.length > 200) return errResponse(400, "bad_request", "too many post-quantum prekeys");
          for (const k of body.pqOneTimePreKeys) mb.pqOneTimePreKeys.set(k.keyId, k.publicKey);
        }
        return json(200, { oneTimePreKeyCount: mb.oneTimePreKeys.size, pqOneTimePreKeyCount: mb.pqOneTimePreKeys.size });
      }
      if (method === "PUT" && pathname === "/v1/profile") {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        const body = JSON.parse(utf8Decode(bodyBytes)) as { deliveryToken: string };
        mb.deliveryToken = body.deliveryToken;
        return json(200, {});
      }
      if (method === "GET" && pathname === "/v1/messages") {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        const envelopes = mb.queue.slice(0, 100);
        return json(200, { envelopes, more: mb.queue.length > 100 });
      }
      if (method === "DELETE" && pathname.startsWith("/v1/messages/")) {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        const id = decodeURIComponent(pathname.slice("/v1/messages/".length));
        mb.queue = mb.queue.filter((e) => e.id !== id);
        return json(200, {});
      }
      if (method === "POST" && pathname === "/v1/attachments") {
        await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        if (bodyBytes.length > 25 * 1024 * 1024) return errResponse(413, "too_large", "attachment too large");
        const id = hexEncode(randomBytes(32));
        this.attachments.set(id, bodyBytes);
        return json(201, { id });
      }
      if (method === "POST" && pathname === "/v1/invites") {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        const code = hexEncode(randomBytes(16));
        const expiresAt = Date.now() + 7 * 24 * 3600 * 1000;
        this.invites.set(code, { code, creator: mb.username, expiresAt, used: false });
        return json(201, { code, expiresAt });
      }
      if (method === "PUT" && pathname === "/v1/push") {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        mb.pushSubscription = JSON.parse(utf8Decode(bodyBytes)) as PushSubscriptionWire;
        return json(200, {});
      }
      if (method === "DELETE" && pathname === "/v1/push") {
        const mb = await this.verifyAuth(method, pathname, headers(init), bodyBytes);
        mb.pushSubscription = undefined;
        return json(200, {});
      }
      return errResponse(404, "not_found", `no such route: ${method} ${pathname}`);
    } catch (e) {
      if (e instanceof HttpError) return errResponse(e.status, e.code, e.message);
      return errResponse(500, "internal", (e as Error).message ?? String(e));
    }
  }

  private async handleSend(pathname: string, reqHeaders: HeadersInit | undefined, bodyBytes: Uint8Array): Promise<Response> {
    const targetUsername = decodeURIComponent(pathname.slice("/v1/messages/".length));
    const uaToken = headerOf(reqHeaders, "unidentified-access");
    let from: { username: string; deviceId: number } | undefined;
    if (uaToken !== undefined) {
      const target = this.mailboxes.get(targetUsername);
      if (!target) return errResponse(404, "not_found", "unknown recipient");
      if (uaToken !== target.deliveryToken) return errResponse(403, "forbidden", "bad unidentified-access token");
      from = undefined;
    } else {
      const sender = await this.verifyAuth("POST", pathname, reqHeaders, bodyBytes);
      from = { username: sender.username, deviceId: 1 };
    }
    const body = JSON.parse(utf8Decode(bodyBytes)) as { messages: Array<{ destinationDeviceId: number; type: number; content: string }>; timestamp: number };
    for (const m of body.messages) {
      await this.deliver(targetUsername, from, m.type, m.content);
    }
    return json(200, { needsSync: false });
  }

  private async handleRegister(reqHeaders: HeadersInit | undefined, bodyBytes: Uint8Array): Promise<Response> {
    const body = JSON.parse(utf8Decode(bodyBytes)) as RegisterBody;
    if (!/^[a-z0-9_]{3,32}$/.test(body.username)) return errResponse(400, "bad_request", "bad username");
    const isBootstrap = body.inviteCode === this.bootstrapInvite;
    const invite = this.invites.get(body.inviteCode);
    if (!isBootstrap) {
      if (!invite || invite.used || invite.expiresAt < Date.now()) return errResponse(403, "invite_invalid", "invite invalid, used or expired");
    }
    // Signed with the NEW identity key, per docs/API.md ("verified against the identity key inside its
    // body, since the user does not exist yet"). We deliberately allow re-registration of an existing
    // username with a fresh identity key: this simulates a device reset / reinstall (Signal's real servers
    // allow re-keying the same account the same way), which is what the "identity changed" test exercises.
    // A strict 409 "username taken" is intentionally not enforced here; see the core agent's final report.
    const header = headerOf(reqHeaders, "authorization");
    if (!header) return errResponse(401, "unauthenticated", "missing Authorization");
    const m = AUTH_RE.exec(header);
    if (!m || m[1] !== body.username) return errResponse(401, "unauthenticated", "malformed Authorization header");
    const tsStr = m[3]!;
    const sigB64 = m[4]!;
    const ts = parseInt(tsStr, 10);
    if (!Number.isFinite(ts) || Math.abs(Math.floor(Date.now() / 1000) - ts) > 300) return errResponse(401, "unauthenticated", "stale timestamp");
    const identityKey = b64Decode(body.identityKey);
    const bodyHashHex = await sha256Hex(bodyBytes);
    const message = `POST\n/v1/register\n${tsStr}\n${bodyHashHex}`;
    const sigOk = await xeddsaVerify(identityKey, utf8Encode(message), b64Decode(sigB64));
    if (!sigOk) return errResponse(401, "unauthenticated", "bad signature");
    const spkOk = await xeddsaVerify(identityKey, b64Decode(body.signedPreKey.publicKey), b64Decode(body.signedPreKey.signature));
    if (!spkOk) return errResponse(400, "bad_request", "bad signed prekey signature");
    if (body.oneTimePreKeys.length > 100) return errResponse(400, "bad_request", "too many one-time prekeys");

    // Post-quantum half (docs/POSTQUANTUM.md): optional, but all-or-nothing. A half-upgraded
    // account would be indistinguishable from a downgrade attack, so a partial upload is a 400.
    // One-time prekeys require an identity (they'd be meaningless -- and unverifiable as
    // belonging to this account -- without one).
    const hasPqIdentity = body.pqIdentityKey !== undefined;
    const hasPqSignedPreKey = body.pqSignedPreKey !== undefined;
    const hasPqOneTime = body.pqOneTimePreKeys !== undefined && body.pqOneTimePreKeys.length > 0;
    if (hasPqIdentity !== hasPqSignedPreKey) {
      return errResponse(400, "bad_request", "post-quantum identity and signed prekey must be sent together");
    }
    if (hasPqOneTime && !hasPqIdentity) {
      return errResponse(400, "bad_request", "post-quantum one-time prekeys require a post-quantum identity");
    }
    if (hasPqIdentity && body.pqOneTimePreKeys && body.pqOneTimePreKeys.length > 100) {
      return errResponse(400, "bad_request", "too many post-quantum one-time prekeys");
    }
    if (hasPqIdentity) {
      // The server verifies the classical (XEdDSA) signature binding the ML-KEM prekey to the
      // classical identity key; the ML-DSA `pqSignature` is the receiving client's job (API.md).
      const pqSpkOk = await xeddsaVerify(identityKey, b64Decode(body.pqSignedPreKey!.publicKey), b64Decode(body.pqSignedPreKey!.signature));
      if (!pqSpkOk) return errResponse(400, "bad_request", "bad post-quantum signed prekey signature");
    }

    const mb: MailboxRecord = {
      username: body.username,
      identityKey,
      registrationId: body.registrationId,
      deliveryToken: body.deliveryToken,
      signedPreKey: body.signedPreKey,
      oneTimePreKeys: new Map(body.oneTimePreKeys.map((k) => [k.keyId, k.publicKey])),
      queue: this.mailboxes.get(body.username)?.queue ?? [],
      pqIdentityKey: body.pqIdentityKey,
      pqSignedPreKey: body.pqSignedPreKey,
      pqOneTimePreKeys: new Map((body.pqOneTimePreKeys ?? []).map((k) => [k.keyId, k.publicKey])),
    };
    this.mailboxes.set(body.username, mb);
    if (!isBootstrap && invite) invite.used = true;
    return json(201, { username: body.username, deviceId: 1 });
  }
}

function headers(init: RequestInit | undefined): HeadersInit | undefined {
  return init?.headers;
}
