// Private Messenger server: a dumb, sharded mailbox on Cloudflare Workers.
// See docs/API.md for the contract this file implements.

import { deleteAttachment, getAttachment, storeAttachment } from "./attachments";
import {
  type AuthContext,
  emptyBodyHash,
  parseAuthorizationHeader,
  parseAuthorizationQuery,
  parseUnidentifiedAccess,
  verifyClaims,
  verifyIdentitySignature,
} from "./auth";
import { Invite } from "./invite";
import { Mailbox, MAX_ONE_TIME_PREKEYS } from "./mailbox";
import { isValidSubscription } from "./push";
import {
  ML_DSA_65_PUBLIC,
  ML_DSA_65_SIGNATURE,
  ML_KEM_1024_PUBLIC,
  ApiError,
  type Env,
  type IncomingMessage,
  type OneTimePreKey,
  type PqOneTimePreKey,
  type PqSignedPreKey,
  type SignedPreKey,
} from "./types";
import { b64Decode, constantTimeEqual, isEnvelopeId, isPositiveInt, isValidUsername, randomHex, sha256Hex, utf8 } from "./util";

export { Mailbox, Invite };


/* Attachments ride inside messages rather than in separate storage, so a
   message has to be able to carry a photo.
 *
 * A Durable Object value tops out at 2 MB, measured rather than assumed, and
 * `content` is base64: four characters for every three bytes. So a megabyte
 * of ciphertext is stored as about 1.37 MB, comfortably inside the limit with
 * room for the rest of the row. Anything larger is split into chunks by the
 * client, which the server neither knows nor cares about, since a chunk is
 * just another message.
 *
 * The request body limit is derived from this rather than picked separately,
 * because the two drifting apart is what made a photo-sized message fail with
 * a body-length error that said nothing about photos. */
const MAX_CONTENT_BYTES = 1024 * 1024;
const BASE64_EXPANSION = 4 / 3;
/** One maximum-sized message, base64-expanded, plus room for the JSON around it. */
const MAX_JSON_BODY = Math.ceil(MAX_CONTENT_BYTES * BASE64_EXPANSION) + 64 * 1024;
const MAX_MESSAGES_PER_SEND = 100;
const MAX_PREKEYS_PER_REGISTER = 100;

// ---------------------------------------------------------------------------
// Routing

interface Ctx {
  request: Request;
  env: Env;
  exec: ExecutionContext;
  url: URL;
  path: string;
  params: Record<string, string>;
}

type Handler = (c: Ctx) => Promise<Response>;

interface Route {
  method: string;
  pattern: RegExp;
  keys: string[];
  handler: Handler;
}

const routes: Route[] = [];

function route(method: string, path: string, handler: Handler): void {
  const keys: string[] = [];
  const source = path.replace(/:([a-zA-Z]+)/g, (_, k: string) => {
    keys.push(k);
    return "([^/]+)";
  });
  routes.push({ method, pattern: new RegExp(`^${source}$`), keys, handler });
}

function json(status: number, body: unknown, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...(headers ?? {}) },
  });
}

function errorResponse(status: number, code: string, message: string): Response {
  return json(status, { error: code, message });
}

// ---------------------------------------------------------------------------
// CORS

const CORS_METHODS = "GET, POST, PUT, DELETE, OPTIONS";
const CORS_HEADERS = "Authorization, Unidentified-Access, Content-Type";

function allowedOrigin(request: Request, env: Env): string | null {
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  const list = (env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (list.includes("*")) return origin;
  return list.includes(origin) ? origin : null;
}

function withCors(response: Response, origin: string | null): Response {
  if (!origin || response.status === 101) return response;
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Access-Control-Allow-Methods", CORS_METHODS);
  headers.set("Access-Control-Allow-Headers", CORS_HEADERS);
  headers.set("Access-Control-Expose-Headers", "Content-Length, ETag");
  headers.append("Vary", "Origin");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function preflight(origin: string | null): Response {
  if (!origin) return new Response(null, { status: 403 });
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": CORS_METHODS,
      "Access-Control-Allow-Headers": CORS_HEADERS,
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    },
  });
}

// ---------------------------------------------------------------------------
// Helpers

async function readBody(request: Request, max = MAX_JSON_BODY): Promise<Uint8Array> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > max) throw new ApiError(413, "too_large", "request body too large");
  const buf = new Uint8Array(await request.arrayBuffer());
  if (buf.byteLength > max) throw new ApiError(413, "too_large", "request body too large");
  return buf;
}

function parseJson<T = Record<string, unknown>>(body: Uint8Array): T {
  if (body.byteLength === 0) throw new ApiError(400, "bad_request", "expected a JSON body");
  try {
    const v = JSON.parse(new TextDecoder().decode(body));
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error();
    return v as T;
  } catch {
    throw new ApiError(400, "bad_json", "body is not a JSON object");
  }
}

function mailboxFor(env: Env, username: string): DurableObjectStub<Mailbox> {
  return env.MAILBOX.get(env.MAILBOX.idFromName(username));
}

interface Authed {
  auth: AuthContext;
  mailbox: DurableObjectStub<Mailbox>;
  identityKey: Uint8Array;
}

/** Verifies `Authorization: Signal ...` for a request whose raw body is `body`. */
async function requireAuth(c: Ctx, body: Uint8Array): Promise<Authed> {
  const claims = parseAuthorizationHeader(c.request.headers.get("Authorization"));
  const mailbox = mailboxFor(c.env, claims.username);
  const stored = await mailbox.getIdentityKey();
  const identityKey = stored ? b64Decode(stored) : null;
  const auth = await verifyClaims(claims, identityKey, c.request.method, c.path, await sha256Hex(body));
  return { auth, mailbox, identityKey: identityKey! };
}

function decodeKey(v: unknown, len: number): Uint8Array | null {
  if (typeof v !== "string") return null;
  const bytes = b64Decode(v);
  return bytes && bytes.length === len ? bytes : null;
}

function validateOneTimePreKeys(v: unknown, max: number): OneTimePreKey[] {
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new ApiError(400, "bad_request", "oneTimePreKeys must be an array");
  if (v.length > max) throw new ApiError(400, "bad_request", `at most ${max} one-time prekeys`);
  const out: OneTimePreKey[] = [];
  const seen = new Set<number>();
  for (const k of v) {
    if (!k || typeof k !== "object" || !isPositiveInt(k.keyId) || !decodeKey(k.publicKey, 33)) {
      throw new ApiError(400, "bad_request", "invalid one-time prekey");
    }
    if (seen.has(k.keyId)) throw new ApiError(400, "bad_request", "duplicate one-time prekey id");
    seen.add(k.keyId);
    out.push({ keyId: k.keyId, publicKey: k.publicKey });
  }
  return out;
}

async function validateSignedPreKey(v: unknown, identityKey: Uint8Array): Promise<SignedPreKey> {
  if (!v || typeof v !== "object") throw new ApiError(400, "bad_request", "signedPreKey required");
  const s = v as Record<string, unknown>;
  const pub = decodeKey(s.publicKey, 33);
  const sig = decodeKey(s.signature, 64);
  if (!isPositiveInt(s.keyId) || !pub || !sig) throw new ApiError(400, "bad_request", "invalid signedPreKey");
  if (!(await verifyIdentitySignature(identityKey, pub, sig))) {
    throw new ApiError(400, "bad_signature", "signedPreKey signature does not verify under identityKey");
  }
  return { keyId: s.keyId, publicKey: s.publicKey as string, signature: s.signature as string };
}

/* Post-quantum prekeys (docs/POSTQUANTUM.md). The server checks lengths and
   the XEdDSA signature binding the ML-KEM public key to the classical identity
   key; that is enough to stop a server-side swap. ML-DSA verification is the
   client's job. */
function validatePqOneTimePreKeys(v: unknown, max: number): PqOneTimePreKey[] {
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new ApiError(400, "bad_request", "pqOneTimePreKeys must be an array");
  if (v.length > max) throw new ApiError(400, "bad_request", `at most ${max} post-quantum one-time prekeys`);
  const out: PqOneTimePreKey[] = [];
  const seen = new Set<number>();
  for (const k of v) {
    if (!k || typeof k !== "object" || !isPositiveInt(k.keyId) || !decodeKey(k.publicKey, ML_KEM_1024_PUBLIC)) {
      throw new ApiError(400, "bad_request", "invalid post-quantum one-time prekey");
    }
    if (seen.has(k.keyId)) throw new ApiError(400, "bad_request", "duplicate post-quantum prekey id");
    seen.add(k.keyId);
    out.push({ keyId: k.keyId, publicKey: k.publicKey });
  }
  return out;
}

async function validatePqSignedPreKey(v: unknown, identityKey: Uint8Array): Promise<PqSignedPreKey> {
  if (!v || typeof v !== "object") throw new ApiError(400, "bad_request", "pqSignedPreKey must be an object");
  const s = v as Record<string, unknown>;
  const pub = decodeKey(s.publicKey, ML_KEM_1024_PUBLIC);
  const sig = decodeKey(s.signature, 64);
  const pqSig = decodeKey(s.pqSignature, ML_DSA_65_SIGNATURE);
  if (!isPositiveInt(s.keyId) || !pub || !sig || !pqSig) {
    throw new ApiError(400, "bad_request", "invalid pqSignedPreKey");
  }
  if (!(await verifyIdentitySignature(identityKey, pub, sig))) {
    throw new ApiError(400, "bad_signature", "pqSignedPreKey signature does not verify under identityKey");
  }
  return {
    keyId: s.keyId,
    publicKey: s.publicKey as string,
    signature: s.signature as string,
    pqSignature: s.pqSignature as string,
  };
}

/* The post-quantum half is all-or-nothing: a client that sends an ML-DSA
   identity must also send a signed ML-KEM prekey, so a bundle can never be
   half-upgraded. */
async function validatePqHalf(
  b: Record<string, unknown>,
  identityKey: Uint8Array,
  max: number,
): Promise<{ pqIdentityKey?: string; pqSignedPreKey?: PqSignedPreKey; pqOneTimePreKeys: PqOneTimePreKey[] }> {
  const hasIdentity = b.pqIdentityKey !== undefined;
  const hasSigned = b.pqSignedPreKey !== undefined;
  if (hasIdentity !== hasSigned) {
    throw new ApiError(400, "bad_request", "pqIdentityKey and pqSignedPreKey must be sent together");
  }
  const pqOneTimePreKeys = validatePqOneTimePreKeys(b.pqOneTimePreKeys, max);
  if (!hasIdentity) {
    if (pqOneTimePreKeys.length) throw new ApiError(400, "bad_request", "pqOneTimePreKeys need a pqIdentityKey");
    return { pqOneTimePreKeys: [] };
  }
  if (!decodeKey(b.pqIdentityKey, ML_DSA_65_PUBLIC)) {
    throw new ApiError(400, "bad_request", `pqIdentityKey must be ${ML_DSA_65_PUBLIC} bytes (ML-DSA-65)`);
  }
  return {
    pqIdentityKey: b.pqIdentityKey as string,
    pqSignedPreKey: await validatePqSignedPreKey(b.pqSignedPreKey, identityKey),
    pqOneTimePreKeys,
  };
}

/* No `timestamp` field is accepted. The time a message was written belongs
   inside the ciphertext, where the server cannot read it; taking it here as
   well would hand the operator a plaintext clock on every message. A client
   that still sends one is not rejected, it is simply ignored. */
function validateMessages(body: Record<string, unknown>): { messages: IncomingMessage[] } {
  const messages = body.messages;
  if (!Array.isArray(messages) || messages.length === 0) throw new ApiError(400, "bad_request", "messages must be a non-empty array");
  if (messages.length > MAX_MESSAGES_PER_SEND) throw new ApiError(400, "bad_request", "too many messages");
  const out: IncomingMessage[] = [];
  for (const m of messages) {
    if (!m || typeof m !== "object") throw new ApiError(400, "bad_request", "invalid message");
    if (m.destinationDeviceId !== 1) throw new ApiError(400, "bad_request", "unknown destinationDeviceId");
    if (!isPositiveInt(m.type)) throw new ApiError(400, "bad_request", "invalid message type");
    if (typeof m.content !== "string") throw new ApiError(400, "bad_request", "content must be base64");
    if (m.content.length > Math.ceil(MAX_CONTENT_BYTES * BASE64_EXPANSION)) throw new ApiError(413, "too_large", "content exceeds 1 MB");
    const bytes = b64Decode(m.content);
    if (!bytes || bytes.length === 0) throw new ApiError(400, "bad_request", "content must be base64");
    if (bytes.length > MAX_CONTENT_BYTES) throw new ApiError(413, "too_large", "content exceeds 1 MB");
    out.push({ destinationDeviceId: 1, type: m.type, content: m.content });
  }
  return { messages: out };
}

// ---------------------------------------------------------------------------
// Routes

route("GET", "/v1/health", async () => json(200, { ok: true }));

route("POST", "/v1/register", async (c) => {
  const body = await readBody(c.request);
  const claims = parseAuthorizationHeader(c.request.headers.get("Authorization"));
  const b = parseJson(body);

  if (!isValidUsername(b.username)) throw new ApiError(400, "bad_request", "username must match ^[a-z0-9_]{3,32}$");
  if (b.username !== claims.username) throw new ApiError(401, "unauthorized", "Authorization username does not match body");
  const identityKey = decodeKey(b.identityKey, 33);
  if (!identityKey || identityKey[0] !== 0x05) throw new ApiError(400, "bad_request", "identityKey must be 33 bytes with 0x05 prefix");
  if (!isPositiveInt(b.registrationId) || b.registrationId > 0x3fff) throw new ApiError(400, "bad_request", "invalid registrationId");
  if (!decodeKey(b.deliveryToken, 32)) throw new ApiError(400, "bad_request", "deliveryToken must be 32 bytes");
  if (typeof b.inviteCode !== "string" || b.inviteCode.length === 0 || b.inviteCode.length > 128) {
    throw new ApiError(400, "bad_request", "inviteCode required");
  }

  // Verified against the identity key in the body, since the user does not exist yet.
  await verifyClaims(claims, identityKey, c.request.method, c.path, await sha256Hex(body));

  const signedPreKey = await validateSignedPreKey(b.signedPreKey, identityKey);
  const oneTimePreKeys = validateOneTimePreKeys(b.oneTimePreKeys, MAX_PREKEYS_PER_REGISTER);
  const pq = await validatePqHalf(b, identityKey, MAX_PREKEYS_PER_REGISTER);

  const mailbox = mailboxFor(c.env, b.username);
  if (await mailbox.exists()) throw new ApiError(409, "username_taken", "username is already registered");

  // Claim the invite (atomic inside the Invite object), or accept the bootstrap code.
  const bootstrap = c.env.BOOTSTRAP_INVITE;
  const isBootstrap = !!bootstrap && constantTimeEqual(utf8(b.inviteCode), utf8(bootstrap));
  const invite = isBootstrap ? null : c.env.INVITE.get(c.env.INVITE.idFromName(b.inviteCode));
  if (invite) {
    const claim = await invite.claim(b.username);
    if (!claim.ok) throw new ApiError(403, "invite_invalid", `invite code is ${claim.reason}`);
  }

  const created = await mailbox.register({
    identityKey: b.identityKey as string,
    registrationId: b.registrationId,
    deliveryToken: b.deliveryToken as string,
    signedPreKey,
    oneTimePreKeys,
    pqIdentityKey: pq.pqIdentityKey,
    pqSignedPreKey: pq.pqSignedPreKey,
    pqOneTimePreKeys: pq.pqOneTimePreKeys,
  });
  if (!created) {
    if (invite) await invite.release(b.username);
    throw new ApiError(409, "username_taken", "username is already registered");
  }
  return json(201, { username: b.username, deviceId: 1 });
});

route("GET", "/v1/keys/count", async (c) => {
  const { mailbox } = await requireAuth(c, new Uint8Array(0));
  return json(200, {
    oneTimePreKeyCount: await mailbox.preKeyCount(),
    pqOneTimePreKeyCount: await mailbox.pqPreKeyCount(),
  });
});

route("GET", "/v1/keys/:username", async (c) => {
  const { mailbox } = await requireAuth(c, new Uint8Array(0));
  const target = c.params.username;
  if (!isValidUsername(target)) throw new ApiError(404, "not_found", "unknown user");
  if (!(await mailbox.bump("keys", 60, 60))) throw new ApiError(429, "rate_limited", "too many bundle fetches");
  const bundle = await mailboxFor(c.env, target).fetchBundle(target);
  if (!bundle) throw new ApiError(404, "not_found", "unknown user");
  return json(200, bundle);
});

route("PUT", "/v1/keys", async (c) => {
  const body = await readBody(c.request);
  const { mailbox, identityKey } = await requireAuth(c, body);
  const b = parseJson(body);
  const signedPreKey = b.signedPreKey === undefined ? null : await validateSignedPreKey(b.signedPreKey, identityKey);
  const oneTimePreKeys = validateOneTimePreKeys(b.oneTimePreKeys, MAX_ONE_TIME_PREKEYS);
  const pqSignedPreKey = b.pqSignedPreKey === undefined ? null : await validatePqSignedPreKey(b.pqSignedPreKey, identityKey);
  const pqOneTimePreKeys = validatePqOneTimePreKeys(b.pqOneTimePreKeys, MAX_ONE_TIME_PREKEYS);
  const result = await mailbox.putKeys(signedPreKey, oneTimePreKeys, { signedPreKey: pqSignedPreKey, oneTimePreKeys: pqOneTimePreKeys });
  if ("error" in result) throw new ApiError(400, "too_many_prekeys", `the server keeps at most ${MAX_ONE_TIME_PREKEYS} one-time prekeys`);
  return json(200, { oneTimePreKeyCount: result.count, pqOneTimePreKeyCount: result.pqCount });
});

route("PUT", "/v1/profile", async (c) => {
  const body = await readBody(c.request);
  const { mailbox } = await requireAuth(c, body);
  const b = parseJson(body);
  if (!decodeKey(b.deliveryToken, 32)) throw new ApiError(400, "bad_request", "deliveryToken must be 32 bytes");
  await mailbox.setDeliveryToken(b.deliveryToken as string);
  return json(200, { ok: true });
});

route("POST", "/v1/messages/:username", async (c) => {
  const body = await readBody(c.request);
  const recipient = c.params.username;
  if (!isValidUsername(recipient)) throw new ApiError(404, "not_found", "unknown recipient");
  const unidentified = c.request.headers.get("Unidentified-Access");
  const recipientBox = mailboxFor(c.env, recipient);

  if (unidentified !== null && c.request.headers.get("Authorization") === null) {
    const token = parseUnidentifiedAccess(unidentified);
    if (!token) throw new ApiError(403, "forbidden", "invalid Unidentified-Access token");
    const { messages } = validateMessages(parseJson(body));
    const result = await recipientBox.unidentifiedSend(token, messages);
    return sendResult(result);
  }

  const { auth, mailbox } = await requireAuth(c, body);
  const { messages } = validateMessages(parseJson(body));
  if (!(await mailbox.bump("send", 300, 60))) throw new ApiError(429, "rate_limited", "too many sends");
  const result = await recipientBox.enqueue({ username: auth.username, deviceId: auth.deviceId }, messages);
  return sendResult(result);
});

function sendResult(result: Awaited<ReturnType<Mailbox["enqueue"]>>): Response {
  switch (result.status) {
    case "ok":
      return json(200, { needsSync: false });
    case "unknown":
      throw new ApiError(404, "not_found", "unknown recipient");
    case "forbidden":
      throw new ApiError(403, "forbidden", "delivery token does not match");
    case "rate_limited":
      throw new ApiError(429, "rate_limited", "recipient is receiving too many messages");
  }
}

route("GET", "/v1/messages", async (c) => {
  const { mailbox } = await requireAuth(c, new Uint8Array(0));
  return json(200, await mailbox.drain());
});

route("DELETE", "/v1/messages/:id", async (c) => {
  const { mailbox } = await requireAuth(c, new Uint8Array(0));
  if (!isEnvelopeId(c.params.id)) throw new ApiError(400, "bad_request", "invalid envelope id");
  await mailbox.ack(c.params.id);
  return json(200, { ok: true });
});

route("GET", "/v1/ws", async (c) => {
  if (c.request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    throw new ApiError(426, "upgrade_required", "expected a WebSocket upgrade");
  }
  const claims = parseAuthorizationQuery(c.url);
  const mailbox = mailboxFor(c.env, claims.username);
  const stored = await mailbox.getIdentityKey();
  await verifyClaims(claims, stored ? b64Decode(stored) : null, "GET", "/v1/ws", await emptyBodyHash());
  return mailbox.fetch(c.request);
});

route("POST", "/v1/attachments", async (c) => {
  // Cheap checks first (header shape, timestamp window, known user), then
  // stream the body into R2 while hashing it, then verify the signature over
  // the hash. An upload whose signature fails is deleted again.
  const claims = parseAuthorizationHeader(c.request.headers.get("Authorization"));
  const stored = await mailboxFor(c.env, claims.username).getIdentityKey();
  const identityKey = stored ? b64Decode(stored) : null;
  if (!identityKey) throw new ApiError(401, "unauthorized", "unknown user or bad signature");
  const upload = await storeAttachment(c.request, c.env);
  try {
    await verifyClaims(claims, identityKey, c.request.method, c.path, upload.bodyHashHex);
  } catch (e) {
    await deleteAttachment(c.env, upload.id);
    throw e;
  }
  return json(201, { id: upload.id });
});

route("GET", "/v1/attachments/:id", async (c) => getAttachment(c.env, c.params.id));

route("POST", "/v1/invites", async (c) => {
  const { auth, mailbox } = await requireAuth(c, await readBody(c.request));
  if (!(await mailbox.bump("invites", 20, 86400))) throw new ApiError(429, "rate_limited", "too many invites today");
  const code = randomHex(16);
  const { expiresAt } = await c.env.INVITE.get(c.env.INVITE.idFromName(code)).mint(auth.username);
  return json(201, { code, expiresAt });
});

route("PUT", "/v1/push", async (c) => {
  const body = await readBody(c.request);
  const { mailbox } = await requireAuth(c, body);
  const sub = parseJson(body);
  if (!isValidSubscription(sub)) throw new ApiError(400, "bad_request", "invalid push subscription");
  await mailbox.setPushSubscription({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } });
  return json(200, { ok: true });
});

route("DELETE", "/v1/push", async (c) => {
  const { mailbox } = await requireAuth(c, new Uint8Array(0));
  await mailbox.deletePushSubscription();
  return json(200, { ok: true });
});

// ---------------------------------------------------------------------------
// Entry point

async function dispatch(request: Request, env: Env, exec: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  let methodMatched = false;
  for (const r of routes) {
    const m = r.pattern.exec(path);
    if (!m) continue;
    if (r.method !== request.method) {
      methodMatched = true;
      continue;
    }
    const params: Record<string, string> = {};
    r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
    // `await` here so a handler that throws synchronously never leaves a
    // momentarily-unhandled rejection behind (the curve library installs a
    // Node-style unhandledRejection hook that would abort on it).
    return await r.handler({ request, env, exec, url, path, params });
  }
  if (methodMatched) throw new ApiError(405, "method_not_allowed", "method not allowed");
  throw new ApiError(404, "not_found", "no such route");
}

export default {
  async fetch(request: Request, env: Env, exec: ExecutionContext): Promise<Response> {
    const origin = allowedOrigin(request, env);
    if (request.method === "OPTIONS") return preflight(origin);
    let response: Response;
    try {
      response = await dispatch(request, env, exec);
    } catch (e) {
      if (e instanceof ApiError) {
        response = errorResponse(e.status, e.code, e.message);
      } else {
        console.error("unhandled error", e);
        response = errorResponse(500, "internal", "internal error");
      }
    }
    return withCors(response, origin);
  },
} satisfies ExportedHandler<Env>;
