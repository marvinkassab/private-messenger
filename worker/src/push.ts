// Web Push with VAPID (RFC 8292). Payload is always empty, so no content
// encryption is needed: the push is only a wake-up for the service worker.
//
// VAPID_PUBLIC_KEY : base64url of the 65-byte uncompressed P-256 public key
//                    (the same string the browser gets as applicationServerKey)
// VAPID_PRIVATE_KEY: either base64url of the raw 32-byte private scalar
//                    (what `web-push generate-vapid-keys` prints), or a PEM
//                    PKCS#8 block ("-----BEGIN PRIVATE KEY-----").
// VAPID_SUBJECT    : "mailto:you@example.com" or an https URL.

import type { PushSubscription } from "./types";
import { b64urlDecode, b64urlEncode, utf8 } from "./util";

export interface VapidConfig {
  publicKey: string;
  privateKey: string;
  subject: string;
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export const PUSH_TTL_SECONDS = 86400;
export const PUSH_DEBOUNCE_MS = 10_000;

const keyCache = new Map<string, Promise<CryptoKey>>();

async function importVapidPrivateKey(cfg: VapidConfig): Promise<CryptoKey> {
  const cacheKey = cfg.privateKey + "|" + cfg.publicKey;
  let p = keyCache.get(cacheKey);
  if (!p) {
    p = doImport(cfg);
    keyCache.set(cacheKey, p);
  }
  return p;
}

async function doImport(cfg: VapidConfig): Promise<CryptoKey> {
  const alg = { name: "ECDSA", namedCurve: "P-256" };
  const priv = cfg.privateKey.trim();
  if (priv.includes("-----BEGIN")) {
    const der = b64urlDecode(priv.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""));
    if (!der) throw new Error("VAPID_PRIVATE_KEY: invalid PEM");
    return crypto.subtle.importKey("pkcs8", der as BufferSource, alg, false, ["sign"]);
  }
  const d = b64urlDecode(priv);
  const pub = b64urlDecode(cfg.publicKey.trim());
  if (!d || d.length !== 32) throw new Error("VAPID_PRIVATE_KEY: expected 32 raw bytes (base64url) or PEM");
  if (!pub || pub.length !== 65 || pub[0] !== 0x04) throw new Error("VAPID_PUBLIC_KEY: expected 65-byte uncompressed point (base64url)");
  const jwk: JsonWebKey = {
    kty: "EC",
    crv: "P-256",
    x: b64urlEncode(pub.subarray(1, 33)),
    y: b64urlEncode(pub.subarray(33, 65)),
    d: b64urlEncode(d),
    ext: true,
  };
  return crypto.subtle.importKey("jwk", jwk, alg, false, ["sign"]);
}

/** Builds the ES256 JWT `vapid t=` value for the push service at `audience`. */
export async function createVapidJwt(cfg: VapidConfig, audience: string, now = Date.now()): Promise<string> {
  const key = await importVapidPrivateKey(cfg);
  const header = b64urlEncode(utf8(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64urlEncode(
    utf8(JSON.stringify({ aud: audience, exp: Math.floor(now / 1000) + 12 * 3600, sub: cfg.subject })),
  );
  const signingInput = `${header}.${claims}`;
  // WebCrypto ECDSA returns the raw r||s concatenation, which is what JWS wants.
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(signingInput) as BufferSource),
  );
  return `${signingInput}.${b64urlEncode(sig)}`;
}

export function vapidConfigFromEnv(env: {
  VAPID_PUBLIC_KEY?: string;
  VAPID_PRIVATE_KEY?: string;
  VAPID_SUBJECT?: string;
}): VapidConfig | null {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY || !env.VAPID_SUBJECT) return null;
  return { publicKey: env.VAPID_PUBLIC_KEY, privateKey: env.VAPID_PRIVATE_KEY, subject: env.VAPID_SUBJECT };
}

export type PushResult = "sent" | "gone" | "failed";

/**
 * Sends an empty Web Push to `sub`. Returns "gone" when the push service
 * says the subscription no longer exists (404/410), in which case the caller
 * should drop it.
 */
export async function sendWebPush(
  sub: PushSubscription,
  cfg: VapidConfig,
  fetchImpl: FetchLike = (input, init) => fetch(input, init),
): Promise<PushResult> {
  let audience: string;
  try {
    const u = new URL(sub.endpoint);
    if (u.protocol !== "https:") return "gone";
    audience = u.origin;
  } catch {
    return "gone";
  }
  const jwt = await createVapidJwt(cfg, audience);
  const pub = b64urlEncode(b64urlDecode(cfg.publicKey.trim()) ?? new Uint8Array(0));
  try {
    const res = await fetchImpl(sub.endpoint, {
      method: "POST",
      headers: {
        Authorization: `vapid t=${jwt}, k=${pub}`,
        TTL: String(PUSH_TTL_SECONDS),
        Urgency: "high",
        "Content-Length": "0",
      },
    });
    if (res.status === 404 || res.status === 410) return "gone";
    return res.ok ? "sent" : "failed";
  } catch {
    return "failed";
  }
}

// ---- injectable transport, so tests (which share the isolate with the
// Worker) can capture what the Mailbox would have sent ----

let transport: FetchLike | undefined;

export function setPushTransport(fn: FetchLike | undefined): void {
  transport = fn;
}

export function getPushTransport(): FetchLike {
  return transport ?? ((input, init) => fetch(input, init));
}

export function isValidSubscription(v: unknown): v is PushSubscription {
  if (!v || typeof v !== "object") return false;
  const s = v as Record<string, unknown>;
  if (typeof s.endpoint !== "string" || s.endpoint.length > 2048) return false;
  try {
    if (new URL(s.endpoint).protocol !== "https:") return false;
  } catch {
    return false;
  }
  const keys = s.keys as Record<string, unknown> | undefined;
  return (
    !!keys &&
    typeof keys === "object" &&
    typeof keys.p256dh === "string" &&
    typeof keys.auth === "string" &&
    keys.p256dh.length <= 256 &&
    keys.auth.length <= 64
  );
}
