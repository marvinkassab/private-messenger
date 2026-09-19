// Small helpers shared by the Worker and the Durable Objects.

const enc = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

// ---- base64 (standard alphabet, with padding) ----

export function b64Encode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

/** Decodes standard base64. Returns null when the input is not valid base64. */
export function b64Decode(s: string): Uint8Array | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return null;
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

// ---- base64url (no padding), used by VAPID / Web Push ----

export function b64urlEncode(bytes: Uint8Array): string {
  return b64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Uint8Array | null {
  if (typeof s !== "string") return null;
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4 !== 0) t += "=";
  return b64Decode(t);
}

// ---- hex ----

export function hexEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

export function randomHex(nBytes: number): string {
  return hexEncode(crypto.getRandomValues(new Uint8Array(nBytes)));
}

// ---- hashing ----

export async function sha256(data: Uint8Array | ArrayBuffer): Promise<Uint8Array> {
  const buf = data instanceof Uint8Array ? data : new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf as BufferSource));
}

export async function sha256Hex(data: Uint8Array | ArrayBuffer): Promise<string> {
  return hexEncode(await sha256(data));
}

// ---- constant-time comparison ----

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Length is not secret; still walk the full longer array to avoid an early exit.
  const n = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < n; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

// ---- ULID-like sortable ids ----
// 26 chars of Crockford base32: 48-bit millisecond timestamp + 80 bits of randomness.
// The generator is monotonic within one process: ids created in the same
// millisecond increment the random part so ORDER BY id is insertion order.

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function createIdGenerator(): (now?: number) => string {
  let lastTime = -1;
  let lastRandom = new Uint8Array(10);
  return (now = Date.now()) => {
    if (now <= lastTime) {
      now = lastTime;
      // increment the 80-bit random part (big endian)
      for (let i = 9; i >= 0; i--) {
        lastRandom[i] = (lastRandom[i] + 1) & 0xff;
        if (lastRandom[i] !== 0) break;
      }
    } else {
      lastTime = now;
      lastRandom = crypto.getRandomValues(new Uint8Array(10));
    }
    return encodeTime(now) + encodeRandom(lastRandom);
  };
}

function encodeTime(ms: number): string {
  let s = "";
  let t = ms;
  for (let i = 0; i < 10; i++) {
    s = CROCKFORD[t % 32] + s;
    t = Math.floor(t / 32);
  }
  return s;
}

function encodeRandom(bytes: Uint8Array): string {
  // 80 bits -> 16 chars of 5 bits
  let bits = 0n;
  for (const b of bytes) bits = (bits << 8n) | BigInt(b);
  let s = "";
  for (let i = 0; i < 16; i++) {
    s = CROCKFORD[Number(bits & 31n)] + s;
    bits >>= 5n;
  }
  return s;
}

export const newId = createIdGenerator();

export function isEnvelopeId(id: unknown): id is string {
  return typeof id === "string" && /^[0-9A-HJKMNP-TV-Z]{26}$/.test(id);
}

// ---- misc ----

export const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
/** Path segments that would collide with fixed routes. */
export const RESERVED_USERNAMES = new Set(["count"]);

export function isValidUsername(u: unknown): u is string {
  return typeof u === "string" && USERNAME_RE.test(u) && !RESERVED_USERNAMES.has(u);
}

export function isPositiveInt(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n > 0;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
