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

// ---- sortable, clockless envelope ids ----
// 26 chars of Crockford base32: 48-bit millisecond timestamp + 80 bits of randomness.
// The generator is monotonic within one process: ids created in the same
// millisecond increment the random part so ORDER BY id is insertion order.

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Envelope ids.
 *
 * These were ULIDs, whose leading characters encode the creation time to the
 * millisecond. That put an arrival clock on every message even with the
 * timestamp columns removed, so ids are now a per-mailbox sequence number
 * followed by random padding: they still sort in arrival order, which is all
 * the queue needs, but carry no wall-clock information.
 */
const ID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const SEQ_CHARS = 10;
const RANDOM_CHARS = 16;

function encodeSeq(seq: number): string {
  let n = BigInt(seq);
  let out = "";
  for (let i = 0; i < SEQ_CHARS; i++) {
    out = ID_ALPHABET[Number(n % 32n)] + out;
    n /= 32n;
  }
  return out;
}

function encodeRandom(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < RANDOM_CHARS; i++) out += ID_ALPHABET[bytes[i] & 31];
  return out;
}

/** Builds an id generator over a caller-supplied, monotonically rising seq. */
export function createIdGenerator(): (seq: number) => string {
  return (seq: number) => encodeSeq(seq) + encodeRandom(crypto.getRandomValues(new Uint8Array(RANDOM_CHARS)));
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
