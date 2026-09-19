/* Small byte / encoding helpers shared by the core. No imports on purpose. */

export type Bytes = Uint8Array;

export function utf8Encode(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function utf8Decode(b: ArrayBuffer | Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function toArrayBuffer(b: ArrayBuffer | Uint8Array): ArrayBuffer {
  if (b instanceof ArrayBuffer) return b;
  if (b.byteOffset === 0 && b.byteLength === b.buffer.byteLength && b.buffer instanceof ArrayBuffer) return b.buffer;
  return b.slice().buffer as ArrayBuffer;
}

export function toBytes(b: ArrayBuffer | Uint8Array): Uint8Array {
  return b instanceof Uint8Array ? b : new Uint8Array(b);
}

export function concatBytes(...parts: Array<ArrayBuffer | Uint8Array>): Uint8Array {
  const arrs = parts.map(toBytes);
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function bytesEqual(a: ArrayBuffer | Uint8Array, b: ArrayBuffer | Uint8Array): boolean {
  const x = toBytes(a);
  const y = toBytes(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i]! ^ y[i]!;
  return diff === 0;
}

/* Standard base64 (RFC 4648 with padding). */
export function b64Encode(b: ArrayBuffer | Uint8Array): string {
  const bytes = toBytes(b);
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunk)));
  }
  return btoa(bin);
}

export function b64Decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function isB64(s: unknown, byteLength?: number): boolean {
  if (typeof s !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) return false;
  if (byteLength === undefined) return true;
  try {
    return b64Decode(s).length === byteLength;
  } catch {
    return false;
  }
}

/* The Signal library represents ciphertext as a "binary string" (one char per byte). */
export function binaryStringToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

export function bytesToBinaryString(b: ArrayBuffer | Uint8Array): string {
  const bytes = toBytes(b);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return s;
}

export function hexEncode(b: ArrayBuffer | Uint8Array): string {
  const bytes = toBytes(b);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, "0");
  return s;
}

export function hexDecode(s: string): Uint8Array {
  if (s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) throw new Error("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function webcrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error("WebCrypto is not available in this environment");
  return c;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  webcrypto().getRandomValues(out);
  return out;
}

/* 16 random bytes as hex: the message / group id format from PROTOCOL.md. */
export function randomId(): string {
  return hexEncode(randomBytes(16));
}

export async function sha256(data: ArrayBuffer | Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await webcrypto().subtle.digest("SHA-256", toArrayBuffer(data)));
}

export async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  return hexEncode(await sha256(data));
}

export async function hkdfSha256(
  ikm: ArrayBuffer | Uint8Array,
  salt: ArrayBuffer | Uint8Array,
  info: ArrayBuffer | Uint8Array,
  lengthBytes: number,
): Promise<Uint8Array> {
  const subtle = webcrypto().subtle;
  const key = await subtle.importKey("raw", toArrayBuffer(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: toArrayBuffer(salt), info: toArrayBuffer(info) },
    key,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function aesGcmEncrypt(
  key: ArrayBuffer | Uint8Array,
  iv: ArrayBuffer | Uint8Array,
  plaintext: ArrayBuffer | Uint8Array,
  aad?: ArrayBuffer | Uint8Array,
): Promise<Uint8Array> {
  const subtle = webcrypto().subtle;
  const k = await subtle.importKey("raw", toArrayBuffer(key), "AES-GCM", false, ["encrypt"]);
  const params: AesGcmParams = { name: "AES-GCM", iv: toArrayBuffer(iv) };
  if (aad) params.additionalData = toArrayBuffer(aad);
  return new Uint8Array(await subtle.encrypt(params, k, toArrayBuffer(plaintext)));
}

export async function aesGcmDecrypt(
  key: ArrayBuffer | Uint8Array,
  iv: ArrayBuffer | Uint8Array,
  ciphertext: ArrayBuffer | Uint8Array,
  aad?: ArrayBuffer | Uint8Array,
): Promise<Uint8Array> {
  const subtle = webcrypto().subtle;
  const k = await subtle.importKey("raw", toArrayBuffer(key), "AES-GCM", false, ["decrypt"]);
  const params: AesGcmParams = { name: "AES-GCM", iv: toArrayBuffer(iv) };
  if (aad) params.additionalData = toArrayBuffer(aad);
  return new Uint8Array(await subtle.decrypt(params, k, toArrayBuffer(ciphertext)));
}

/* PBKDF2-SHA256 key derivation used by the app lock and backups (PROTOCOL.md). */
export const PBKDF2_ITERATIONS = 310_000;

export async function deriveKeyBytes(
  passphrase: string,
  salt: ArrayBuffer | Uint8Array,
  iterations = PBKDF2_ITERATIONS,
): Promise<Uint8Array> {
  const subtle = webcrypto().subtle;
  const base = await subtle.importKey("raw", toArrayBuffer(utf8Encode(passphrase)), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: toArrayBuffer(salt), iterations }, base, 256);
  return new Uint8Array(bits);
}

/* JSON that can carry ArrayBuffers / Uint8Arrays (used for encrypted records and backups). */
export function toJsonSafe(v: unknown): unknown {
  if (v instanceof ArrayBuffer) return { $b64: b64Encode(v) };
  if (v instanceof Uint8Array) return { $b64: b64Encode(v), $u8: true };
  if (Array.isArray(v)) return v.map(toJsonSafe);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (val !== undefined) out[k] = toJsonSafe(val);
    }
    return out;
  }
  return v;
}

export function fromJsonSafe(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(fromJsonSafe);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (typeof o.$b64 === "string" && Object.keys(o).every((k) => k === "$b64" || k === "$u8")) {
      const bytes = b64Decode(o.$b64);
      return o.$u8 ? bytes : toArrayBuffer(bytes);
    }
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(o)) out[k] = fromJsonSafe(val);
    return out;
  }
  return v;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export function uniq<T>(xs: T[]): T[] {
  return Array.from(new Set(xs));
}

export const USERNAME_RE = /^[a-z0-9_]{3,32}$/;

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
