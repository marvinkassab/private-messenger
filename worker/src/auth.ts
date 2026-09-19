// Request authentication as specified in docs/API.md.
//
//   ts       = unix seconds, decimal string
//   bodyHash = hex(sha256(raw body))  (sha256("") when there is no body)
//   message  = METHOD + "\n" + PATH + "\n" + ts + "\n" + bodyHash
//   sig      = XEdDSA_sign(identityPrivateKey, utf8(message))
//   Authorization: Signal <username>:<deviceId>:<ts>:<base64 sig>
//
// The identity key is the 33-byte Signal key (0x05 || 32-byte Curve25519
// Montgomery public key).
//
// Verification is implemented here rather than taken from the Signal
// libraries, because those ship an Emscripten build that reads `__dirname` at
// load time. That works under Node and under the test harness's Node shim,
// but the Workers runtime has no `__dirname`, so importing it prevented the
// Worker from starting at all. This is pure arithmetic over @noble/curves and
// runs anywhere.

import { ed25519 } from "@noble/curves/ed25519.js";
import { ApiError } from "./types";
import { b64Decode, constantTimeEqual, isValidUsername, nowSeconds, sha256Hex, utf8 } from "./util";

export const AUTH_WINDOW_SECONDS = 300;

const FIELD_P = 2n ** 255n - 19n;

/** Modular inverse by Fermat's little theorem; p is prime. */
function invert(a: bigint): bigint {
  let result = 1n;
  let base = ((a % FIELD_P) + FIELD_P) % FIELD_P;
  let e = FIELD_P - 2n;
  while (e > 0n) {
    if (e & 1n) result = (result * base) % FIELD_P;
    base = (base * base) % FIELD_P;
    e >>= 1n;
  }
  return result;
}

function leToBigInt(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

/**
 * XEdDSA's `convert_mont`: the Montgomery u-coordinate of a Curve25519 public
 * key becomes the Edwards y-coordinate, y = (u - 1) / (u + 1).
 *
 * The sign bit is left zero here and supplied by the caller, because libsignal
 * carries the Edwards key's sign bit in the unused top bit of the signature's
 * s value rather than deriving it. Verification has to move it back before the
 * Ed25519 check, or every signature from a key with sign bit 1 is rejected.
 */
function montgomeryToEdwards(u32: Uint8Array): Uint8Array | null {
  const u = leToBigInt(u32) & ((1n << 255n) - 1n);
  if (u >= FIELD_P) return null;
  const denominator = (u + 1n) % FIELD_P;
  if (denominator === 0n) return null;
  const y = ((u + FIELD_P - 1n) % FIELD_P) * invert(denominator) % FIELD_P;
  const out = new Uint8Array(32);
  let t = y;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(t & 0xffn);
    t >>= 8n;
  }
  out[31] &= 0x7f; // XEdDSA fixes the sign bit at zero
  return out;
}

/** Strips the 0x05 prefix. Returns null when the key is not a 33-byte Signal key. */
export function rawIdentityKey(identityKey: Uint8Array): Uint8Array | null {
  if (identityKey.length !== 33 || identityKey[0] !== 0x05) return null;
  return identityKey.subarray(1);
}

/** XEdDSA verification with a 33-byte Signal identity key. Never throws. */
export async function verifyIdentitySignature(
  identityKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const raw = rawIdentityKey(identityKey);
  if (!raw || signature.length !== 64) return false;
  try {
    const edwards = montgomeryToEdwards(raw);
    if (!edwards) return false;
    // Move the signer's sign bit out of the signature and onto the key, then
    // clear it, which is exactly what libsignal's curve25519_verify does.
    edwards[31] = (edwards[31] & 0x7f) | (signature[63] & 0x80);
    const sig = Uint8Array.from(signature);
    sig[63] &= 0x7f;
    return ed25519.verify(sig, message, edwards, { zip215: false });
  } catch {
    return false;
  }
}

function toBuffer(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

export function buildAuthMessage(method: string, path: string, ts: string, bodyHashHex: string): Uint8Array {
  return utf8(`${method.toUpperCase()}\n${path}\n${ts}\n${bodyHashHex}`);
}

export interface AuthClaims {
  username: string;
  deviceId: number;
  ts: string;
  sig: Uint8Array;
}

export interface AuthContext {
  username: string;
  deviceId: number;
}

const unauthorized = (message: string) => new ApiError(401, "unauthorized", message);

/** Parses `Authorization: Signal u:d:ts:sig` and checks the timestamp window. */
export function parseAuthorizationHeader(header: string | null): AuthClaims {
  if (!header) throw unauthorized("missing Authorization header");
  const m = /^Signal\s+(.+)$/i.exec(header.trim());
  if (!m) throw unauthorized("unsupported authorization scheme");
  const parts = m[1].split(":");
  if (parts.length !== 4) throw unauthorized("malformed Authorization header");
  return validateClaims(parts[0], parts[1], parts[2], parts[3]);
}

/** Same values from the WebSocket query string: u, d, ts, sig. */
export function parseAuthorizationQuery(url: URL): AuthClaims {
  const u = url.searchParams.get("u");
  const d = url.searchParams.get("d");
  const ts = url.searchParams.get("ts");
  const sig = url.searchParams.get("sig");
  if (u === null || d === null || ts === null || sig === null) throw unauthorized("missing auth query parameters");
  return validateClaims(u, d, ts, sig);
}

function validateClaims(username: string, deviceIdStr: string, ts: string, sigB64: string): AuthClaims {
  if (!isValidUsername(username)) throw unauthorized("invalid username");
  if (!/^\d{1,9}$/.test(deviceIdStr)) throw unauthorized("invalid deviceId");
  const deviceId = Number(deviceIdStr);
  if (deviceId !== 1) throw unauthorized("unknown device");
  if (!/^\d{1,12}$/.test(ts)) throw unauthorized("invalid timestamp");
  if (Math.abs(nowSeconds() - Number(ts)) > AUTH_WINDOW_SECONDS) throw unauthorized("timestamp outside allowed window");
  const sig = b64Decode(sigB64);
  if (!sig || sig.length !== 64) throw unauthorized("invalid signature encoding");
  return { username, deviceId, ts, sig };
}

/**
 * Verifies the claims against `identityKey` (33 bytes). `bodyHashHex` is the
 * hex sha256 of the raw body (or of the empty string).
 */
export async function verifyClaims(
  claims: AuthClaims,
  identityKey: Uint8Array | null,
  method: string,
  path: string,
  bodyHashHex: string,
): Promise<AuthContext> {
  if (!identityKey) throw unauthorized("unknown user or bad signature");
  const message = buildAuthMessage(method, path, claims.ts, bodyHashHex);
  const ok = await verifyIdentitySignature(identityKey, message, claims.sig);
  if (!ok) throw unauthorized("unknown user or bad signature");
  return { username: claims.username, deviceId: claims.deviceId };
}

export async function emptyBodyHash(): Promise<string> {
  return sha256Hex(new Uint8Array(0));
}

/** Decodes an `Unidentified-Access` header. Returns null when malformed. */
export function parseUnidentifiedAccess(header: string | null): Uint8Array | null {
  if (!header) return null;
  const token = b64Decode(header.trim());
  if (!token || token.length !== 32) return null;
  return token;
}

/** Constant-time comparison of two delivery tokens. */
export function deliveryTokensMatch(presented: Uint8Array, stored: Uint8Array | null): boolean {
  // Compare against a dummy when the user has no token so timing does not leak that.
  return constantTimeEqual(presented, stored ?? new Uint8Array(32)) && stored !== null;
}
