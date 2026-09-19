// Request authentication as specified in docs/API.md.
//
//   ts       = unix seconds, decimal string
//   bodyHash = hex(sha256(raw body))  (sha256("") when there is no body)
//   message  = METHOD + "\n" + PATH + "\n" + ts + "\n" + bodyHash
//   sig      = XEdDSA_sign(identityPrivateKey, utf8(message))
//   Authorization: Signal <username>:<deviceId>:<ts>:<base64 sig>
//
// The identity key is the 33-byte Signal key (0x05 || 32-byte Curve25519
// Montgomery public key). The curve library wants the 32 raw bytes.

import { Curve25519Wrapper } from "@privacyresearch/curve25519-typescript";
import { ApiError } from "./types";
import { b64Decode, constantTimeEqual, isValidUsername, nowSeconds, sha256Hex, utf8 } from "./util";

export const AUTH_WINDOW_SECONDS = 300;

let curvePromise: Promise<Curve25519Wrapper> | undefined;
function curve(): Promise<Curve25519Wrapper> {
  if (!curvePromise) curvePromise = Curve25519Wrapper.create();
  return curvePromise;
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
    const c = await curve();
    return c.signatureIsValid(toBuffer(raw), toBuffer(message), toBuffer(signature));
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
