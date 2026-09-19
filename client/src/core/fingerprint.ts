/* Signal safety numbers.
 *
 * This is the same algorithm as the protocol library's FingerprintGenerator,
 * byte for byte, and `test/core/fingerprint.test.ts` proves the two agree on
 * random inputs. It exists because the library's version routes 5,200
 * sequential SHA-512 rounds through a pure-JavaScript crypto polyfill, each
 * one an awaited promise. Measured in a real browser against the real server,
 * one safety number took **43 seconds**, during which the details panel sits
 * on "Loading safety number…" and looks broken.
 *
 * Hashing synchronously does the identical work in about ten milliseconds.
 *
 * The algorithm, for reference:
 *   data = uint16le(0) || identityKey || identifierBytes
 *   h    = SHA-512(data || identityKey)
 *   then 5,199 more times: h = SHA-512(h || identityKey)
 *   take the first 30 bytes as six 5-byte chunks; each chunk, read big-endian,
 *   modulo 100000, zero-padded to five digits
 *   the pair's number is the two parties' strings sorted and concatenated
 */

import { sha512 } from "@noble/hashes/sha2.js";

export const FINGERPRINT_VERSION = 0;
export const FINGERPRINT_ITERATIONS = 5200;

function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

/** The library treats the identifier as a binary string, one byte per char. */
function identifierBytes(identifier: string): Uint8Array {
  const out = new Uint8Array(identifier.length);
  for (let i = 0; i < identifier.length; i++) {
    const code = identifier.charCodeAt(i);
    if (code > 0xff) throw new RangeError("illegal char code: " + code);
    out[i] = code;
  }
  return out;
}

function uint16le(n: number): Uint8Array {
  const out = new Uint8Array(2);
  new DataView(out.buffer).setUint16(0, n, true);
  return out;
}

/** Five bytes read big-endian, modulo 100000, as five digits. */
function encodedChunk(hash: Uint8Array, offset: number): string {
  const chunk =
    (hash[offset] * 2 ** 32 +
      hash[offset + 1] * 2 ** 24 +
      hash[offset + 2] * 2 ** 16 +
      hash[offset + 3] * 2 ** 8 +
      hash[offset + 4]) %
    100000;
  return String(chunk).padStart(5, "0");
}

/** One party's 30 digits. */
export function displayStringFor(
  identifier: string,
  identityKey: Uint8Array,
  iterations = FINGERPRINT_ITERATIONS,
): string {
  let hash = concat(uint16le(FINGERPRINT_VERSION), identityKey, identifierBytes(identifier));
  for (let i = 0; i < iterations; i++) {
    hash = sha512(concat(hash, identityKey));
  }
  return (
    encodedChunk(hash, 0) +
    encodedChunk(hash, 5) +
    encodedChunk(hash, 10) +
    encodedChunk(hash, 15) +
    encodedChunk(hash, 20) +
    encodedChunk(hash, 25)
  );
}

/** The 60-digit safety number shared by two people. */
export function safetyNumberFor(
  localIdentifier: string,
  localIdentityKey: Uint8Array,
  remoteIdentifier: string,
  remoteIdentityKey: Uint8Array,
  iterations = FINGERPRINT_ITERATIONS,
): string {
  const local = displayStringFor(localIdentifier, localIdentityKey, iterations);
  const remote = displayStringFor(remoteIdentifier, remoteIdentityKey, iterations);
  // Sorted, so both sides compute the same number whichever end they are.
  return [local, remote].sort().join("");
}
