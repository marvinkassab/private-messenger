/* Proves the fast safety-number implementation is byte-for-byte identical to
 * the protocol library's, and shows the speed difference that motivated it.
 *
 * Equivalence matters because a safety number people have already compared in
 * person must not change: a different number would look exactly like the
 * warning the whole mechanism exists to raise.
 */

import { FingerprintGenerator } from "@privacyresearch/libsignal-protocol-typescript";
import { describe, expect, it } from "vitest";
import { displayStringFor, safetyNumberFor } from "../../src/core/fingerprint";

function randomKey(): Uint8Array {
  const key = new Uint8Array(33);
  crypto.getRandomValues(key);
  key[0] = 0x05; // Signal identity keys carry this prefix
  return key;
}

function toArrayBuffer(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

describe("safety numbers match the protocol library", () => {
  // A low iteration count keeps the library's slow path usable in a test while
  // exercising exactly the same code; the real count is covered separately.
  const FAST = 20;

  it("agrees with the library on random identities", async () => {
    for (let i = 0; i < 5; i++) {
      const aliceKey = randomKey();
      const bobKey = randomKey();
      const aliceName = `alice_${i}`;
      const bobName = `bob_${i}`;

      const theirs = await new FingerprintGenerator(FAST).createFor(
        aliceName,
        toArrayBuffer(aliceKey),
        bobName,
        toArrayBuffer(bobKey),
      );
      const ours = safetyNumberFor(aliceName, aliceKey, bobName, bobKey, FAST);

      expect(ours).toBe(theirs);
      expect(ours).toHaveLength(60);
      expect(ours).toMatch(/^\d{60}$/);
    }
  });

  it("agrees on one party's half too", async () => {
    const key = randomKey();
    const theirs = await new FingerprintGenerator(FAST).createFor("solo", toArrayBuffer(key), "solo", toArrayBuffer(key));
    const half = displayStringFor("solo", key, FAST);
    expect(theirs).toBe(half + half);
    expect(half).toHaveLength(30);
  });

  it("is symmetric: both ends compute the same number", () => {
    const aliceKey = randomKey();
    const bobKey = randomKey();
    const fromAlice = safetyNumberFor("alice", aliceKey, "bob", bobKey, FAST);
    const fromBob = safetyNumberFor("bob", bobKey, "alice", aliceKey, FAST);
    expect(fromAlice).toBe(fromBob);
  });

  it("changes when an identity key changes, which is the point of it", () => {
    const aliceKey = randomKey();
    const bobKey = randomKey();
    const before = safetyNumberFor("alice", aliceKey, "bob", bobKey, FAST);
    const after = safetyNumberFor("alice", aliceKey, "bob", randomKey(), FAST);
    expect(after).not.toBe(before);
  });

  it("computes a full-strength number quickly", () => {
    const aliceKey = randomKey();
    const bobKey = randomKey();
    const started = Date.now();
    const digits = safetyNumberFor("alice", aliceKey, "bob", bobKey); // the real 5200 iterations
    const elapsed = Date.now() - started;

    expect(digits).toMatch(/^\d{60}$/);
    // The library's version measured 43 seconds in a browser. Anything in this
    // range means the details panel renders immediately instead of appearing
    // to hang.
    expect(elapsed).toBeLessThan(2000);
  });
});
