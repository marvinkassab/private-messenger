import * as pq from "./pqlayer.mjs";
import { randomBytes } from "@noble/hashes/utils.js";
let fail = 0;
const ok = (c, l) => { console.log((c ? "PASS " : "FAIL ") + l); if (!c) fail++; };
const eq = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const te = new TextEncoder();

const aliceDsa = pq.generatePqIdentity(), bobDsa = pq.generatePqIdentity();
const aliceId = randomBytes(32), bobId = randomBytes(32);
const pqIds = Buffer.concat([Buffer.from(aliceDsa.publicKey), Buffer.from(bobDsa.publicKey)]);
const classical = randomBytes(32);   // supplied by the Signal library's X3DH

function newPair({ oneTime = true } = {}) {
  const signed = pq.generatePqPreKey(), ot = oneTime ? pq.generatePqPreKey() : null;
  const init = pq.initiateSession({ classicalSecret: classical, peerSignedPreKeyPub: signed.publicKey, peerOneTimePreKeyPub: ot?.publicKey ?? null, initiatorIdentity: aliceId, responderIdentity: bobId, pqIdentities: pqIds });
  const bob = pq.acceptSession({ classicalSecret: classical, ctSigned: init.ctSigned, ctOneTime: init.ctOneTime, signedPreKeySecret: signed.secretKey, oneTimePreKeySecret: ot?.secretKey ?? null, initiatorIdentity: aliceId, responderIdentity: bobId, pqIdentities: pqIds });
  return { alice: init.state, bob, initFields: { ctSigned: init.ctSigned, ctOneTime: init.ctOneTime }, oneTime };
}

// 1. agreement
{
  const s = newPair();
  ok(eq(s.alice.chainKey, s.bob.chainKey), "both sides derive the same hybrid chain key");
  const inner = te.encode("SIGNAL-CIPHERTEXT-1");
  const w = pq.pqSeal(s.alice, inner, { pqIdentitySecret: aliceDsa.secretKey, initFields: s.initFields });
  const got = pq.pqOpen(s.bob, w, { peerPqIdentityPub: aliceDsa.publicKey, hasInit: true, hasOneTime: true });
  ok(eq(got, inner), "session-opening message round-trips");
  ok(w.length - inner.length > 6000, `opener carries 2 KEM ciphertexts + ML-DSA signature (${w.length - inner.length}B)`);
}

// 2. a wrong classical secret must break the hybrid: PQ is additive, not a replacement
{
  const signed = pq.generatePqPreKey();
  const init = pq.initiateSession({ classicalSecret: classical, peerSignedPreKeyPub: signed.publicKey, peerOneTimePreKeyPub: null, initiatorIdentity: aliceId, responderIdentity: bobId, pqIdentities: pqIds });
  const wrong = pq.acceptSession({ classicalSecret: randomBytes(32), ctSigned: init.ctSigned, ctOneTime: null, signedPreKeySecret: signed.secretKey, oneTimePreKeySecret: null, initiatorIdentity: aliceId, responderIdentity: bobId, pqIdentities: pqIds });
  ok(!eq(init.state.chainKey, wrong.chainKey), "breaking only ML-KEM is not enough: the classical secret is bound into the root");
}

// 3. steady-state traffic and overhead
{
  const s = newPair();
  pq.pqOpen(s.bob, pq.pqSeal(s.alice, te.encode("open"), { pqIdentitySecret: aliceDsa.secretKey, initFields: s.initFields }), { peerPqIdentityPub: aliceDsa.publicKey, hasInit: true, hasOneTime: true });
  let sum = 0; const n = 50;
  for (let i = 0; i < n; i++) {
    const m = te.encode("msg-" + i);
    const w = pq.pqSeal(s.alice, m, { pqIdentitySecret: aliceDsa.secretKey });
    sum += w.length - m.length;
    if (!eq(pq.pqOpen(s.bob, w, { peerPqIdentityPub: aliceDsa.publicKey }), m)) { ok(false, "message " + i); break; }
  }
  ok(true, `${n} sequential messages round-trip; steady-state overhead ${Math.round(sum / n)}B each`);
}

// 4. out-of-order delivery (the network reorders; Signal handles this, so must we)
{
  const s = newPair();
  pq.pqOpen(s.bob, pq.pqSeal(s.alice, te.encode("open"), { pqIdentitySecret: aliceDsa.secretKey, initFields: s.initFields }), { peerPqIdentityPub: aliceDsa.publicKey, hasInit: true, hasOneTime: true });
  const frames = [0,1,2,3,4].map((i) => ({ i, w: pq.pqSeal(s.alice, te.encode("ooo-" + i), { pqIdentitySecret: aliceDsa.secretKey }) }));
  const order = [3, 0, 4, 1, 2];
  let good = true;
  for (const idx of order) {
    const f = frames[idx];
    try { good = good && eq(pq.pqOpen(s.bob, f.w, { peerPqIdentityPub: aliceDsa.publicKey }), te.encode("ooo-" + f.i)); }
    catch (e) { good = false; console.log("   (failed on frame " + idx + ": " + e.message + ")"); }
  }
  ok(good, "messages delivered out of order (3,0,4,1,2) all decrypt");
  let replayed = false;
  try { pq.pqOpen(s.bob, frames[0].w, { peerPqIdentityPub: aliceDsa.publicKey }); } catch { replayed = true; }
  ok(replayed, "a replayed message is rejected (its key was destroyed)");
}

// 5. tampering and forgery
{
  const s = newPair();
  pq.pqOpen(s.bob, pq.pqSeal(s.alice, te.encode("open"), { pqIdentitySecret: aliceDsa.secretKey, initFields: s.initFields }), { peerPqIdentityPub: aliceDsa.publicKey, hasInit: true, hasOneTime: true });
  const w = pq.pqSeal(s.alice, te.encode("tamper me"), { pqIdentitySecret: aliceDsa.secretKey });
  const bad = Uint8Array.from(w); bad[bad.length - 5] ^= 0xff;
  let threw = false; try { pq.pqOpen(s.bob, bad, { peerPqIdentityPub: aliceDsa.publicKey }); } catch { threw = true; }
  ok(threw, "tampered ciphertext is rejected by the outer AEAD");

  const s2 = newPair();
  const forged = pq.pqSeal(s2.alice, te.encode("forge"), { pqIdentitySecret: bobDsa.secretKey, initFields: s2.initFields });
  let threw2 = false; try { pq.pqOpen(s2.bob, forged, { peerPqIdentityPub: aliceDsa.publicKey, hasInit: true, hasOneTime: true }); } catch (e) { threw2 = /signature/.test(e.message); }
  ok(threw2, "session opener signed by the wrong ML-DSA identity is rejected");
}

// 6. the continuous re-key, and post-compromise recovery
{
  const s = newPair({ oneTime: false });
  pq.pqOpen(s.bob, pq.pqSeal(s.alice, te.encode("open"), { pqIdentitySecret: aliceDsa.secretKey, initFields: s.initFields }), { peerPqIdentityPub: aliceDsa.publicKey, hasInit: true, hasOneTime: false });
  const bobKem = pq.generatePqPreKey();
  s.alice.peerKemPub = bobKem.publicKey;
  s.alice.sinceRekey = pq.REKEY_EVERY;                 // force the re-key
  const stolenChainKey = Uint8Array.from(s.alice.chainKey);   // adversary's snapshot
  const stolenCounter = s.alice.counter;
  const w = pq.pqSeal(s.alice, te.encode("after rekey"), { pqIdentitySecret: aliceDsa.secretKey });
  const got = pq.pqOpen(s.bob, w, { peerPqIdentityPub: aliceDsa.publicKey, myKemSecretForRekey: bobKem.secretKey });
  ok(eq(got, te.encode("after rekey")), "re-keyed message round-trips");
  ok(!eq(s.alice.chainKey, stolenChainKey), "chain key changes at the re-key");
  ok(eq(s.alice.chainKey, s.bob.chainKey), "both sides agree on the post-re-key chain key");
  let locked = false;
  try {
    const thief = { chainKey: stolenChainKey, counter: stolenCounter, sinceRekey: 0, lastRekey: 0, skipped: new Map() };
    pq.pqOpen(thief, w, { peerPqIdentityPub: aliceDsa.publicKey, myKemSecretForRekey: null });
  } catch { locked = true; }
  ok(locked, "an adversary holding the pre-re-key chain key cannot read post-re-key traffic");
}

// 7. cost
{
  const s = newPair();
  pq.pqOpen(s.bob, pq.pqSeal(s.alice, te.encode("open"), { pqIdentitySecret: aliceDsa.secretKey, initFields: s.initFields }), { peerPqIdentityPub: aliceDsa.publicKey, hasInit: true, hasOneTime: true });
  const body = te.encode("x".repeat(200));
  const t0 = performance.now();
  for (let i = 0; i < 200; i++) pq.pqSeal(s.alice, body, { pqIdentitySecret: aliceDsa.secretKey });
  const per = (performance.now() - t0) / 200;
  console.log(`\nsteady-state seal: ${per.toFixed(3)}ms per message`);
  ok(per < 1, "steady-state cost is under 1ms per message");
}

console.log(fail ? `\n${fail} FAILURE(S)` : "\nALL PASSED");
process.exit(fail ? 1 : 0);
