/* Reference implementation of the post-quantum hybrid layer in docs/POSTQUANTUM.md.
   Pure functions over bytes; no storage, no network. Ported to TypeScript as
   client/src/core/pq.ts once the core lands. */

import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";

export const KEM_PUB = 1568, KEM_CT = 1568, DSA_SIG = 3309, NONCE = 24;
export const REKEY_EVERY = 100;
export const REKEY_AFTER_MS = 24 * 3600 * 1000;
const te = new TextEncoder();
const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(n); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); return b; };

export const FLAG_INIT = 1, FLAG_REKEY = 2, FLAG_SIGNED = 4;

/* ---- identity and prekeys ---- */
export function generatePqIdentity() { return ml_dsa65.keygen(); }
export function generatePqPreKey() { return ml_kem1024.keygen(); }

/* ---- session establishment ---- */
/* Initiator: classicalSecret comes from the Signal library's X3DH. */
export function initiateSession({ classicalSecret, peerSignedPreKeyPub, peerOneTimePreKeyPub, initiatorIdentity, responderIdentity, pqIdentities }) {
  const s = ml_kem1024.encapsulate(peerSignedPreKeyPub);
  const o = peerOneTimePreKeyPub ? ml_kem1024.encapsulate(peerOneTimePreKeyPub) : null;
  const state = deriveRoot({ classicalSecret, ssSigned: s.sharedSecret, ssOneTime: o?.sharedSecret, initiatorIdentity, responderIdentity, pqIdentities });
  return { state, ctSigned: s.cipherText, ctOneTime: o?.cipherText ?? null };
}
/* Responder */
export function acceptSession({ classicalSecret, ctSigned, ctOneTime, signedPreKeySecret, oneTimePreKeySecret, initiatorIdentity, responderIdentity, pqIdentities }) {
  const ssSigned = ml_kem1024.decapsulate(ctSigned, signedPreKeySecret);
  const ssOneTime = ctOneTime && oneTimePreKeySecret ? ml_kem1024.decapsulate(ctOneTime, oneTimePreKeySecret) : undefined;
  return deriveRoot({ classicalSecret, ssSigned, ssOneTime, initiatorIdentity, responderIdentity, pqIdentities });
}
function deriveRoot({ classicalSecret, ssSigned, ssOneTime, initiatorIdentity, responderIdentity, pqIdentities }) {
  const ikm = cat(classicalSecret, ssSigned, ssOneTime ?? new Uint8Array(0));
  const info = cat(initiatorIdentity, responderIdentity, pqIdentities);
  const out = hkdf(sha512, ikm, te.encode("pm-pq-hybrid-v1"), info, 64);
  return { chainKey: out.slice(0, 32), headerKey: out.slice(32, 64), counter: 0, sinceRekey: 0, lastRekey: Date.now(), myKemPair: null, peerKemPub: null };
}

/* ---- per-message keys ---- */
const MAX_SKIP = 1000;
function deriveAt(chainKey, counter) {
  const out = hkdf(sha512, chainKey, te.encode("pm-pq-msg"), u32(counter), 64);
  return { messageKey: out.slice(0, 32), nextChain: out.slice(32, 64) };
}
function nextMessageKey(state) {
  const { messageKey, nextChain } = deriveAt(state.chainKey, state.counter);
  state.chainKey = nextChain;                   // ratchet forward
  return messageKey;                            // used once, then destroyed
}
/* Ratchet forward to `target`, stashing the keys of messages that have not
   arrived yet so they can still be opened when they do. */
function messageKeyFor(state, target) {
  const stash = state.skipped || (state.skipped = new Map());
  if (stash.has(target)) { const k = stash.get(target); stash.delete(target); return k; }
  if (target < state.counter) throw new Error("pq message key already used or too old");
  if (target - state.counter > MAX_SKIP) throw new Error("pq counter jumped too far");
  while (state.counter < target) {
    const { messageKey, nextChain } = deriveAt(state.chainKey, state.counter);
    stash.set(state.counter, messageKey);
    state.chainKey = nextChain;
    state.counter++;
  }
  return nextMessageKey(state);
}
function foldRekey(state, ssRekey) {
  state.chainKey = hkdf(sha512, cat(state.chainKey, ssRekey), te.encode("pm-pq-rekey-v1"), new Uint8Array(0), 32);
  state.sinceRekey = 0; state.lastRekey = Date.now();
}

/* ---- encrypt / decrypt ---- */
export function pqSeal(state, innerSignalCiphertext, { pqIdentitySecret, initFields = null, now = Date.now() } = {}) {
  let flags = 0, rekeyCt = null, rekeyPub = null;
  if (initFields) flags |= FLAG_INIT;
  const wantRekey = state.peerKemPub && (state.sinceRekey >= REKEY_EVERY || now - state.lastRekey >= REKEY_AFTER_MS);
  if (wantRekey) {
    const enc = ml_kem1024.encapsulate(state.peerKemPub);
    rekeyCt = enc.cipherText;
    state.myKemPair = ml_kem1024.keygen();
    rekeyPub = state.myKemPair.publicKey;
    foldRekey(state, enc.sharedSecret);
    flags |= FLAG_REKEY;
  }
  /* ML-DSA signs exactly the messages that introduce new key material: the
     session opener and every re-key. Ordinary messages are authenticated by
     the outer AEAD, whose key descends from the ML-KEM secret, so forging one
     requires breaking ML-KEM rather than a classical signature. */
  const signThis = (flags & (FLAG_INIT | FLAG_REKEY)) !== 0;
  if (signThis) flags |= FLAG_SIGNED;

  const nonce = randomBytes(NONCE);
  const counter = state.counter;
  const header = cat(new Uint8Array([1, flags]), u32(counter), nonce,
    initFields ? cat(initFields.ctSigned, initFields.ctOneTime ?? new Uint8Array(0)) : new Uint8Array(0),
    rekeyCt ? cat(rekeyCt, rekeyPub) : new Uint8Array(0));
  const key = nextMessageKey(state);
  const outer = xchacha20poly1305(key, nonce, header).encrypt(innerSignalCiphertext);
  key.fill(0);
  const sig = signThis ? ml_dsa65.sign(cat(header, sha512(outer)), pqIdentitySecret) : new Uint8Array(0);
  state.counter++; state.sinceRekey++;
  return cat(header, u32(sig.length), sig, outer);
}

export function pqOpen(state, wire, { peerPqIdentityPub, myKemSecretForRekey = null, hasInit = false, hasOneTime = false } = {}) {
  let o = 0;
  const version = wire[o++], flags = wire[o++];
  if (version !== 1) throw new Error("unsupported pq version");
  const counter = new DataView(wire.buffer, wire.byteOffset + o, 4).getUint32(0); o += 4;
  const nonce = wire.slice(o, o + NONCE); o += NONCE;
  if (flags & FLAG_INIT) { o += KEM_CT + (hasOneTime ? KEM_CT : 0); }
  let rekeyCt = null, rekeyPub = null;
  if (flags & FLAG_REKEY) { rekeyCt = wire.slice(o, o + KEM_CT); o += KEM_CT; rekeyPub = wire.slice(o, o + KEM_PUB); o += KEM_PUB; }
  const header = wire.slice(0, o);
  const sigLen = new DataView(wire.buffer, wire.byteOffset + o, 4).getUint32(0); o += 4;
  const sig = wire.slice(o, o + sigLen); o += sigLen;
  const outer = wire.slice(o);

  if (flags & FLAG_SIGNED) {
    if (!ml_dsa65.verify(sig, cat(header, sha512(outer)), peerPqIdentityPub)) throw new Error("pq signature invalid");
  }
  if (rekeyCt) {
    if (!myKemSecretForRekey) throw new Error("rekey received but no KEM secret held");
    foldRekey(state, ml_kem1024.decapsulate(rekeyCt, myKemSecretForRekey));
    state.peerKemPub = rekeyPub;
  }
  const key = messageKeyFor(state, counter);
  const inner = xchacha20poly1305(key, nonce, header).decrypt(outer);
  key.fill(0);
  if (counter >= state.counter) { state.counter = counter + 1; }
  state.sinceRekey++;
  return inner;
}
