/* The post-quantum hybrid layer (docs/POSTQUANTUM.md).
 *
 * Every Signal ciphertext is wrapped here before it goes on the wire, so an
 * attacker must break the Double Ratchet *and* ML-KEM-1024 independently. The
 * layer is additive by construction: it never sees plaintext and never
 * replaces anything the Signal library does.
 *
 * Pure functions over bytes. No storage, no network, no clock except the one
 * passed in, so the whole thing is testable without mocks.
 */

import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/hashes/utils.js";

export const ML_KEM_PUBLIC = 1568;
export const ML_KEM_CIPHERTEXT = 1568;
export const ML_DSA_PUBLIC = 1952;
export const ML_DSA_SIGNATURE = 3309;
export const NONCE_BYTES = 24;

/** Re-key after this many messages, or this long, whichever comes first. */
export const REKEY_EVERY_MESSAGES = 100;
export const REKEY_AFTER_MS = 24 * 3600 * 1000;
/** How far ahead of the expected counter we will ratchet to catch up. */
export const MAX_SKIPPED_KEYS = 1000;

export const FLAG_INIT = 1;
export const FLAG_REKEY = 2;
export const FLAG_SIGNED = 4;

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface PqSessionState {
  /** Ratchets forward on every message; never leaves the device. */
  chainKey: Uint8Array;
  headerKey: Uint8Array;
  /** Counter of the next message we will send or expect. */
  counter: number;
  /** Messages since the last re-key. */
  sinceRekey: number;
  lastRekeyAt: number;
  /** Our current ML-KEM keypair, once we have advertised one. */
  myKemPair: KeyPair | null;
  /** The peer's current ML-KEM public key, if we have seen one. */
  peerKemPublic: Uint8Array | null;
  /** Keys for messages that have not arrived yet, by counter. */
  skipped: Map<number, Uint8Array>;
}

export interface InitFields {
  ctSigned: Uint8Array;
  ctOneTime: Uint8Array | null;
}

const te = new TextEncoder();

function cat(...parts: Uint8Array[]): Uint8Array {
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

function u32(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}

function readU32(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0);
}

/* ---------------------------------------------------------------- keys ---- */

/** The long-lived ML-DSA-65 identity used to sign key-introducing messages. */
export function generatePqIdentity(): KeyPair {
  return ml_dsa65.keygen();
}

/** An ML-KEM-1024 prekey: signed, one-time, or a re-key. */
export function generatePqPreKey(): KeyPair {
  return ml_kem1024.keygen();
}

export function signPqPreKey(publicKey: Uint8Array, identitySecret: Uint8Array): Uint8Array {
  return ml_dsa65.sign(publicKey, identitySecret);
}

export function verifyPqPreKey(publicKey: Uint8Array, signature: Uint8Array, identityPublic: Uint8Array): boolean {
  return ml_dsa65.verify(signature, publicKey, identityPublic);
}

/* ------------------------------------------------------------ sessions ---- */

interface RootInput {
  /** The X3DH secret from the Signal library. Binding it here is what makes
   *  the layer additive: breaking only ML-KEM does not give the outer key. */
  classicalSecret: Uint8Array;
  ssSigned: Uint8Array;
  ssOneTime?: Uint8Array;
  initiatorIdentity: Uint8Array;
  responderIdentity: Uint8Array;
  pqIdentities: Uint8Array;
}

function deriveRoot(input: RootInput, now: number): PqSessionState {
  const ikm = cat(input.classicalSecret, input.ssSigned, input.ssOneTime ?? new Uint8Array(0));
  const info = cat(input.initiatorIdentity, input.responderIdentity, input.pqIdentities);
  const out = hkdf(sha512, ikm, te.encode("pm-pq-hybrid-v1"), info, 64);
  return {
    chainKey: out.slice(0, 32),
    headerKey: out.slice(32, 64),
    counter: 0,
    sinceRekey: 0,
    lastRekeyAt: now,
    myKemPair: null,
    peerKemPublic: null,
    skipped: new Map(),
  };
}

/** Initiator: encapsulate to the peer's published ML-KEM prekeys. */
export function initiatePqSession(args: {
  classicalSecret: Uint8Array;
  peerSignedPreKey: Uint8Array;
  peerOneTimePreKey?: Uint8Array | null;
  initiatorIdentity: Uint8Array;
  responderIdentity: Uint8Array;
  pqIdentities: Uint8Array;
  now?: number;
}): { state: PqSessionState; init: InitFields } {
  const signed = ml_kem1024.encapsulate(args.peerSignedPreKey);
  const oneTime = args.peerOneTimePreKey ? ml_kem1024.encapsulate(args.peerOneTimePreKey) : null;
  const state = deriveRoot(
    {
      classicalSecret: args.classicalSecret,
      ssSigned: signed.sharedSecret,
      ssOneTime: oneTime?.sharedSecret,
      initiatorIdentity: args.initiatorIdentity,
      responderIdentity: args.responderIdentity,
      pqIdentities: args.pqIdentities,
    },
    args.now ?? Date.now(),
  );
  return { state, init: { ctSigned: signed.cipherText, ctOneTime: oneTime?.cipherText ?? null } };
}

/** Responder: decapsulate with the secrets behind our published prekeys. */
export function acceptPqSession(args: {
  classicalSecret: Uint8Array;
  ctSigned: Uint8Array;
  ctOneTime?: Uint8Array | null;
  signedPreKeySecret: Uint8Array;
  oneTimePreKeySecret?: Uint8Array | null;
  initiatorIdentity: Uint8Array;
  responderIdentity: Uint8Array;
  pqIdentities: Uint8Array;
  now?: number;
}): PqSessionState {
  const ssSigned = ml_kem1024.decapsulate(args.ctSigned, args.signedPreKeySecret);
  const ssOneTime =
    args.ctOneTime && args.oneTimePreKeySecret
      ? ml_kem1024.decapsulate(args.ctOneTime, args.oneTimePreKeySecret)
      : undefined;
  return deriveRoot(
    {
      classicalSecret: args.classicalSecret,
      ssSigned,
      ssOneTime,
      initiatorIdentity: args.initiatorIdentity,
      responderIdentity: args.responderIdentity,
      pqIdentities: args.pqIdentities,
    },
    args.now ?? Date.now(),
  );
}

/* -------------------------------------------------------- message keys ---- */

function deriveAt(chainKey: Uint8Array, counter: number): { messageKey: Uint8Array; nextChain: Uint8Array } {
  const out = hkdf(sha512, chainKey, te.encode("pm-pq-msg"), u32(counter), 64);
  return { messageKey: out.slice(0, 32), nextChain: out.slice(32, 64) };
}

function advance(state: PqSessionState): Uint8Array {
  const { messageKey, nextChain } = deriveAt(state.chainKey, state.counter);
  state.chainKey = nextChain;
  return messageKey;
}

/**
 * The key for message `target`, ratcheting forward and stashing the keys of
 * messages that have not arrived yet. A key is removed as it is used, so a
 * replayed message finds nothing and fails.
 */
function messageKeyFor(state: PqSessionState, target: number): Uint8Array {
  const held = state.skipped.get(target);
  if (held) {
    state.skipped.delete(target);
    return held;
  }
  if (target < state.counter) throw new Error("post-quantum message key already used");
  if (target - state.counter > MAX_SKIPPED_KEYS) throw new Error("post-quantum counter jumped too far ahead");
  while (state.counter < target) {
    const { messageKey, nextChain } = deriveAt(state.chainKey, state.counter);
    state.skipped.set(state.counter, messageKey);
    state.chainKey = nextChain;
    state.counter++;
  }
  return advance(state);
}

function foldRekey(state: PqSessionState, sharedSecret: Uint8Array, now: number): void {
  state.chainKey = hkdf(sha512, cat(state.chainKey, sharedSecret), te.encode("pm-pq-rekey-v1"), new Uint8Array(0), 32);
  state.sinceRekey = 0;
  state.lastRekeyAt = now;
}

/* ------------------------------------------------------------- the wire ---- */

/**
 * Wraps one Signal ciphertext.
 *
 * ML-DSA signs exactly the messages that introduce key material — the session
 * opener and every re-key. Ordinary messages are authenticated by the outer
 * AEAD, whose key descends from the ML-KEM secret, so forging one means
 * breaking ML-KEM rather than a classical signature.
 */
export function pqSeal(
  state: PqSessionState,
  innerSignalCiphertext: Uint8Array,
  opts: { pqIdentitySecret: Uint8Array; init?: InitFields | null; now?: number },
): Uint8Array {
  const now = opts.now ?? Date.now();
  let flags = 0;
  let rekeyCt: Uint8Array | null = null;
  let rekeyPub: Uint8Array | null = null;

  if (opts.init) flags |= FLAG_INIT;

  const dueForRekey =
    state.peerKemPublic !== null &&
    (state.sinceRekey >= REKEY_EVERY_MESSAGES || now - state.lastRekeyAt >= REKEY_AFTER_MS);
  if (dueForRekey && state.peerKemPublic) {
    const enc = ml_kem1024.encapsulate(state.peerKemPublic);
    rekeyCt = enc.cipherText;
    state.myKemPair = ml_kem1024.keygen();
    rekeyPub = state.myKemPair.publicKey;
    foldRekey(state, enc.sharedSecret, now);
    flags |= FLAG_REKEY;
  }

  const signing = (flags & (FLAG_INIT | FLAG_REKEY)) !== 0;
  if (signing) flags |= FLAG_SIGNED;

  const nonce = randomBytes(NONCE_BYTES);
  const header = cat(
    new Uint8Array([1, flags]),
    u32(state.counter),
    nonce,
    opts.init ? cat(opts.init.ctSigned, opts.init.ctOneTime ?? new Uint8Array(0)) : new Uint8Array(0),
    rekeyCt && rekeyPub ? cat(rekeyCt, rekeyPub) : new Uint8Array(0),
  );

  const key = advance(state);
  const outer = xchacha20poly1305(key, nonce, header).encrypt(innerSignalCiphertext);
  key.fill(0);

  const signature = signing ? ml_dsa65.sign(cat(header, sha512(outer)), opts.pqIdentitySecret) : new Uint8Array(0);
  state.counter++;
  state.sinceRekey++;
  return cat(header, u32(signature.length), signature, outer);
}

/** Unwraps one message, returning the Signal ciphertext for the library. */
export function pqOpen(
  state: PqSessionState,
  wire: Uint8Array,
  opts: {
    peerPqIdentity: Uint8Array;
    /** Secret behind the ML-KEM public key we last advertised to this peer. */
    myKemSecret?: Uint8Array | null;
    /** True when this session was opened with a one-time prekey. */
    hasOneTime?: boolean;
    now?: number;
  },
): Uint8Array {
  const now = opts.now ?? Date.now();
  let o = 0;
  const version = wire[o++];
  const flags = wire[o++];
  if (version !== 1) throw new Error("unsupported post-quantum version");
  const counter = readU32(wire, o);
  o += 4;
  const nonce = wire.slice(o, o + NONCE_BYTES);
  o += NONCE_BYTES;
  if (flags & FLAG_INIT) o += ML_KEM_CIPHERTEXT + (opts.hasOneTime ? ML_KEM_CIPHERTEXT : 0);

  let rekeyCt: Uint8Array | null = null;
  let rekeyPub: Uint8Array | null = null;
  if (flags & FLAG_REKEY) {
    rekeyCt = wire.slice(o, o + ML_KEM_CIPHERTEXT);
    o += ML_KEM_CIPHERTEXT;
    rekeyPub = wire.slice(o, o + ML_KEM_PUBLIC);
    o += ML_KEM_PUBLIC;
  }

  const header = wire.slice(0, o);
  const sigLen = readU32(wire, o);
  o += 4;
  if (sigLen > ML_DSA_SIGNATURE) throw new Error("post-quantum signature too large");
  const signature = wire.slice(o, o + sigLen);
  o += sigLen;
  const outer = wire.slice(o);

  if (flags & FLAG_SIGNED) {
    if (!ml_dsa65.verify(signature, cat(header, sha512(outer)), opts.peerPqIdentity)) {
      throw new Error("post-quantum signature invalid");
    }
  } else if (flags & (FLAG_INIT | FLAG_REKEY)) {
    // A key-introducing message must carry a signature; refusing here is what
    // stops an attacker stripping it to smuggle in their own ML-KEM key.
    throw new Error("key-introducing message is unsigned");
  }

  if (rekeyCt) {
    if (!opts.myKemSecret) throw new Error("re-key received but no ML-KEM secret held");
    foldRekey(state, ml_kem1024.decapsulate(rekeyCt, opts.myKemSecret), now);
    state.peerKemPublic = rekeyPub;
  }

  const key = messageKeyFor(state, counter);
  const inner = xchacha20poly1305(key, nonce, header).decrypt(outer);
  key.fill(0);
  if (counter >= state.counter) state.counter = counter + 1;
  state.sinceRekey++;
  return inner;
}

/* ------------------------------------------------------- serialisation ---- */

/** The session state, for the encrypted store. Keys are raw bytes. */
export interface SerializedPqSession {
  chainKey: number[];
  headerKey: number[];
  counter: number;
  sinceRekey: number;
  lastRekeyAt: number;
  myKemPublic: number[] | null;
  myKemSecret: number[] | null;
  peerKemPublic: number[] | null;
  skipped: Array<[number, number[]]>;
}

export function serializePqSession(s: PqSessionState): SerializedPqSession {
  return {
    chainKey: Array.from(s.chainKey),
    headerKey: Array.from(s.headerKey),
    counter: s.counter,
    sinceRekey: s.sinceRekey,
    lastRekeyAt: s.lastRekeyAt,
    myKemPublic: s.myKemPair ? Array.from(s.myKemPair.publicKey) : null,
    myKemSecret: s.myKemPair ? Array.from(s.myKemPair.secretKey) : null,
    peerKemPublic: s.peerKemPublic ? Array.from(s.peerKemPublic) : null,
    skipped: Array.from(s.skipped.entries()).map(([k, v]) => [k, Array.from(v)] as [number, number[]]),
  };
}

export function deserializePqSession(j: SerializedPqSession): PqSessionState {
  return {
    chainKey: Uint8Array.from(j.chainKey),
    headerKey: Uint8Array.from(j.headerKey),
    counter: j.counter,
    sinceRekey: j.sinceRekey,
    lastRekeyAt: j.lastRekeyAt,
    myKemPair:
      j.myKemPublic && j.myKemSecret
        ? { publicKey: Uint8Array.from(j.myKemPublic), secretKey: Uint8Array.from(j.myKemSecret) }
        : null,
    peerKemPublic: j.peerKemPublic ? Uint8Array.from(j.peerKemPublic) : null,
    skipped: new Map(j.skipped.map(([k, v]) => [k, Uint8Array.from(v)])),
  };
}
