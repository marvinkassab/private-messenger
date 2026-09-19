/* The `Messenger` facade: wires store + signal + content + groups + attachments + api
   into the interface from ../types. See docs/PROTOCOL.md and docs/API.md for the wire
   contract this file implements. */

import { type KeyPairType } from "@privacyresearch/libsignal-protocol-typescript";
import { safetyNumberFor } from "./fingerprint";
import type {
  Account,
  AttachmentMeta,
  Chat,
  ChatId,
  Contact,
  ConnectionState,
  GroupState,
  Message,
  Messenger,
  MessengerEvent,
  PreKeyBundleWire,
  SafetyNumber,
  Username,
} from "../types";
import {
  DEVICE_ID,
  SEALED_TYPE,
  SignalSessions,
  SignalStore,
  classicalAgreement,
  generateEphemeralKeyPair,
  generateIdentity,
  generatePreKeys,
  generateSignedPreKey,
  preKeyWire,
  sealMessage,
  signedPreKeyWire,
  unsealMessage,
  xeddsaSign,
  xeddsaVerify,
} from "./signal";
import { ApiClient, WebSocketTransport, type FetchLike, type Transport, type TransportHandlers } from "./api";
import { decodeContent, encodeContent, type AttachmentPointer, type Content, type GroupUpdate } from "./content";
import {
  ML_DSA_PUBLIC,
  ML_KEM_CIPHERTEXT,
  NONCE_BYTES,
  acceptPqSession,
  deserializePqSession,
  generatePqIdentity,
  generatePqPreKey,
  initiatePqSession,
  pqOpen,
  pqSeal,
  serializePqSession,
  signPqPreKey,
  verifyPqPreKey,
  type KeyPair as PqKeyPair,
  type PqSessionState,
  type SerializedPqSession,
} from "./pq";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { applyGroupUpdate, describeGroupChange, isGroupAdmin } from "./groups";
import { decryptAttachment, encryptAttachment, isImageMime, prepareImage } from "./attachments";
import { type RecordIndex, Store } from "./store";
import {
  PBKDF2_ITERATIONS,
  aesGcmDecrypt,
  aesGcmEncrypt,
  b64Decode,
  b64Encode,
  concatBytes,
  deriveKeyBytes,
  fromJsonSafe,
  randomBytes,
  randomId,
  toArrayBuffer,
  toJsonSafe,
  uniq,
  utf8Decode,
  utf8Encode,
} from "./util";

/* ---------- internal storage shapes (superset of the public contract) ---------- */

/** Contact record as we store it: adds fields the UI never sees. */
interface StoredContact extends Contact {
  deliveryToken?: string; // their unidentified-access token, once we know it
  profileSent?: boolean; // have we sent them our own profile/token yet
  pendingIdentityKeyB64?: string; // captured by the identity-change hook, committed by acceptIdentityChange
}

/** Message record as we store it: keeps attachment crypto material out of the public `attachment` field. */
interface StoredMessage extends Message {
  _pointer?: AttachmentPointer;
  _expiresSeconds?: number; // the disappearing-timer value in effect when this message was sent/received
}

export class IdentityChangedError extends Error {
  constructor(public readonly username: string) {
    super(`identity key changed for ${username}; call acceptIdentityChange() first`);
    this.name = "IdentityChangedError";
  }
}

function isIdentityChangedLibError(e: unknown): boolean {
  return e instanceof Error && e.message === "Identity key changed";
}

/** Thrown when a contact we've previously established the post-quantum hybrid layer with
 *  presents a bundle (or, defensively, a live message) that has silently dropped it.
 *  docs/POSTQUANTUM.md: "a client that has previously seen them for this contact treats
 *  their absence as a downgrade and refuses." */
export class PqDowngradeError extends Error {
  constructor(public readonly username: string) {
    super(`post-quantum keys for ${username} disappeared; refusing to fall back to classical-only`);
    this.name = "PqDowngradeError";
  }
}

/* ---------- the post-quantum hybrid layer: per-peer session storage and wire framing ----------
 *
 * pq.ts is the crypto and is untouched. What lives here is the plumbing docs/POSTQUANTUM.md
 * assumes but that this client's Signal library (a port of Signal's older JS implementation)
 * does not give us for free:
 *
 *   1. Binding a classical secret into the hybrid root (`classicalSecret` below). The spec
 *      calls for the library's internal X3DH secret SK_classical. That value is not
 *      reachable through the library's StorageType interface: the initiator's copy is
 *      overwritten by an extra ratchet step before session establishment returns, and the
 *      responder's copy only becomes available as a *side effect* of decrypting the inner
 *      Signal ciphertext -- which is exactly what the outer post-quantum layer must be
 *      opened *before* we can even attempt (pq.ts wraps the raw Signal ciphertext bytes; the
 *      library cannot see them until we hand back the unwrapped bytes). Reaching into the
 *      library's private session-record fields to grab it early is not an option either: the
 *      responder cannot compute the matching value until AFTER the same decrypt, for the same
 *      reason.
 *
 *      So this client performs an independent, additional X25519 Diffie-Hellman: a fresh
 *      one-shot ephemeral key (generated by the initiator) against the recipient's long-term
 *      classical identity key. This is a genuine classical secret -- deriving it requires
 *      breaking X25519 or stealing the recipient's identity private key, exactly like the
 *      real X3DH secret would -- and, crucially, both sides can compute it with information
 *      each of them already has or that travels in the clear, with no circular dependency on
 *      the Signal library's internal state. It satisfies the spec's actual requirement ("an
 *      attacker who breaks only the KEM still cannot derive the outer key"). It is NOT
 *      literally SK_classical, so it does not inherit X3DH's multi-DH forward-secrecy
 *      properties against a compromised long-term key; that cost is deliberate and is called
 *      out in the final report rather than silently accepted.
 *
 *   2. A one-time-use "opener" header carrying that ephemeral public key plus the sender's
 *      ML-DSA identity public key (needed to verify the signed opener and, for the info
 *      binding, both sides must present the same value) -- again because the responder
 *      cannot otherwise learn the sender's post-quantum identity key before the Signal layer
 *      would normally teach it to us (also only as a decrypt side effect). The one-time
 *      ML-KEM prekey's keyId also has to travel here for the same reason: pq.ts's wire
 *      format carries the prekey ciphertext but not which numbered prekey it was consumed
 *      from, and the caller (this file) is what looks it up in storage.
 *
 * Everything below is self-describing per envelope via a one-byte marker, entirely inside the
 * `content` bytes the server already treats as opaque, so it needs no server or protocol
 * changes and no new EnvelopeWire field.
 */

const PQW_CLASSICAL = 0; // content = raw Signal ciphertext, no hybrid layer for this contact
const PQW_ORDINARY = 1; // content = pq.ts wire bytes, on an already-established hybrid session
const PQW_OPENER = 2; // content = [ephPub(33)][senderPqIdentityPub(1952)][hasOneTime(1)][oneTimeKeyId(4)?] + pq.ts wire bytes

interface PqPendingInit {
  ctSignedB64: string;
  ctOneTimeB64: string | null;
  oneTimeKeyId: number | null;
  ephPubB64: string;
}

/** Everything persisted per peer for the hybrid layer: two independent pq.ts session states
 *  (chain keys, counters and the skipped-key store, all covered by serializePqSession) -- one
 *  per direction -- plus, until our first message to them actually goes out, the not-yet-sent
 *  opener fields. Stored in the "sessions" store (already encrypted at rest) under
 *  `pq:<username>`, alongside -- and backed up/restored the same way as -- the classical
 *  Signal session record.
 *
 *  pq.ts's PqSessionState is a SINGLE flat ratchet: `pqSeal` and `pqOpen` both advance the
 *  same `counter`/`chainKey`, with no separate sending/receiving chains the way the classical
 *  Signal library keeps (session-builder.js's `calculateSendingRatchet`, SessionCipher's
 *  `ChainType.SENDING`/`RECEIVING`). Using ONE such state for both directions of a real,
 *  concurrent conversation is unsafe: an unawaited background send -- a delivered receipt,
 *  say -- can advance "the" counter on one side just as the other side independently sends
 *  its own next message, and whichever arrives second is then rejected as "already used".
 *  This is not a pq.ts bug (its own reference suite plausibly only exercises strict,
 *  synchronized round trips) and is not fixed by touching pq.ts. It is fixed here by
 *  splitting the single root chain/header key pq.ts hands back into two independent chains --
 *  one the initiator only ever sends on, one the responder only ever sends on -- via an
 *  ordinary HKDF domain-separation step, exactly mirroring why the classical library keeps
 *  separate sending/receiving chains in the first place. Both directions still ultimately
 *  descend from the same hybrid root (deriveRoot's ikm), so this splits, but does not weaken,
 *  what pq.ts already derived. */
interface PqPeerSession {
  send: SerializedPqSession;
  recv: SerializedPqSession;
  pendingInit: PqPendingInit | null;
}

function pqSessionKey(username: string): string {
  return `pq:${username}`;
}

const PQ_DIR_I2R = "pm-pq-dir-i2r"; // initiator -> responder
const PQ_DIR_R2I = "pm-pq-dir-r2i"; // responder -> initiator

/** One independent directional chain, split off the shared root pq.ts derived (see the
 *  PqPeerSession comment above). `root` is used only for its `chainKey`/`headerKey`; its
 *  counter, skipped-key store and KEM fields are not touched or reused. */
function splitDirectionalState(root: Pick<PqSessionState, "chainKey" | "headerKey">, label: typeof PQ_DIR_I2R | typeof PQ_DIR_R2I, now: number): PqSessionState {
  const material = concatBytes(root.chainKey, root.headerKey);
  const out = hkdf(sha512, material, utf8Encode(label), new Uint8Array(0), 64);
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

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0);
  return b;
}

function readU32be(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0);
}

const CLASSICAL_IDENTITY_BYTES = 33;

function buildOpenerHeader(ephPub: Uint8Array, senderPqIdentityPub: Uint8Array, oneTimeKeyId: number | null): Uint8Array {
  return concatBytes(
    ephPub,
    senderPqIdentityPub,
    new Uint8Array([oneTimeKeyId !== null ? 1 : 0]),
    oneTimeKeyId !== null ? u32be(oneTimeKeyId) : new Uint8Array(0),
  );
}

function parseOpenerHeader(bytes: Uint8Array): {
  ephPub: Uint8Array;
  senderPqIdentityPub: Uint8Array;
  oneTimeKeyId: number | null;
  rest: Uint8Array;
} {
  let o = 0;
  const ephPub = bytes.slice(o, o + CLASSICAL_IDENTITY_BYTES);
  o += CLASSICAL_IDENTITY_BYTES;
  const senderPqIdentityPub = bytes.slice(o, o + ML_DSA_PUBLIC);
  o += ML_DSA_PUBLIC;
  const hasOneTime = bytes[o] === 1;
  o += 1;
  let oneTimeKeyId: number | null = null;
  if (hasOneTime) {
    oneTimeKeyId = readU32be(bytes, o);
    o += 4;
  }
  return { ephPub, senderPqIdentityPub, oneTimeKeyId, rest: bytes.slice(o) };
}

/** Pulls `ct_signed` / `ct_onetime` back out of a pq.ts opener wire, mirroring the fixed
 *  layout documented in docs/POSTQUANTUM.md ("The outer layer, per message"): pq.ts's own
 *  `pqOpen` skips these same bytes rather than returning them, since it assumes the session
 *  state (and thus the KEM secrets) already exists; establishing that state as the responder
 *  is exactly the job of this function's caller. */
function parseInitFieldsFromPqWire(wire: Uint8Array, hasOneTime: boolean): { ctSigned: Uint8Array; ctOneTime: Uint8Array | null } {
  const FIXED = 1 + 1 + 4 + NONCE_BYTES; // version + flags + counter + nonce
  let o = FIXED;
  const ctSigned = wire.slice(o, o + ML_KEM_CIPHERTEXT);
  o += ML_KEM_CIPHERTEXT;
  const ctOneTime = hasOneTime ? wire.slice(o, o + ML_KEM_CIPHERTEXT) : null;
  return { ctSigned, ctOneTime };
}

function removeUserFromReactions(reactions: Record<string, Username[]>, user: Username): void {
  for (const emoji of Object.keys(reactions)) {
    const next = reactions[emoji]!.filter((u) => u !== user);
    if (next.length) reactions[emoji] = next;
    else delete reactions[emoji];
  }
}

const STATUS_RANK: Record<Message["status"], number> = { failed: -1, pending: 0, sent: 1, delivered: 2, read: 3 };

function urlB64ToUint8Array(base64Url: string): Uint8Array {
  const pad = "=".repeat((4 - (base64Url.length % 4)) % 4);
  const base64 = (base64Url + pad).replace(/-/g, "+").replace(/_/g, "/");
  return b64Decode(base64);
}

/** Batches delivered-receipt ids per sender: up to 50 ids, at most one send per second per peer. */
class ReceiptBatcher {
  private pending = new Map<string, Set<string>>();
  private timers = new Map<string, ReturnType<typeof setTimeout>>();
  private lastSentAt = new Map<string, number>();

  constructor(private readonly send: (sender: string, ids: string[]) => Promise<void>) {}

  add(sender: string, id: string): void {
    let set = this.pending.get(sender);
    if (!set) {
      set = new Set();
      this.pending.set(sender, set);
    }
    set.add(id);
    if (set.size >= 50) {
      this.flush(sender);
      return;
    }
    if (this.timers.has(sender)) return;
    const last = this.lastSentAt.get(sender) ?? 0;
    const wait = Math.max(0, 1000 - (Date.now() - last));
    const t = setTimeout(() => this.flush(sender), wait);
    (t as unknown as { unref?: () => void }).unref?.();
    this.timers.set(sender, t);
  }

  private flush(sender: string): void {
    const timer = this.timers.get(sender);
    if (timer) clearTimeout(timer);
    this.timers.delete(sender);
    const set = this.pending.get(sender);
    if (!set || set.size === 0) return;
    const ids = Array.from(set).slice(0, 50);
    for (const id of ids) set.delete(id);
    if (set.size === 0) this.pending.delete(sender);
    this.lastSentAt.set(sender, Date.now());
    void this.send(sender, ids).catch(() => {
      /* best effort; a future receipt will cover it if this is retried by the app */
    });
    if (set.size > 0) this.add(sender, Array.from(set)[0]!); // reschedule remaining ids
  }
}

export interface MessengerDeps {
  baseUrl: string;
  appUrl?: string;
  fetch?: FetchLike;
  transport?: Transport;
  dbName?: string;
  indexedDB?: IDBFactory;
  WebSocketImpl?: typeof WebSocket;
  /** How often the disappearing-message sweep runs, in ms. Default 1000. */
  sweepIntervalMs?: number;
}

export function createMessengerImpl(opts: MessengerDeps): Messenger {
  return new MessengerImpl(opts);
}

export class MessengerImpl implements Messenger {
  private readonly store: Store;
  private readonly signalStore: SignalStore;
  private readonly sessions: SignalSessions;
  private readonly api: ApiClient;
  private readonly transport: Transport;
  private readonly appUrl?: string;
  private readonly sweepIntervalMs: number;

  private acct: Account | null = null;
  private locked = false;
  private ready = false;
  private connState: ConnectionState = "offline";
  private readonly listeners = new Set<(e: MessengerEvent) => void>();
  private seenIds = new Set<string>();
  private sweepTimer: ReturnType<typeof setInterval> | null = null;
  private readonly typingSentAt = new Map<string, number>();
  private readonly typingState = new Map<string, Set<string>>();
  private readonly typingTimers = new Map<string, ReturnType<typeof setTimeout>>();
  private pushEnabledFlag = false;
  private readonly deliveredBatcher: ReceiptBatcher;

  constructor(opts: MessengerDeps) {
    this.store = new Store({ dbName: opts.dbName, indexedDB: opts.indexedDB });
    this.signalStore = new SignalStore(this.store);
    this.sessions = new SignalSessions(this.signalStore);
    this.api = new ApiClient({ baseUrl: opts.baseUrl, fetch: opts.fetch });
    this.transport = opts.transport ?? new WebSocketTransport({ baseUrl: opts.baseUrl, WebSocketImpl: opts.WebSocketImpl });
    this.appUrl = opts.appUrl;
    this.sweepIntervalMs = opts.sweepIntervalMs ?? 1000;
    this.deliveredBatcher = new ReceiptBatcher(async (sender, ids) => {
      const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "receipt", receipt: "delivered", ref: ids.join(",") };
      await this.deliverToUser(sender, content);
    });
  }

  /* ================= lifecycle ================= */

  async init(): Promise<{ account: Account | null; locked: boolean }> {
    await this.store.open();
    this.locked = this.store.isLocked();
    this.acct = (await this.store.get<Account>("kv", "account")) ?? null;
    if (this.locked) return { account: this.acct, locked: true };
    await this.ensureReady();
    return { account: this.acct, locked: false };
  }

  private async ensureReady(): Promise<void> {
    if (this.ready) return;
    this.ready = true;
    this.signalStore.setHooks({ onIdentityChange: (username, newKey) => this.handleIdentityChange(username, newKey) });
    const seen = (await this.store.get<string[]>("kv", "seenIds")) ?? [];
    this.seenIds = new Set(seen);
    this.pushEnabledFlag = (await this.store.get<boolean>("kv", "pushEnabled")) ?? false;
    this.startSweep();
  }

  private configureSigner(): void {
    if (!this.acct) return;
    const acct = this.acct;
    this.api.setSigner({
      username: acct.username,
      deviceId: acct.deviceId,
      sign: async (message) => {
        const kp = await this.signalStore.getIdentityKeyPair();
        if (!kp) throw new Error("no identity key pair");
        return xeddsaSign(kp.privKey, message);
      },
    });
  }

  /* ---------- post-quantum key storage (docs/POSTQUANTUM.md) ----------
   * Private halves live in the same encrypted stores the classical keys use, under key
   * names that cannot collide with the classical (numeric-id) ones: the "identity" store
   * gains "pqIdentityKeyPair", "signedPreKeys" gains "pq-signed", and "prekeys" gains one
   * entry per one-time prekey named "pq:<keyId>". All three stores are already in
   * ENCRYPTED_STORES (store.ts), so this material is covered by the app lock exactly like
   * the classical identity/prekeys are. */

  private async pqSaveIdentity(kp: PqKeyPair): Promise<void> {
    await this.store.put("identity", "pqIdentityKeyPair", { publicKey: kp.publicKey, secretKey: kp.secretKey });
  }

  private async pqLoadIdentity(): Promise<PqKeyPair | undefined> {
    return this.store.get<PqKeyPair>("identity", "pqIdentityKeyPair");
  }

  private async pqSaveSignedPreKey(entry: { keyId: number; publicKey: Uint8Array; secretKey: Uint8Array }): Promise<void> {
    await this.store.put("signedPreKeys", "pq-signed", entry);
  }

  private async pqLoadSignedPreKey(): Promise<{ keyId: number; publicKey: Uint8Array; secretKey: Uint8Array } | undefined> {
    return this.store.get("signedPreKeys", "pq-signed");
  }

  private async pqSaveOneTimePreKeys(entries: Array<{ keyId: number; publicKey: Uint8Array; secretKey: Uint8Array }>): Promise<void> {
    for (const e of entries) await this.store.put("prekeys", `pq:${e.keyId}`, { publicKey: e.publicKey, secretKey: e.secretKey });
  }

  /** Loads and removes (consumes) one one-time prekey's secret; null if unknown or already used. */
  private async pqTakeOneTimePreKey(keyId: number): Promise<Uint8Array | null> {
    const rec = await this.store.get<{ publicKey: Uint8Array; secretKey: Uint8Array }>("prekeys", `pq:${keyId}`);
    if (!rec) return null;
    await this.store.delete("prekeys", `pq:${keyId}`);
    return rec.secretKey;
  }

  private async mustClassicalIdentity(): Promise<{ privKey: ArrayBuffer; pubBytes: Uint8Array }> {
    const kp = await this.signalStore.getIdentityKeyPair();
    if (!kp) throw new Error("no local identity");
    return { privKey: kp.privKey, pubBytes: new Uint8Array(kp.pubKey) };
  }

  async register(username: Username, inviteCode: string, displayName: string): Promise<Account> {
    await this.store.open();
    if (this.locked) throw new Error("store is locked");
    if (this.acct) throw new Error("already registered");
    const identity = await generateIdentity();
    await this.signalStore.setIdentity(identity);
    const signedPreKey = await generateSignedPreKey(identity.identityKeyPair, 1);
    await this.signalStore.storeSignedPreKey(1, signedPreKey.keyPair);
    await this.store.put("kv", "signedPreKeyId", 1);
    const preKeys = await generatePreKeys(1, 100);
    for (const pk of preKeys) await this.signalStore.storePreKey(pk.keyId, pk.keyPair);
    await this.store.put("kv", "nextPreKeyId", 101);
    const deliveryToken = randomBytes(32);
    await this.store.put("kv", "deliveryToken", b64Encode(deliveryToken));

    // Post-quantum half (docs/POSTQUANTUM.md): generated unconditionally for every account.
    const pqIdentity = generatePqIdentity();
    await this.pqSaveIdentity(pqIdentity);
    const pqSignedKeyId = 1;
    const pqSignedPreKeyPair = generatePqPreKey();
    await this.pqSaveSignedPreKey({ keyId: pqSignedKeyId, publicKey: pqSignedPreKeyPair.publicKey, secretKey: pqSignedPreKeyPair.secretKey });
    // Bound by BOTH the classical identity (XEdDSA, same primitive the classical signed
    // prekey uses) and the ML-DSA identity, per docs/POSTQUANTUM.md.
    const pqClassicalSig = await xeddsaSign(identity.identityKeyPair.privKey, pqSignedPreKeyPair.publicKey);
    const pqSig = signPqPreKey(pqSignedPreKeyPair.publicKey, pqIdentity.secretKey);
    const pqOneTimeKeys = Array.from({ length: 100 }, (_, i) => ({ keyId: i + 1, ...generatePqPreKey() }));
    await this.pqSaveOneTimePreKeys(pqOneTimeKeys);
    await this.store.put("kv", "pqNextPreKeyId", 101);

    const acct: Account = {
      username,
      deviceId: DEVICE_ID,
      identityKeyB64: b64Encode(identity.identityKeyPair.pubKey),
      registrationId: identity.registrationId,
      displayName,
      createdAt: Date.now(),
    };
    this.acct = acct;
    this.configureSigner();
    try {
      await this.api.register({
        username,
        inviteCode,
        identityKey: acct.identityKeyB64,
        registrationId: identity.registrationId,
        deliveryToken: b64Encode(deliveryToken),
        signedPreKey: signedPreKeyWire(signedPreKey),
        oneTimePreKeys: preKeys.map(preKeyWire),
        pqIdentityKey: b64Encode(pqIdentity.publicKey),
        pqSignedPreKey: {
          keyId: pqSignedKeyId,
          publicKey: b64Encode(pqSignedPreKeyPair.publicKey),
          signature: b64Encode(pqClassicalSig),
          pqSignature: b64Encode(pqSig),
        },
        pqOneTimePreKeys: pqOneTimeKeys.map((k) => ({ keyId: k.keyId, publicKey: b64Encode(k.publicKey) })),
      });
    } catch (e) {
      this.acct = null;
      this.api.setSigner(null);
      throw e;
    }
    await this.store.put("kv", "account", acct);
    await this.ensureReady();
    return acct;
  }

  account(): Account | null {
    return this.acct;
  }

  async connect(): Promise<void> {
    if (!this.acct) throw new Error("not registered");
    if (this.locked) throw new Error("store is locked");
    await this.ensureReady();
    this.configureSigner();
    const acct = this.acct;
    const handlers: TransportHandlers = {
      onEnvelope: (env) => this.handleEnvelope(env),
      onState: (state) => {
        this.connState = state;
        this.emit({ type: "connection", state });
      },
      onQueueEmpty: () => {
        void this.topUpPreKeys().catch(() => {});
      },
    };
    this.transport.connect({ username: acct.username, deviceId: acct.deviceId, params: () => this.api.wsAuthParams() }, handlers);
  }

  disconnect(): void {
    this.transport.disconnect();
    this.connState = "offline";
  }

  connectionState(): ConnectionState {
    return this.connState;
  }

  on(handler: (e: MessengerEvent) => void): () => void {
    this.listeners.add(handler);
    return () => this.listeners.delete(handler);
  }

  private emit(e: MessengerEvent): void {
    for (const h of Array.from(this.listeners)) {
      try {
        h(e);
      } catch {
        /* a misbehaving listener must not break delivery for the others */
      }
    }
  }

  private emitError(message: string): void {
    this.emit({ type: "error", message });
  }

  private assertReady(): void {
    if (this.locked) throw new Error("store is locked");
    if (!this.acct) throw new Error("not registered");
  }

  private me(): string {
    if (!this.acct) throw new Error("not registered");
    return this.acct.username;
  }

  /* ================= identity / sessions ================= */

  private wrapIdentityError(username: string, e: unknown): Error {
    return isIdentityChangedLibError(e) ? new IdentityChangedError(username) : (e as Error);
  }

  /** Classical X3DH (via the Signal library) plus, when the bundle offers it, the post-quantum
   *  hybrid session (docs/POSTQUANTUM.md "Session establishment"). Verifies the post-quantum
   *  signed prekey under BOTH signatures, aborting on either failure; refuses a bundle that has
   *  silently dropped post-quantum keys we previously saw for this contact (PqDowngradeError);
   *  otherwise marks a contact who never had them "classical only". Returns the post-quantum
   *  fields for the caller to fold into its own Contact upsert. */
  private async establishSession(username: string, bundle: PreKeyBundleWire): Promise<{ pqIdentityKeyB64?: string; classicalOnly: boolean }> {
    const contact = await this.store.get<StoredContact>("contacts", username);
    const hadPq = !!contact?.pqIdentityKeyB64;
    const bundleHasPq = !!(bundle.pqIdentityKey && bundle.pqSignedPreKey);

    if (bundleHasPq) {
      const classicalIdKey = b64Decode(bundle.identityKey);
      const pqIdKey = b64Decode(bundle.pqIdentityKey!);
      const spkPub = b64Decode(bundle.pqSignedPreKey!.publicKey);
      const classicalOk = await xeddsaVerify(classicalIdKey, spkPub, b64Decode(bundle.pqSignedPreKey!.signature));
      const pqOk = verifyPqPreKey(spkPub, b64Decode(bundle.pqSignedPreKey!.pqSignature), pqIdKey);
      if (!classicalOk || !pqOk) throw new Error(`post-quantum signed prekey signature invalid for ${username}`);
    } else if (hadPq) {
      throw new PqDowngradeError(username);
    }

    await this.sessions.processBundle(bundle);

    if (bundleHasPq) {
      await this.setupPqSessionAsInitiator(username, bundle);
      return { pqIdentityKeyB64: bundle.pqIdentityKey, classicalOnly: false };
    }
    return { classicalOnly: true };
  }

  /** Encapsulates to the peer's published post-quantum prekeys and derives the hybrid root
   *  once per peer; a no-op if we already hold a session for them (re-fetching a bundle for an
   *  already-open classical session must not burn another one-time prekey or re-derive the
   *  root). See the "post-quantum hybrid layer" comment above for how `classicalSecret` is
   *  bound in, and `pqSeal`/`deliverToUser` for when the opener actually goes out. */
  private async setupPqSessionAsInitiator(username: string, bundle: PreKeyBundleWire): Promise<void> {
    const key = pqSessionKey(username);
    if (await this.store.get<PqPeerSession>("sessions", key)) return;
    const pqIdentity = await this.pqLoadIdentity();
    if (!pqIdentity) return; // we ourselves predate the layer; nothing to bind

    const eph = await generateEphemeralKeyPair();
    const peerClassicalIdentity = b64Decode(bundle.identityKey);
    const classicalSecret = await classicalAgreement(peerClassicalIdentity, eph.privKey);
    const peerSignedPreKeyPub = b64Decode(bundle.pqSignedPreKey!.publicKey);
    const peerOneTimePub = bundle.pqPreKey ? b64Decode(bundle.pqPreKey.publicKey) : null;
    const peerPqIdentityPub = b64Decode(bundle.pqIdentityKey!);

    const { state: rootState, init } = initiatePqSession({
      classicalSecret,
      peerSignedPreKey: peerSignedPreKeyPub,
      peerOneTimePreKey: peerOneTimePub,
      initiatorIdentity: new Uint8Array(eph.pubKey),
      responderIdentity: peerClassicalIdentity,
      pqIdentities: concatBytes(pqIdentity.publicKey, peerPqIdentityPub),
    });
    // Split into independent directional chains; see the PqPeerSession comment above.
    const now = Date.now();
    const sendState = splitDirectionalState(rootState, PQ_DIR_I2R, now);
    const recvState = splitDirectionalState(rootState, PQ_DIR_R2I, now);
    // Seed the KEM ratchet on OUR sending chain: the peer's "current" key is what we just
    // encapsulated to (their published signed prekey), so our own first re-key targets it.
    // pq.ts itself leaves this null; see the pq.ts import comment above `PQW_CLASSICAL`.
    sendState.peerKemPublic = peerSignedPreKeyPub;

    const peer: PqPeerSession = {
      send: serializePqSession(sendState),
      recv: serializePqSession(recvState),
      pendingInit: {
        ctSignedB64: b64Encode(init.ctSigned),
        ctOneTimeB64: init.ctOneTime ? b64Encode(init.ctOneTime) : null,
        oneTimeKeyId: bundle.pqPreKey ? bundle.pqPreKey.keyId : null,
        ephPubB64: b64Encode(eph.pubKey),
      },
    };
    await this.store.put("sessions", key, peer);
  }

  private async ensureSession(username: string): Promise<void> {
    if (await this.sessions.hasSession(username)) return;
    const bundle = await this.api.getBundle(username);
    let pqInfo: { pqIdentityKeyB64?: string; classicalOnly: boolean };
    try {
      pqInfo = await this.establishSession(username, bundle);
    } catch (e) {
      throw this.wrapIdentityError(username, e);
    }
    let contact = await this.store.get<StoredContact>("contacts", username);
    if (!contact) {
      contact = { username, verified: false, addedAt: Date.now(), hasDeliveryToken: false, identityKeyB64: bundle.identityKey };
    }
    if (pqInfo.pqIdentityKeyB64) contact.pqIdentityKeyB64 = pqInfo.pqIdentityKeyB64;
    if (pqInfo.classicalOnly) contact.classicalOnly = true;
    await this.store.put("contacts", username, contact);
    this.emit({ type: "contact", contact: this.toPublicContact(contact) });
  }

  private async handleIdentityChange(username: string, newKey: Uint8Array): Promise<void> {
    let c = await this.store.get<StoredContact>("contacts", username);
    if (!c) {
      c = { username, verified: false, addedAt: Date.now(), hasDeliveryToken: false, identityKeyB64: "" };
    }
    c.identityChanged = true;
    c.verified = false;
    c.pendingIdentityKeyB64 = b64Encode(newKey);
    await this.store.put("contacts", username, c);
    this.emit({ type: "contact", contact: this.toPublicContact(c) });
  }

  /* ================= contacts ================= */

  private toPublicContact(c: StoredContact): Contact {
    const { deliveryToken: _deliveryToken, profileSent: _profileSent, pendingIdentityKeyB64: _pendingIdentityKeyB64, ...rest } = c;
    return rest;
  }

  async addContact(username: Username): Promise<Contact> {
    this.assertReady();
    if (username === this.me()) throw new Error("cannot add yourself as a contact");
    const bundle = await this.api.getBundle(username);
    let pqInfo: { pqIdentityKeyB64?: string; classicalOnly: boolean };
    try {
      pqInfo = await this.establishSession(username, bundle);
    } catch (e) {
      throw this.wrapIdentityError(username, e);
    }
    const now = Date.now();
    let contact = await this.store.get<StoredContact>("contacts", username);
    if (!contact) {
      contact = { username, verified: false, addedAt: now, hasDeliveryToken: false, identityKeyB64: bundle.identityKey };
    } else {
      contact.identityKeyB64 = bundle.identityKey;
    }
    if (pqInfo.pqIdentityKeyB64) contact.pqIdentityKeyB64 = pqInfo.pqIdentityKeyB64;
    if (pqInfo.classicalOnly) contact.classicalOnly = true;
    await this.store.put("contacts", username, contact);
    this.emit({ type: "contact", contact: this.toPublicContact(contact) });

    const chatId: ChatId = `u:${username}`;
    let chat = await this.store.get<Chat>("chats", chatId);
    if (!chat) {
      chat = { id: chatId, kind: "direct", title: contact.displayName ?? username, members: [username], unread: 0, disappearSeconds: 0, updatedAt: now };
      await this.store.put("chats", chatId, chat);
      this.emit({ type: "chat", chat });
    }
    if (!contact.profileSent) {
      contact.profileSent = true;
      await this.store.put("contacts", username, contact);
      await this.sendProfileTo(username);
    }
    return this.toPublicContact(contact);
  }

  async listContacts(): Promise<Contact[]> {
    this.assertReady();
    const all = await this.store.getAll<StoredContact>("contacts");
    return all.map((r) => this.toPublicContact(r.value));
  }

  async getContact(username: Username): Promise<Contact | undefined> {
    this.assertReady();
    const c = await this.store.get<StoredContact>("contacts", username);
    return c ? this.toPublicContact(c) : undefined;
  }

  async safetyNumber(username: Username): Promise<SafetyNumber> {
    this.assertReady();
    if (!this.acct) throw new Error("not registered");
    const c = await this.store.get<StoredContact>("contacts", username);
    if (!c) throw new Error("contact not found");
    const localKp = await this.signalStore.getIdentityKeyPair();
    if (!localKp) throw new Error("no local identity");
    const theirKey = (await this.signalStore.getTrustedIdentity(username)) ?? b64Decode(c.identityKeyB64);
    /* Our own implementation of the library's algorithm, verified identical in
       test/core/fingerprint.test.ts. The library's routes 5,200 SHA-512 rounds
       through a JavaScript crypto polyfill one awaited promise at a time, which
       measured 43 seconds in a browser; this takes milliseconds. */
    // docs/POSTQUANTUM.md "Safety numbers": the fingerprint covers BOTH identity keys, so a
    // quantum adversary cannot produce a colliding identity. Every account created by this
    // client always has a pq identity; a contact's is appended only once known (a genuinely
    // classical-only contact never has one, and both sides agree not to include it).
    const ourPq = await this.pqLoadIdentity();
    const ourFingerprintKey = ourPq ? concatBytes(new Uint8Array(localKp.pubKey), ourPq.publicKey) : new Uint8Array(localKp.pubKey);
    const theirFingerprintKey = c.pqIdentityKeyB64 ? concatBytes(new Uint8Array(theirKey), b64Decode(c.pqIdentityKeyB64)) : new Uint8Array(theirKey);
    const digits = safetyNumberFor(
      this.acct.username,
      ourFingerprintKey,
      username,
      theirFingerprintKey,
    );
    return { digits, verified: c.verified, identityChanged: !!c.identityChanged };
  }

  async setVerified(username: Username, verified: boolean): Promise<void> {
    this.assertReady();
    const c = await this.store.get<StoredContact>("contacts", username);
    if (!c) throw new Error("contact not found");
    c.verified = verified;
    await this.store.put("contacts", username, c);
    this.emit({ type: "contact", contact: this.toPublicContact(c) });
  }

  async acceptIdentityChange(username: Username): Promise<void> {
    this.assertReady();
    const c = await this.store.get<StoredContact>("contacts", username);
    if (!c || !c.pendingIdentityKeyB64) throw new Error("no pending identity change for this contact");
    await this.signalStore.trustIdentity(username, b64Decode(c.pendingIdentityKeyB64));
    await this.sessions.deleteSessions(username);
    c.identityKeyB64 = c.pendingIdentityKeyB64;
    c.identityChanged = false;
    c.verified = false;
    delete c.pendingIdentityKeyB64;
    await this.store.put("contacts", username, c);
    this.emit({ type: "contact", contact: this.toPublicContact(c) });
  }

  async setDisplayName(name: string): Promise<void> {
    this.assertReady();
    if (!this.acct) throw new Error("not registered");
    this.acct = { ...this.acct, displayName: name };
    await this.store.put("kv", "account", this.acct);
    const contacts = await this.store.getAll<StoredContact>("contacts");
    for (const { key: username } of contacts) {
      const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "profile", profile: { name } };
      try {
        await this.deliverToUser(username, content, { forceIdentified: true });
      } catch (e) {
        this.emitError(`could not tell ${username} about the new name: ${(e as Error).message}`);
      }
    }
  }

  /* ================= sending plumbing ================= */

  private async sendProfileTo(username: string): Promise<void> {
    const token = await this.store.get<string>("kv", "deliveryToken");
    const content: Content = {
      v: 1,
      id: randomId(),
      ts: Date.now(),
      kind: "profile",
      profile: { name: this.acct?.displayName, deliveryToken: token },
    };
    await this.deliverToUser(username, content, { forceIdentified: true });
  }

  /** Wraps one outgoing Signal ciphertext in the post-quantum outer layer (docs/POSTQUANTUM.md
   *  "The outer layer, per message"). Every outgoing Signal ciphertext goes through this before
   *  it reaches api.sendMessages. Falls back to marking the content classical-only (marker 0,
   *  bytes untouched) for a confirmed classical-only contact, or -- defensively, should
   *  deliverToUser ever be reached without a prior establishSession -- when no hybrid session
   *  or identity is available, rather than dropping the message. */
  private async pqWrapOutgoing(to: string, rawSignalCiphertext: Uint8Array): Promise<Uint8Array> {
    const contact = await this.store.get<StoredContact>("contacts", to);
    if (contact?.classicalOnly) return concatBytes(new Uint8Array([PQW_CLASSICAL]), rawSignalCiphertext);

    const key = pqSessionKey(to);
    const peer = await this.store.get<PqPeerSession>("sessions", key);
    const pqIdentity = peer ? await this.pqLoadIdentity() : undefined;
    if (!peer || !pqIdentity) return concatBytes(new Uint8Array([PQW_CLASSICAL]), rawSignalCiphertext);

    const state = deserializePqSession(peer.send);
    const pending = peer.pendingInit;
    const init = pending
      ? { ctSigned: b64Decode(pending.ctSignedB64), ctOneTime: pending.ctOneTimeB64 ? b64Decode(pending.ctOneTimeB64) : null }
      : null;
    const sealed = pqSeal(state, rawSignalCiphertext, { pqIdentitySecret: pqIdentity.secretKey, init });
    await this.store.put("sessions", key, { send: serializePqSession(state), recv: peer.recv, pendingInit: null } satisfies PqPeerSession);

    if (pending) {
      const header = buildOpenerHeader(b64Decode(pending.ephPubB64), pqIdentity.publicKey, pending.oneTimeKeyId);
      return concatBytes(new Uint8Array([PQW_OPENER]), header, sealed);
    }
    return concatBytes(new Uint8Array([PQW_ORDINARY]), sealed);
  }

  /** Encrypts and sends one content payload to one user, choosing sealed vs identified delivery. */
  private async deliverToUser(to: string, content: Content, opts: { forceIdentified?: boolean } = {}): Promise<void> {
    await this.ensureSession(to);
    const contact = await this.store.get<StoredContact>("contacts", to);
    const plaintext = encodeContent(content);
    let cipher: { type: number; content: string };
    try {
      cipher = await this.sessions.encrypt(to, plaintext);
    } catch (e) {
      throw this.wrapIdentityError(to, e);
    }
    const wrapped = await this.pqWrapOutgoing(to, b64Decode(cipher.content));
    const wrappedContentB64 = b64Encode(wrapped);
    if (!opts.forceIdentified && contact?.hasDeliveryToken && contact.deliveryToken) {
      const theirIdentity = await this.signalStore.getTrustedIdentity(to);
      if (!theirIdentity) throw new Error(`no trusted identity for ${to}`);
      const sealed = await sealMessage(theirIdentity, { from: this.me(), deviceId: DEVICE_ID, type: cipher.type, content: wrappedContentB64 });
      await this.api.sendMessages(to, [{ destinationDeviceId: DEVICE_ID, type: SEALED_TYPE, content: sealed }], contact.deliveryToken);
    } else {
      await this.api.sendMessages(to, [{ destinationDeviceId: DEVICE_ID, type: cipher.type, content: wrappedContentB64 }]);
    }
  }

  private async broadcastControl(chat: Chat, content: Content): Promise<void> {
    for (const to of this.recipientsFor(chat)) {
      try {
        await this.deliverToUser(to, content);
      } catch (e) {
        this.emitError(`could not deliver ${content.kind} to ${to}: ${(e as Error).message}`);
      }
    }
  }

  private recipientsFor(chat: Chat): string[] {
    if (chat.kind === "direct") return chat.members.slice(0, 1);
    return (chat.group?.members ?? []).filter((m) => m !== this.acct?.username);
  }

  /* ================= chats & messages ================= */

  private toPublic(m: StoredMessage): Message {
    const { _pointer: _p, _expiresSeconds: _e, ...rest } = m;
    return rest;
  }

  private indexFor(m: StoredMessage): RecordIndex {
    return { c: m.chatId, t: m.sentAt, x: m.expiresAt };
  }

  private async saveMessage(m: StoredMessage): Promise<void> {
    await this.store.put("messages", m.id, m, this.indexFor(m));
  }

  private async updateChat(chatId: ChatId, patch: Partial<Chat>): Promise<Chat | undefined> {
    const chat = await this.store.get<Chat>("chats", chatId);
    if (!chat) return undefined;
    const next: Chat = { ...chat, ...patch };
    await this.store.put("chats", chatId, next);
    this.emit({ type: "chat", chat: next });
    return next;
  }

  async listChats(): Promise<Chat[]> {
    this.assertReady();
    const all = await this.store.getAll<Chat>("chats");
    return all.map((r) => r.value).sort((a, b) => b.updatedAt - a.updatedAt);
  }

  async getChat(id: ChatId): Promise<Chat | undefined> {
    this.assertReady();
    return this.store.get<Chat>("chats", id);
  }

  async getMessages(chatId: ChatId, opts?: { before?: number; limit?: number }): Promise<Message[]> {
    this.assertReady();
    const raw = await this.store.messagesByChat<StoredMessage>(chatId, opts);
    return raw.map((m) => this.toPublic(m));
  }

  private async addSystemMessage(chatId: ChatId, body: string, opts: { countsUnread?: boolean } = {}): Promise<void> {
    const now = Date.now();
    const msg: StoredMessage = { id: randomId(), chatId, sender: "", mine: false, sentAt: now, receivedAt: now, kind: "system", body, reactions: {}, status: "delivered" };
    await this.saveMessage(msg);
    this.emit({ type: "message", message: this.toPublic(msg) });
    const chat = await this.store.get<Chat>("chats", chatId);
    if (!chat) return;
    const patch: Partial<Chat> = { lastMessage: { body, sentAt: now, sender: "", kind: "system" }, updatedAt: now };
    if (opts.countsUnread !== false) patch.unread = (chat.unread ?? 0) + 1;
    await this.updateChat(chatId, patch);
  }

  private async sendUserMessage(
    chatId: ChatId,
    kind: "text" | "attachment",
    opts: { body?: string; replyTo?: string; attachment?: AttachmentPointer; attachmentMeta?: AttachmentMeta },
  ): Promise<Message> {
    this.assertReady();
    const chat = await this.store.get<Chat>("chats", chatId);
    if (!chat) throw new Error(`unknown chat ${chatId}`);
    if (chat.kind === "group" && chat.group?.leftOrRemoved) throw new Error("this chat is read-only");
    const id = randomId();
    const ts = Date.now();
    const expiresSeconds = chat.disappearSeconds > 0 ? chat.disappearSeconds : undefined;
    const msg: StoredMessage = { id, chatId, sender: this.me(), mine: true, sentAt: ts, receivedAt: ts, kind, body: opts.body ?? "", replyTo: opts.replyTo, reactions: {}, status: "pending" };
    if (opts.attachmentMeta) msg.attachment = opts.attachmentMeta;
    if (opts.attachment) msg._pointer = opts.attachment;
    if (expiresSeconds !== undefined) {
      msg.expiresAt = ts + expiresSeconds * 1000;
      msg._expiresSeconds = expiresSeconds;
    }
    await this.saveMessage(msg);
    this.emit({ type: "message", message: this.toPublic(msg) });
    await this.updateChat(chatId, { lastMessage: { body: msg.body, sentAt: ts, sender: this.me(), kind }, updatedAt: ts });
    await this.deliverMessage(msg, chat, expiresSeconds, opts.attachment);
    return this.toPublic((await this.store.get<StoredMessage>("messages", id))!);
  }

  private async deliverMessage(msg: StoredMessage, chat: Chat, expiresSeconds: number | undefined, attachment: AttachmentPointer | undefined): Promise<void> {
    const content: Content = { v: 1, id: msg.id, ts: msg.sentAt, kind: msg.kind === "attachment" ? "attachment" : "text" };
    if (msg.body) content.body = msg.body;
    if (msg.replyTo) content.replyTo = msg.replyTo;
    if (chat.kind === "group" && chat.group) content.group = chat.group.id;
    if (expiresSeconds !== undefined) content.expires = expiresSeconds;
    if (attachment) content.attachment = attachment;

    const targets = this.recipientsFor(chat);
    let identityBlocked: Error | null = null;
    let anyFailure = false;
    for (const to of targets) {
      try {
        await this.deliverToUser(to, content);
      } catch (e) {
        anyFailure = true;
        if (e instanceof IdentityChangedError) identityBlocked = e;
        else this.emitError(`could not deliver message to ${to}: ${(e as Error).message}`);
      }
    }
    const fresh = await this.store.get<StoredMessage>("messages", msg.id);
    if (fresh) {
      fresh.status = anyFailure ? "failed" : "sent";
      await this.saveMessage(fresh);
      this.emit({ type: "message", message: this.toPublic(fresh) });
    }
    if (identityBlocked) throw identityBlocked;
  }

  async sendText(chatId: ChatId, body: string, opts?: { replyTo?: string }): Promise<Message> {
    return this.sendUserMessage(chatId, "text", { body, replyTo: opts?.replyTo });
  }

  async sendAttachment(chatId: ChatId, file: Blob, opts?: { name?: string; caption?: string; original?: boolean }): Promise<Message> {
    this.assertReady();
    let mime = file.type || "application/octet-stream";
    let plainBytes = new Uint8Array(await file.arrayBuffer());
    let width: number | undefined;
    let height: number | undefined;
    if (isImageMime(mime) && !opts?.original) {
      try {
        const prepared = await prepareImage(file, mime);
        mime = prepared.mime;
        width = prepared.width;
        height = prepared.height;
        plainBytes = new Uint8Array(await prepared.blob.arrayBuffer());
      } catch {
        /* fall back to the original bytes */
      }
    }
    const enc = await encryptAttachment(plainBytes);
    const { id: attId } = await this.api.uploadAttachment(enc.ciphertext);
    const pointer: AttachmentPointer = { id: attId, key: enc.key, iv: enc.iv, digest: enc.digest, mime, size: plainBytes.length, name: opts?.name, width, height, caption: opts?.caption };
    const meta: AttachmentMeta = { id: attId, mime, size: plainBytes.length, name: opts?.name, width, height, caption: opts?.caption };
    const msg = await this.sendUserMessage(chatId, "attachment", { body: opts?.caption, attachment: pointer, attachmentMeta: meta });
    await this.store.put("attachments", msg.id, toArrayBuffer(plainBytes));
    return msg;
  }

  async downloadAttachment(messageId: string): Promise<Blob> {
    this.assertReady();
    const stored = await this.store.get<StoredMessage>("messages", messageId);
    if (!stored || !stored.attachment) throw new Error("message has no attachment");
    const cached = await this.store.get<ArrayBuffer>("attachments", messageId);
    if (cached) return new Blob([cached], { type: stored.attachment.mime });
    const pointer = stored._pointer;
    if (!pointer) throw new Error("attachment is not available for download");
    const ciphertext = await this.api.downloadAttachment(pointer.id);
    const plaintext = await decryptAttachment(ciphertext, pointer);
    await this.store.put("attachments", messageId, toArrayBuffer(plaintext));
    return new Blob([toArrayBuffer(plaintext)], { type: stored.attachment.mime });
  }

  async retry(messageId: string): Promise<Message> {
    this.assertReady();
    const msg = await this.store.get<StoredMessage>("messages", messageId);
    if (!msg || !msg.mine) throw new Error("message not found");
    const chat = await this.store.get<Chat>("chats", msg.chatId);
    if (!chat) throw new Error("chat not found");
    msg.status = "pending";
    await this.saveMessage(msg);
    this.emit({ type: "message", message: this.toPublic(msg) });
    await this.deliverMessage(msg, chat, msg._expiresSeconds, msg._pointer);
    return this.toPublic((await this.store.get<StoredMessage>("messages", messageId))!);
  }

  async react(messageId: string, emoji: string): Promise<void> {
    this.assertReady();
    const msg = await this.store.get<StoredMessage>("messages", messageId);
    if (!msg) throw new Error("message not found");
    const chat = await this.store.get<Chat>("chats", msg.chatId);
    if (!chat) throw new Error("chat not found");
    const me = this.me();
    let mine: string | undefined;
    for (const [e, users] of Object.entries(msg.reactions)) {
      if (users.includes(me)) {
        mine = e;
        break;
      }
    }
    const finalEmoji = mine === emoji ? "" : emoji;
    removeUserFromReactions(msg.reactions, me);
    if (finalEmoji) (msg.reactions[finalEmoji] ??= []).push(me);
    await this.saveMessage(msg);
    this.emit({ type: "message", message: this.toPublic(msg) });
    const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "reaction", ref: messageId, body: finalEmoji };
    if (chat.kind === "group" && chat.group) content.group = chat.group.id;
    await this.broadcastControl(chat, content);
  }

  async deleteForEveryone(messageId: string): Promise<void> {
    this.assertReady();
    const msg = await this.store.get<StoredMessage>("messages", messageId);
    if (!msg) throw new Error("message not found");
    if (!msg.mine) throw new Error("only the original sender can delete for everyone");
    const chat = await this.store.get<Chat>("chats", msg.chatId);
    if (!chat) throw new Error("chat not found");
    msg.deleted = true;
    msg.body = "";
    msg.attachment = undefined;
    msg._pointer = undefined;
    await this.saveMessage(msg);
    await this.store.delete("attachments", msg.id);
    this.emit({ type: "message", message: this.toPublic(msg) });
    const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "delete", ref: messageId };
    if (chat.kind === "group" && chat.group) content.group = chat.group.id;
    await this.broadcastControl(chat, content);
  }

  async deleteLocally(messageId: string): Promise<void> {
    this.assertReady();
    const msg = await this.store.get<StoredMessage>("messages", messageId);
    if (!msg) return;
    await this.store.delete("messages", messageId);
    await this.store.delete("attachments", messageId);
    this.emit({ type: "message", message: { ...this.toPublic(msg), deleted: true, body: "" } });
  }

  async markRead(chatId: ChatId): Promise<void> {
    this.assertReady();
    const msgs = await this.store.messagesByChat<StoredMessage>(chatId);
    const bySender = new Map<string, string[]>();
    for (const m of msgs) {
      if (m.mine || m.deleted || m.status === "read" || !m.sender) continue;
      const arr = bySender.get(m.sender) ?? [];
      arr.push(m.id);
      bySender.set(m.sender, arr);
      m.status = "read";
      await this.saveMessage(m);
      this.emit({ type: "message", message: this.toPublic(m) });
    }
    await this.updateChat(chatId, { unread: 0, updatedAt: Date.now() });
    for (const [sender, ids] of bySender) {
      for (let i = 0; i < ids.length; i += 50) {
        const batch = ids.slice(i, i + 50);
        const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "receipt", receipt: "read", ref: batch.join(",") };
        try {
          await this.deliverToUser(sender, content);
        } catch (e) {
          this.emitError(`could not send read receipt to ${sender}: ${(e as Error).message}`);
        }
      }
    }
  }

  setTyping(chatId: ChatId, typing: boolean): void {
    if (!this.acct || this.locked) return;
    const last = this.typingSentAt.get(chatId) ?? 0;
    const now = Date.now();
    if (typing && now - last < 5000) return;
    this.typingSentAt.set(chatId, typing ? now : 0);
    void (async () => {
      try {
        const chat = await this.store.get<Chat>("chats", chatId);
        if (!chat) return;
        const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "typing", body: typing ? "start" : "stop" };
        if (chat.kind === "group" && chat.group) content.group = chat.group.id;
        await this.broadcastControl(chat, content);
      } catch {
        /* typing indicators are best-effort */
      }
    })();
  }

  async setDisappearing(chatId: ChatId, seconds: number): Promise<void> {
    this.assertReady();
    const chat = await this.store.get<Chat>("chats", chatId);
    if (!chat) throw new Error("chat not found");
    if (chat.kind === "group" && chat.group && !isGroupAdmin(chat.group, this.me())) {
      throw new Error("only admins can change disappearing messages for this group");
    }
    const updated = await this.updateChat(chatId, { disappearSeconds: seconds, updatedAt: Date.now() });
    const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "disappear", disappear: seconds };
    if (chat.kind === "group" && chat.group) content.group = chat.group.id;
    await this.broadcastControl(updated ?? chat, content);
  }

  /* ================= groups ================= */

  async createGroup(name: string, members: Username[]): Promise<Chat> {
    this.assertReady();
    const me = this.me();
    const allMembers = uniq([me, ...members]);
    const id = randomId();
    const state: GroupState = { id, name, creator: me, admins: [me], members: allMembers, revision: 1 };
    const chatId: ChatId = `g:${id}`;
    const chat: Chat = { id: chatId, kind: "group", title: name, members: allMembers, group: state, unread: 0, disappearSeconds: 0, updatedAt: Date.now() };
    await this.store.put("chats", chatId, chat);
    this.emit({ type: "chat", chat });
    await this.addSystemMessage(chatId, `You created the group "${name}"`, { countsUnread: false });
    const gu: GroupUpdate = { id, revision: 1, name, creator: me, admins: [me], members: allMembers, action: "create" };
    const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "group", group: id, group_update: gu };
    await this.broadcastControl(chat, content);
    return chat;
  }

  async updateGroup(groupId: string, patch: { name?: string; add?: Username[]; remove?: Username[] }): Promise<Chat> {
    this.assertReady();
    const chatId: ChatId = `g:${groupId}`;
    const chat = await this.store.get<Chat>("chats", chatId);
    if (!chat || !chat.group) throw new Error("group not found");
    const me = this.me();
    if (!isGroupAdmin(chat.group, me)) throw new Error("only admins can update this group");
    const removed = uniq(patch.remove ?? []);
    const added = uniq(patch.add ?? []);
    const newMembers = uniq([...chat.group.members.filter((m) => !removed.includes(m)), ...added]);
    const newRevision = chat.group.revision + 1;
    const newName = patch.name ?? chat.group.name;
    const prevGroup = chat.group;
    const state: GroupState = {
      id: chat.group.id,
      name: newName,
      creator: chat.group.creator,
      admins: chat.group.admins.filter((a) => newMembers.includes(a)),
      members: newMembers,
      revision: newRevision,
    };
    const updatedChat: Chat = { ...chat, group: state, title: newName, members: newMembers, updatedAt: Date.now() };
    await this.store.put("chats", chatId, updatedChat);
    this.emit({ type: "chat", chat: updatedChat });
    await this.addSystemMessage(chatId, describeGroupChange(prevGroup, state, me, "update"), { countsUnread: false });
    const gu: GroupUpdate = { id: state.id, revision: newRevision, name: newName, creator: state.creator, admins: state.admins, members: newMembers, action: "update" };
    const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "group", group: state.id, group_update: gu };
    const targets = uniq([...newMembers, ...removed]).filter((m) => m !== me);
    for (const to of targets) {
      try {
        await this.deliverToUser(to, content);
      } catch (e) {
        this.emitError(`could not deliver group update to ${to}: ${(e as Error).message}`);
      }
    }
    return updatedChat;
  }

  async leaveGroup(groupId: string): Promise<void> {
    this.assertReady();
    const chatId: ChatId = `g:${groupId}`;
    const chat = await this.store.get<Chat>("chats", chatId);
    if (!chat || !chat.group) throw new Error("group not found");
    const me = this.me();
    const newMembers = chat.group.members.filter((m) => m !== me);
    const state: GroupState = { ...chat.group, members: newMembers, admins: chat.group.admins.filter((a) => a !== me), leftOrRemoved: true };
    const updatedChat: Chat = { ...chat, group: state, members: newMembers, updatedAt: Date.now() };
    await this.store.put("chats", chatId, updatedChat);
    this.emit({ type: "chat", chat: updatedChat });
    await this.addSystemMessage(chatId, "You left the group", { countsUnread: false });
    const gu: GroupUpdate = { id: state.id, revision: chat.group.revision, name: state.name, creator: state.creator, admins: state.admins, members: newMembers, action: "leave" };
    const content: Content = { v: 1, id: randomId(), ts: Date.now(), kind: "group", group: state.id, group_update: gu };
    for (const to of newMembers) {
      try {
        await this.deliverToUser(to, content);
      } catch (e) {
        this.emitError(`could not tell ${to} that you left: ${(e as Error).message}`);
      }
    }
  }

  /* ================= receive loop ================= */

  private async markSeen(id: string): Promise<void> {
    this.seenIds.add(id);
    let arr = Array.from(this.seenIds);
    if (arr.length > 5000) {
      arr = arr.slice(arr.length - 5000);
      this.seenIds = new Set(arr);
    }
    await this.store.put("kv", "seenIds", arr);
  }

  private async ensureChatForIncoming(chatId: ChatId, sender: string, content: Content): Promise<Chat | undefined> {
    const chat = await this.store.get<Chat>("chats", chatId);
    if (chat) {
      if (chat.kind === "group" && chat.group && !chat.group.members.includes(sender)) return undefined;
      return chat;
    }
    if (content.group) return undefined; // message for a group we don't know: drop
    const contact = await this.store.get<StoredContact>("contacts", sender);
    const now = Date.now();
    const newChat: Chat = { id: chatId, kind: "direct", title: contact?.displayName ?? sender, members: [sender], unread: 0, disappearSeconds: 0, updatedAt: now };
    await this.store.put("chats", chatId, newChat);
    this.emit({ type: "chat", chat: newChat });
    return newChat;
  }

  private setChatTyping(chatId: string, user: string, typing: boolean): void {
    let set = this.typingState.get(chatId);
    if (!set) {
      set = new Set();
      this.typingState.set(chatId, set);
    }
    const timerKey = `${chatId}\u0000${user}`;
    const existingTimer = this.typingTimers.get(timerKey);
    if (existingTimer) clearTimeout(existingTimer);
    this.typingTimers.delete(timerKey);
    if (typing) {
      set.add(user);
      const t = setTimeout(() => {
        set!.delete(user);
        this.typingTimers.delete(timerKey);
        this.emit({ type: "typing", chatId, users: Array.from(set!) });
      }, 10000);
      (t as unknown as { unref?: () => void }).unref?.();
      this.typingTimers.set(timerKey, t);
    } else {
      set.delete(user);
    }
    this.emit({ type: "typing", chatId, users: Array.from(set) });
  }

  private queueDeliveredReceipt(sender: string, id: string): void {
    this.deliveredBatcher.add(sender, id);
  }

  private async handleIncomingProfile(sender: string, profile: { name?: string; deliveryToken?: string }): Promise<void> {
    let contact = await this.store.get<StoredContact>("contacts", sender);
    const now = Date.now();
    if (!contact) {
      const theirKey = await this.signalStore.getTrustedIdentity(sender);
      contact = { username: sender, verified: false, addedAt: now, hasDeliveryToken: false, identityKeyB64: theirKey ? b64Encode(theirKey) : "" };
    } else if (!contact.identityKeyB64) {
      // The post-quantum opener handler (pqUnwrapIncoming) may have created this contact
      // stub before the Signal library had learned the sender's classical identity key
      // (see the "post-quantum hybrid layer" comment above); backfill it now that it's known.
      const theirKey = await this.signalStore.getTrustedIdentity(sender);
      if (theirKey) contact.identityKeyB64 = b64Encode(theirKey);
    }
    if (profile.name) contact.displayName = profile.name;
    if (profile.deliveryToken) {
      contact.deliveryToken = profile.deliveryToken;
      contact.hasDeliveryToken = true;
    }
    await this.store.put("contacts", sender, contact);
    this.emit({ type: "contact", contact: this.toPublicContact(contact) });

    const chatId: ChatId = `u:${sender}`;
    let chat = await this.store.get<Chat>("chats", chatId);
    if (!chat) {
      chat = { id: chatId, kind: "direct", title: contact.displayName ?? sender, members: [sender], unread: 0, disappearSeconds: 0, updatedAt: now };
      await this.store.put("chats", chatId, chat);
      this.emit({ type: "chat", chat });
    } else if (profile.name && chat.title !== profile.name) {
      await this.updateChat(chatId, { title: profile.name });
    }

    if (!contact.profileSent) {
      contact.profileSent = true;
      await this.store.put("contacts", sender, contact);
      try {
        await this.sendProfileTo(sender);
      } catch (e) {
        this.emitError(`could not reply with our profile to ${sender}: ${(e as Error).message}`);
      }
    }
  }

  private async dispatchContent(sender: string, content: Content): Promise<void> {
    switch (content.kind) {
      case "text":
      case "attachment": {
        const chatId: ChatId = content.group ? `g:${content.group}` : `u:${sender}`;
        const chat = await this.ensureChatForIncoming(chatId, sender, content);
        if (!chat) return;
        const now = Date.now();
        const msg: StoredMessage = {
          id: content.id,
          chatId,
          sender,
          mine: false,
          sentAt: content.ts,
          receivedAt: now,
          kind: content.kind as "text" | "attachment",
          body: content.body ?? "",
          replyTo: content.replyTo,
          reactions: {},
          status: "delivered",
        };
        if (content.kind === "attachment" && content.attachment) {
          const a = content.attachment;
          msg.attachment = { id: a.id, mime: a.mime, size: a.size, name: a.name, width: a.width, height: a.height, caption: a.caption };
          msg._pointer = a;
        }
        if (content.expires) {
          msg.expiresAt = now + content.expires * 1000;
          msg._expiresSeconds = content.expires;
        }
        await this.saveMessage(msg);
        this.emit({ type: "message", message: this.toPublic(msg) });
        await this.updateChat(chatId, { lastMessage: { body: msg.body, sentAt: msg.sentAt, sender, kind: msg.kind }, unread: (chat.unread ?? 0) + 1, updatedAt: now });
        this.queueDeliveredReceipt(sender, content.id);
        break;
      }
      case "reaction": {
        if (!content.ref) return;
        const target = await this.store.get<StoredMessage>("messages", content.ref);
        if (!target) return;
        removeUserFromReactions(target.reactions, sender);
        if (content.body) (target.reactions[content.body] ??= []).push(sender);
        await this.saveMessage(target);
        this.emit({ type: "message", message: this.toPublic(target) });
        break;
      }
      case "delete": {
        if (!content.ref) return;
        const target = await this.store.get<StoredMessage>("messages", content.ref);
        if (!target || target.sender !== sender) return;
        target.deleted = true;
        target.body = "";
        target.attachment = undefined;
        target._pointer = undefined;
        await this.saveMessage(target);
        await this.store.delete("attachments", target.id);
        this.emit({ type: "message", message: this.toPublic(target) });
        break;
      }
      case "receipt": {
        const ids = (content.ref ?? "").split(",").filter(Boolean);
        const nextStatus: Message["status"] = content.receipt === "read" ? "read" : "delivered";
        for (const id of ids) {
          const m = await this.store.get<StoredMessage>("messages", id);
          if (!m || !m.mine) continue;
          if (STATUS_RANK[nextStatus] <= STATUS_RANK[m.status]) continue;
          m.status = nextStatus;
          await this.saveMessage(m);
          this.emit({ type: "message", message: this.toPublic(m) });
        }
        break;
      }
      case "typing": {
        const chatId: ChatId = content.group ? `g:${content.group}` : `u:${sender}`;
        this.setChatTyping(chatId, sender, content.body === "start");
        break;
      }
      case "group": {
        if (!content.group_update) return;
        const gu = content.group_update;
        const chatId: ChatId = `g:${gu.id}`;
        const existingChat = await this.store.get<Chat>("chats", chatId);
        const result = applyGroupUpdate(existingChat?.group, gu, sender, this.me());
        if (!result.ok) {
          this.emitError(`group update from ${sender} rejected: ${result.reason}`);
          return;
        }
        const now = Date.now();
        const chat: Chat = existingChat
          ? { ...existingChat, group: result.state, title: result.state.name, members: result.state.members, updatedAt: now }
          : { id: chatId, kind: "group", title: result.state.name, members: result.state.members, group: result.state, unread: 0, disappearSeconds: 0, updatedAt: now };
        await this.store.put("chats", chatId, chat);
        this.emit({ type: "chat", chat });
        await this.addSystemMessage(chatId, describeGroupChange(existingChat?.group, result.state, sender, gu.action));
        break;
      }
      case "profile": {
        await this.handleIncomingProfile(sender, content.profile ?? {});
        break;
      }
      case "disappear": {
        const chatId: ChatId = content.group ? `g:${content.group}` : `u:${sender}`;
        const chat = await this.store.get<Chat>("chats", chatId);
        if (!chat) return;
        if (chat.kind === "group" && chat.group) {
          if (!isGroupAdmin(chat.group, sender)) return;
        } else if (chat.kind === "direct" && chat.members[0] !== sender) {
          return;
        }
        await this.updateChat(chatId, { disappearSeconds: content.disappear ?? 0, updatedAt: Date.now() });
        break;
      }
      default:
        break; // unknown kinds are ignored, not errors (docs/PROTOCOL.md)
    }
  }

  /** Unwraps one incoming post-quantum outer layer, returning the raw Signal ciphertext bytes
   *  for the library to decrypt (docs/POSTQUANTUM.md "The outer layer, per message"). Every
   *  incoming Signal ciphertext goes through this before the Signal library sees it. See the
   *  "post-quantum hybrid layer" comment above `PQW_CLASSICAL` for the wire framing and for why
   *  a brand-new opener's identity fields have to travel here rather than being learned from
   *  the (as yet unopened) Signal ciphertext. */
  private async pqUnwrapIncoming(sender: string, wrapped: Uint8Array): Promise<Uint8Array> {
    if (wrapped.length < 1) throw new Error("empty post-quantum envelope");
    const marker = wrapped[0];
    const rest = wrapped.slice(1);
    const key = pqSessionKey(sender);
    const contact = await this.store.get<StoredContact>("contacts", sender);

    if (marker === PQW_CLASSICAL) {
      const existingPeer = await this.store.get<PqPeerSession>("sessions", key);
      if (existingPeer || contact?.pqIdentityKeyB64) throw new PqDowngradeError(sender);
      return rest;
    }

    if (marker === PQW_OPENER) {
      const { ephPub, senderPqIdentityPub, oneTimeKeyId, rest: pqWire } = parseOpenerHeader(rest);
      const ourClassical = await this.mustClassicalIdentity();
      const ourPqIdentity = await this.pqLoadIdentity();
      const signedPreKey = await this.pqLoadSignedPreKey();
      if (!ourPqIdentity || !signedPreKey) throw new Error("no post-quantum identity/signed prekey to accept a session with");

      const hasOneTime = oneTimeKeyId !== null;
      let oneTimeSecret: Uint8Array | undefined;
      if (oneTimeKeyId !== null) {
        const consumed = await this.pqTakeOneTimePreKey(oneTimeKeyId);
        if (!consumed) throw new Error("post-quantum one-time prekey already used or unknown");
        oneTimeSecret = consumed;
      }
      const { ctSigned, ctOneTime } = parseInitFieldsFromPqWire(pqWire, hasOneTime);
      const classicalSecret = await classicalAgreement(ephPub, ourClassical.privKey);

      const rootState = acceptPqSession({
        classicalSecret,
        ctSigned,
        ctOneTime,
        signedPreKeySecret: signedPreKey.secretKey,
        oneTimePreKeySecret: oneTimeSecret,
        initiatorIdentity: ephPub,
        responderIdentity: ourClassical.pubBytes,
        pqIdentities: concatBytes(senderPqIdentityPub, ourPqIdentity.publicKey),
      });
      // Split into independent directional chains; see the PqPeerSession comment above. We
      // (the responder) receive on the initiator->responder chain and send on the reverse.
      const now = Date.now();
      const sendState = splitDirectionalState(rootState, PQ_DIR_R2I, now);
      const recvState = splitDirectionalState(rootState, PQ_DIR_I2R, now);
      // See setupPqSessionAsInitiator: we advertised our signed prekey, so that is the key a
      // peer's first re-key toward us (on the chain they send on) will target.
      recvState.myKemPair = { publicKey: signedPreKey.publicKey, secretKey: signedPreKey.secretKey };

      const inner = pqOpen(recvState, pqWire, { peerPqIdentity: senderPqIdentityPub, myKemSecret: recvState.myKemPair.secretKey, hasOneTime });
      await this.store.put("sessions", key, {
        send: serializePqSession(sendState),
        recv: serializePqSession(recvState),
        pendingInit: null,
      } satisfies PqPeerSession);

      let c = contact;
      if (!c) c = { username: sender, verified: false, addedAt: Date.now(), hasDeliveryToken: false, identityKeyB64: "" };
      c.pqIdentityKeyB64 = b64Encode(senderPqIdentityPub);
      delete c.classicalOnly;
      await this.store.put("contacts", sender, c);
      this.emit({ type: "contact", contact: this.toPublicContact(c) });
      return inner;
    }

    // PQW_ORDINARY: an already-established hybrid session; open on our receiving chain.
    const peer = await this.store.get<PqPeerSession>("sessions", key);
    if (!peer) throw new Error(`post-quantum message from ${sender} for a session we have not established`);
    const peerPqIdentity = contact?.pqIdentityKeyB64 ? b64Decode(contact.pqIdentityKeyB64) : null;
    if (!peerPqIdentity) throw new Error(`no known post-quantum identity for ${sender}`);
    const recvState = deserializePqSession(peer.recv);
    const hadPeerKemBefore = recvState.peerKemPublic;
    const inner = pqOpen(recvState, rest, { peerPqIdentity, myKemSecret: recvState.myKemPair?.secretKey ?? null, hasOneTime: false });

    // In a one-sided contact (only the initiator ever fetched a bundle), the responder's own
    // outbound chain starts with no re-key target at all (see the PqPeerSession comment
    // above): they never published anything for the initiator's FIRST session-establishing
    // encapsulation to target back. The peer's first re-key on the chain we just opened is the
    // first KEM public key of theirs we learn afterwards -- reuse it as our own outbound
    // chain's target too, so both directions gain an independent re-key cadence once any one
    // re-key has happened, rather than the responder's outbound chain staying dormant forever.
    let sendState = deserializePqSession(peer.send);
    if (recvState.peerKemPublic && !hadPeerKemBefore && !sendState.peerKemPublic) {
      sendState = { ...sendState, peerKemPublic: recvState.peerKemPublic };
    }

    await this.store.put("sessions", key, {
      send: serializePqSession(sendState),
      recv: serializePqSession(recvState),
      pendingInit: peer.pendingInit,
    } satisfies PqPeerSession);
    return inner;
  }

  private async handleEnvelope(env: import("../types").EnvelopeWire): Promise<void> {
    try {
      let sender: string;
      let innerType: number;
      let innerContent: string;
      if (env.type === SEALED_TYPE) {
        const idKeyPair = await this.signalStore.getIdentityKeyPair();
        if (!idKeyPair) return;
        let inner;
        try {
          inner = await unsealMessage(idKeyPair, env.content);
        } catch (e) {
          this.emitError(`discarded an unreadable sealed message: ${(e as Error).message}`);
          return;
        }
        sender = inner.from;
        innerType = inner.type;
        innerContent = inner.content;
      } else {
        if (!env.from) {
          this.emitError("dropped an identified envelope with no sender");
          return;
        }
        sender = env.from.username;
        innerType = env.type;
        innerContent = env.content;
      }
      let plaintext: Uint8Array;
      try {
        const rawSignalCiphertext = await this.pqUnwrapIncoming(sender, b64Decode(innerContent));
        plaintext = await this.sessions.decrypt(sender, innerType, b64Encode(rawSignalCiphertext));
      } catch (e) {
        this.emitError(`could not decrypt a message from ${sender}: ${(e as Error).message}`);
        return;
      }
      let content: Content;
      try {
        content = decodeContent(plaintext);
      } catch {
        return;
      }
      if (this.seenIds.has(content.id)) return;
      await this.markSeen(content.id);
      await this.dispatchContent(sender, content);
    } catch (e) {
      this.emitError((e as Error).message ?? String(e));
    }
  }

  /* ================= prekey hygiene ================= */

  private async topUpPreKeys(): Promise<void> {
    if (!this.acct) return;
    try {
      const { oneTimePreKeyCount, pqOneTimePreKeyCount } = await this.api.keysCount();
      if (oneTimePreKeyCount < 20) {
        const nextId = (await this.store.get<number>("kv", "nextPreKeyId")) ?? 1;
        const toGenerate = Math.max(0, 100 - oneTimePreKeyCount);
        if (toGenerate > 0) {
          const preKeys = await generatePreKeys(nextId, toGenerate);
          for (const pk of preKeys) await this.signalStore.storePreKey(pk.keyId, pk.keyPair);
          await this.store.put("kv", "nextPreKeyId", nextId + toGenerate);
          await this.api.putKeys({ oneTimePreKeys: preKeys.map(preKeyWire) });
        }
      }
      // Same trigger (below 20 remaining), independent stock, per docs/API.md GET /v1/keys/count.
      if (pqOneTimePreKeyCount !== undefined && pqOneTimePreKeyCount < 20) {
        const nextId = (await this.store.get<number>("kv", "pqNextPreKeyId")) ?? 1;
        const toGenerate = Math.max(0, 100 - pqOneTimePreKeyCount);
        if (toGenerate > 0) {
          const keys = Array.from({ length: toGenerate }, (_, i) => ({ keyId: nextId + i, ...generatePqPreKey() }));
          await this.pqSaveOneTimePreKeys(keys);
          await this.store.put("kv", "pqNextPreKeyId", nextId + toGenerate);
          await this.api.putKeys({ pqOneTimePreKeys: keys.map((k) => ({ keyId: k.keyId, publicKey: b64Encode(k.publicKey) })) });
        }
      }
    } catch {
      /* best effort; will retry on the next queue-empty */
    }
  }

  /* ================= disappearing messages ================= */

  private startSweep(): void {
    if (this.sweepTimer) return;
    this.sweepTimer = setInterval(() => void this.sweepExpired(), this.sweepIntervalMs);
    (this.sweepTimer as unknown as { unref?: () => void }).unref?.();
  }

  private stopSweep(): void {
    if (this.sweepTimer) clearInterval(this.sweepTimer);
    this.sweepTimer = null;
  }

  private async sweepExpired(): Promise<void> {
    if (!this.acct || this.locked) return;
    try {
      const expired = await this.store.expiredMessages<StoredMessage>(Date.now());
      for (const { value: m } of expired) {
        if (m.deleted) continue;
        m.deleted = true;
        m.body = "";
        m.attachment = undefined;
        m._pointer = undefined;
        m.expiresAt = undefined;
        await this.saveMessage(m);
        await this.store.delete("attachments", m.id);
        this.emit({ type: "message", message: this.toPublic(m) });
      }
    } catch {
      /* best effort */
    }
  }

  /* ================= invites, push, lock, backup ================= */

  async mintInvite(): Promise<{ code: string; expiresAt: number; link: string }> {
    this.assertReady();
    const r = await this.api.mintInvite();
    const base = (this.appUrl ?? this.api.baseUrl).replace(/\/+$/, "").replace(/#.*$/, "");
    /* The code goes in the fragment, not the path. Two reasons: the
       registration screen reads it from there, and a fragment is never sent to
       any server, so the invite code stays out of request logs and out of the
       hands of whoever hosts the page. A path would also 404 on a static host
       without a rewrite rule. */
    return { code: r.code, expiresAt: r.expiresAt, link: `${base}#invite=${encodeURIComponent(r.code)}` };
  }

  async enablePush(): Promise<boolean> {
    this.assertReady();
    const g = globalThis as unknown as {
      navigator?: { serviceWorker?: { ready: Promise<{ pushManager: { subscribe: (o: unknown) => Promise<{ toJSON(): { endpoint: string; keys: { p256dh: string; auth: string } } }> } }> } };
      PushManager?: unknown;
    };
    if (!g.navigator?.serviceWorker || !g.PushManager) return false;
    try {
      const vapid = await this.api.getVapidPublicKey();
      if (!vapid) return false;
      const reg = await g.navigator.serviceWorker.ready;
      const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToUint8Array(vapid) });
      const json = sub.toJSON();
      await this.api.putPush({ endpoint: json.endpoint, keys: json.keys });
      this.pushEnabledFlag = true;
      await this.store.put("kv", "pushEnabled", true);
      return true;
    } catch {
      return false;
    }
  }

  async disablePush(): Promise<void> {
    this.assertReady();
    try {
      await this.api.deletePush();
    } catch {
      /* best effort */
    }
    this.pushEnabledFlag = false;
    await this.store.put("kv", "pushEnabled", false);
  }

  pushEnabled(): boolean {
    return this.pushEnabledFlag;
  }

  async setLock(passphrase: string | null): Promise<void> {
    this.assertReady();
    await this.store.setLock(passphrase);
  }

  async unlock(passphrase: string): Promise<boolean> {
    await this.store.open();
    const ok = await this.store.unlock(passphrase);
    if (ok) {
      this.locked = false;
      this.acct = (await this.store.get<Account>("kv", "account")) ?? null;
      await this.ensureReady();
      this.configureSigner();
    }
    return ok;
  }

  async exportBackup(passphrase: string): Promise<Blob> {
    this.assertReady();
    if (!this.acct) throw new Error("not registered");
    const kp = await this.signalStore.getIdentityKeyPair();
    const regId = await this.signalStore.getLocalRegistrationId();
    if (!kp || regId === undefined) throw new Error("no identity to back up");
    const deliveryToken = await this.store.get<string>("kv", "deliveryToken");
    const contacts = (await this.store.getAll<StoredContact>("contacts")).map((r) => r.value);
    const chats = await this.store.getAll<Chat>("chats");
    const groups = chats.filter((r) => r.value.kind === "group" && r.value.group).map((r) => r.value);
    const sessions = await this.store.getAll<string>("sessions"); // includes the pq per-peer chains (key "pq:<username>")
    // Post-quantum private key material (docs/POSTQUANTUM.md), so a restored device can still
    // decrypt: sign future re-keys/openers (identity), and accept new incoming sessions and
    // any pending re-key targeting our currently-published signed prekey.
    const pqIdentity = await this.pqLoadIdentity();
    const pqSignedPreKey = await this.pqLoadSignedPreKey();
    const pqOneTimeRaw = await this.store.getAll<{ publicKey: Uint8Array; secretKey: Uint8Array }>("prekeys");
    const pqOneTimeKeys = pqOneTimeRaw.filter((r) => r.key.startsWith("pq:"));
    const pqNextPreKeyId = await this.store.get<number>("kv", "pqNextPreKeyId");
    const payload = {
      v: 1,
      account: this.acct,
      identityKeyPair: kp,
      registrationId: regId,
      deliveryToken,
      contacts,
      groups,
      sessions,
      pqIdentity,
      pqSignedPreKey,
      pqOneTimeKeys,
      pqNextPreKeyId,
    };
    const salt = randomBytes(16);
    const key = await deriveKeyBytes(passphrase, salt, PBKDF2_ITERATIONS);
    const iv = randomBytes(12);
    const pt = utf8Encode(JSON.stringify(toJsonSafe(payload)));
    const ct = await aesGcmEncrypt(key, iv, pt);
    const file = { v: 1, salt: b64Encode(salt), iterations: PBKDF2_ITERATIONS, iv: b64Encode(iv), ciphertext: b64Encode(ct) };
    return new Blob([JSON.stringify(file)], { type: "application/json" });
  }

  async importBackup(file: Blob, passphrase: string): Promise<Account> {
    await this.store.open();
    const text = await file.text();
    const outer = JSON.parse(text) as { v: number; salt: string; iterations: number; iv: string; ciphertext: string };
    const key = await deriveKeyBytes(passphrase, b64Decode(outer.salt), outer.iterations);
    let pt: Uint8Array;
    try {
      pt = await aesGcmDecrypt(key, b64Decode(outer.iv), b64Decode(outer.ciphertext));
    } catch {
      throw new Error("wrong passphrase or corrupt backup");
    }
    const payload = fromJsonSafe(JSON.parse(utf8Decode(pt))) as {
      account: Account;
      identityKeyPair: KeyPairType;
      registrationId: number;
      deliveryToken?: string;
      contacts: StoredContact[];
      groups: Chat[];
      sessions: Array<{ key: string; value: string }>;
      pqIdentity?: PqKeyPair;
      pqSignedPreKey?: { keyId: number; publicKey: Uint8Array; secretKey: Uint8Array };
      pqOneTimeKeys?: Array<{ key: string; value: { publicKey: Uint8Array; secretKey: Uint8Array } }>;
      pqNextPreKeyId?: number;
    };
    await this.signalStore.setIdentity({ identityKeyPair: payload.identityKeyPair, registrationId: payload.registrationId });
    if (payload.deliveryToken) await this.store.put("kv", "deliveryToken", payload.deliveryToken);
    for (const c of payload.contacts) {
      await this.store.put("contacts", c.username, c);
      if (c.identityKeyB64) await this.signalStore.trustIdentity(c.username, b64Decode(c.identityKeyB64));
      const chatId: ChatId = `u:${c.username}`;
      const existing = await this.store.get<Chat>("chats", chatId);
      if (!existing) {
        await this.store.put("chats", chatId, { id: chatId, kind: "direct", title: c.displayName ?? c.username, members: [c.username], unread: 0, disappearSeconds: 0, updatedAt: Date.now() });
      }
    }
    for (const g of payload.groups) await this.store.put("chats", g.id, g);
    for (const s of payload.sessions) await this.store.put("sessions", s.key, s.value);
    if (payload.pqIdentity) await this.pqSaveIdentity(payload.pqIdentity);
    if (payload.pqSignedPreKey) await this.pqSaveSignedPreKey(payload.pqSignedPreKey);
    if (payload.pqOneTimeKeys) for (const e of payload.pqOneTimeKeys) await this.store.put("prekeys", e.key, e.value);
    if (payload.pqNextPreKeyId !== undefined) await this.store.put("kv", "pqNextPreKeyId", payload.pqNextPreKeyId);
    this.acct = payload.account;
    await this.store.put("kv", "account", this.acct);
    this.locked = false;
    await this.ensureReady();
    this.configureSigner();
    return this.acct;
  }

  async wipe(): Promise<void> {
    this.transport.disconnect();
    this.stopSweep();
    await this.store.destroy();
    this.acct = null;
    this.locked = false;
    this.ready = false;
    this.seenIds = new Set();
    this.pushEnabledFlag = false;
    this.api.setSigner(null);
    this.connState = "offline";
  }
}
