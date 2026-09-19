/* Signal protocol glue: identity / prekey generation, the StorageType adapter
   over our IndexedDB store, session establishment, encrypt/decrypt, sealed
   sender (PROTOCOL.md) and XEdDSA request signatures (API.md). */

import libsignalInit, {
  Direction,
  KeyHelper,
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
  setWebCrypto,
  type Curve,
  type DeviceType,
  type KeyPairType,
  type PreKeyPairType,
  type SignedPreKeyPairType,
  type StorageType,
} from "@privacyresearch/libsignal-protocol-typescript";
import type { PreKeyBundleWire } from "../types";
import type { Store } from "./store";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  b64Decode,
  b64Encode,
  binaryStringToBytes,
  bytesEqual,
  concatBytes,
  hkdfSha256,
  randomBytes,
  toArrayBuffer,
  utf8Decode,
  utf8Encode,
} from "./util";

export const DEVICE_ID = 1;
export const SEALED_TYPE = 4;
export const PREKEY_TYPE = 3;
export const WHISPER_TYPE = 1;
export const SEALED_SALT = "pm-sealed-v1";

/* ---------- library bootstrap ---------- */

let curvePromise: Promise<Curve> | null = null;
let webCryptoSet = false;

/** The library picks up `globalThis.crypto` itself, but make it explicit (Node and browsers). */
export function ensureWebCrypto(): void {
  if (webCryptoSet) return;
  const c = globalThis.crypto;
  if (!c || !c.subtle) throw new Error("WebCrypto unavailable");
  setWebCrypto(c);
  webCryptoSet = true;
}

/** The library's synchronous Curve (Curve25519 via emscripten), created once. */
export function getCurve(): Promise<Curve> {
  if (!curvePromise) {
    ensureWebCrypto();
    const mod = libsignalInit as unknown;
    const init = (typeof mod === "function" ? mod : (mod as { default: unknown }).default) as () => Promise<{ Curve: Curve }>;
    curvePromise = init().then((r) => r.Curve);
  }
  return curvePromise;
}

/* ---------- XEdDSA (request signing) ---------- */

export async function xeddsaSign(identityPrivKey: ArrayBuffer | Uint8Array, message: ArrayBuffer | Uint8Array): Promise<Uint8Array> {
  const curve = await getCurve();
  const sig = await curve.calculateSignature(toArrayBuffer(identityPrivKey), toArrayBuffer(message));
  return new Uint8Array(sig);
}

/**
 * True when `sig` is a valid XEdDSA signature of `message` under the 33-byte identity key.
 * Note: the library's `Curve.verifySignature` returns `true` when the signature is INVALID
 * (curve25519-donna's return code); this helper normalises that to plain "valid?".
 */
export async function xeddsaVerify(
  identityPubKey: ArrayBuffer | Uint8Array,
  message: ArrayBuffer | Uint8Array,
  sig: ArrayBuffer | Uint8Array,
): Promise<boolean> {
  const curve = await getCurve();
  try {
    const invalid = curve.verifySignature(toArrayBuffer(identityPubKey), toArrayBuffer(message), toArrayBuffer(sig));
    return invalid === false;
  } catch {
    return false;
  }
}

/* ---------- key generation ---------- */

export interface IdentityMaterial {
  identityKeyPair: KeyPairType;
  registrationId: number;
}

export async function generateIdentity(): Promise<IdentityMaterial> {
  ensureWebCrypto();
  return { identityKeyPair: await KeyHelper.generateIdentityKeyPair(), registrationId: KeyHelper.generateRegistrationId() };
}

export async function generateSignedPreKey(identityKeyPair: KeyPairType, keyId: number): Promise<SignedPreKeyPairType> {
  ensureWebCrypto();
  return KeyHelper.generateSignedPreKey(identityKeyPair, keyId);
}

export async function generatePreKeys(startId: number, count: number): Promise<PreKeyPairType[]> {
  ensureWebCrypto();
  const out: PreKeyPairType[] = [];
  for (let i = 0; i < count; i++) out.push(await KeyHelper.generatePreKey(startId + i));
  return out;
}

export function signedPreKeyWire(spk: SignedPreKeyPairType): { keyId: number; publicKey: string; signature: string } {
  return { keyId: spk.keyId, publicKey: b64Encode(spk.keyPair.pubKey), signature: b64Encode(spk.signature) };
}

export function preKeyWire(pk: PreKeyPairType): { keyId: number; publicKey: string } {
  return { keyId: pk.keyId, publicKey: b64Encode(pk.keyPair.pubKey) };
}

export function bundleToDevice(b: PreKeyBundleWire): DeviceType {
  const dev: DeviceType = {
    identityKey: toArrayBuffer(b64Decode(b.identityKey)),
    registrationId: b.registrationId,
    signedPreKey: {
      keyId: b.signedPreKey.keyId,
      publicKey: toArrayBuffer(b64Decode(b.signedPreKey.publicKey)),
      signature: toArrayBuffer(b64Decode(b.signedPreKey.signature)),
    },
  };
  if (b.preKey) dev.preKey = { keyId: b.preKey.keyId, publicKey: toArrayBuffer(b64Decode(b.preKey.publicKey)) };
  return dev;
}

/* ---------- StorageType over the IndexedDB store ---------- */

export const KV_IDENTITY_KEY = "identityKey";
export const KV_REGISTRATION_ID = "registrationId";

export interface SignalStoreHooks {
  /** Called when a known peer presents a different identity key. The store has NOT accepted it. */
  onIdentityChange?: (username: string, newKey: Uint8Array, oldKey: Uint8Array) => Promise<void> | void;
}

function nameOf(identifier: string): string {
  const i = identifier.indexOf(".");
  return i === -1 ? identifier : identifier.slice(0, i);
}

/**
 * Trust on first use. A changed key is rejected (returns false, so the library
 * throws "Identity key changed") and reported through `onIdentityChange`; the
 * UI decides when to accept it via `trustIdentity`.
 */
export class SignalStore implements StorageType {
  constructor(
    private readonly store: Store,
    private hooks: SignalStoreHooks = {},
  ) {}

  setHooks(h: SignalStoreHooks): void {
    this.hooks = h;
  }

  async getIdentityKeyPair(): Promise<KeyPairType | undefined> {
    return this.store.get<KeyPairType>("identity", KV_IDENTITY_KEY);
  }

  async getLocalRegistrationId(): Promise<number | undefined> {
    return this.store.get<number>("identity", KV_REGISTRATION_ID);
  }

  async setIdentity(m: IdentityMaterial): Promise<void> {
    await this.store.put("identity", KV_IDENTITY_KEY, m.identityKeyPair);
    await this.store.put("identity", KV_REGISTRATION_ID, m.registrationId);
  }

  async getTrustedIdentity(username: string): Promise<Uint8Array | undefined> {
    const v = await this.store.get<ArrayBuffer>("identities", nameOf(username));
    return v ? new Uint8Array(v) : undefined;
  }

  /** Explicitly (re)trust a key: used by acceptIdentityChange. */
  async trustIdentity(username: string, key: ArrayBuffer | Uint8Array): Promise<void> {
    await this.store.put("identities", nameOf(username), toArrayBuffer(new Uint8Array(key).slice()));
  }

  async isTrustedIdentity(identifier: string, identityKey: ArrayBuffer, _direction: Direction): Promise<boolean> {
    const name = nameOf(identifier);
    const existing = await this.getTrustedIdentity(name);
    if (!existing) return true; // first use
    if (bytesEqual(existing, identityKey)) return true;
    await this.hooks.onIdentityChange?.(name, new Uint8Array(identityKey), existing);
    return false;
  }

  async saveIdentity(encodedAddress: string, publicKey: ArrayBuffer): Promise<boolean> {
    const name = nameOf(encodedAddress);
    const existing = await this.getTrustedIdentity(name);
    if (existing && !bytesEqual(existing, publicKey)) {
      // Never silently replace: the change must go through trustIdentity().
      await this.hooks.onIdentityChange?.(name, new Uint8Array(publicKey), existing);
      return false;
    }
    if (!existing) await this.trustIdentity(name, publicKey);
    return existing === undefined;
  }

  async loadPreKey(keyId: string | number): Promise<KeyPairType | undefined> {
    return this.store.get<KeyPairType>("prekeys", String(keyId));
  }
  async storePreKey(keyId: string | number, keyPair: KeyPairType): Promise<void> {
    await this.store.put("prekeys", String(keyId), keyPair);
  }
  async removePreKey(keyId: string | number): Promise<void> {
    await this.store.delete("prekeys", String(keyId));
  }

  async loadSignedPreKey(keyId: string | number): Promise<KeyPairType | undefined> {
    return this.store.get<KeyPairType>("signedPreKeys", String(keyId));
  }
  async storeSignedPreKey(keyId: string | number, keyPair: KeyPairType): Promise<void> {
    await this.store.put("signedPreKeys", String(keyId), keyPair);
  }
  async removeSignedPreKey(keyId: string | number): Promise<void> {
    await this.store.delete("signedPreKeys", String(keyId));
  }

  async loadSession(encodedAddress: string): Promise<string | undefined> {
    return this.store.get<string>("sessions", encodedAddress);
  }
  async storeSession(encodedAddress: string, record: string): Promise<void> {
    await this.store.put("sessions", encodedAddress, record);
  }
  async removeSession(encodedAddress: string): Promise<void> {
    await this.store.delete("sessions", encodedAddress);
  }
  async removeAllSessions(username: string): Promise<void> {
    for (const k of await this.store.keys("sessions")) {
      if (nameOf(k) === username) await this.store.delete("sessions", k);
    }
  }
}

/* ---------- sessions ---------- */

export interface SignalCiphertext {
  type: number;     // 1 whisper, 3 prekey
  content: string;  // base64 serialized Signal message
}

export class SignalSessions {
  constructor(private readonly store: SignalStore) {
    ensureWebCrypto();
  }

  address(username: string): SignalProtocolAddress {
    return new SignalProtocolAddress(username, DEVICE_ID);
  }

  async hasSession(username: string): Promise<boolean> {
    return new SessionCipher(this.store, this.address(username)).hasOpenSession();
  }

  /** X3DH from a fetched bundle. Throws "Identity key changed" when the key differs from the trusted one. */
  async processBundle(bundle: PreKeyBundleWire): Promise<void> {
    const builder = new SessionBuilder(this.store, this.address(bundle.username));
    await builder.processPreKey(bundleToDevice(bundle));
  }

  async encrypt(username: string, plaintext: Uint8Array): Promise<SignalCiphertext> {
    const cipher = new SessionCipher(this.store, this.address(username));
    const res = await cipher.encrypt(toArrayBuffer(plaintext));
    if (!res.body) throw new Error("encrypt produced no body");
    return { type: res.type, content: b64Encode(binaryStringToBytes(res.body)) };
  }

  async decrypt(username: string, type: number, contentB64: string): Promise<Uint8Array> {
    const cipher = new SessionCipher(this.store, this.address(username));
    const bytes = toArrayBuffer(b64Decode(contentB64));
    if (type === PREKEY_TYPE) return new Uint8Array(await cipher.decryptPreKeyWhisperMessage(bytes));
    if (type === WHISPER_TYPE) return new Uint8Array(await cipher.decryptWhisperMessage(bytes));
    throw new Error(`unsupported message type ${type}`);
  }

  async deleteSessions(username: string): Promise<void> {
    await this.store.removeAllSessions(username);
  }
}

/* ---------- sealed sender ---------- */

export interface SealedInner {
  from: string;
  deviceId: number;
  type: number;
  content: string;
}

async function sealedKey(shared: ArrayBuffer, recipientIdentityKey: Uint8Array): Promise<Uint8Array> {
  return hkdfSha256(shared, utf8Encode(SEALED_SALT), recipientIdentityKey, 32);
}

/** Wrap a Signal ciphertext for unidentified delivery. Returns the base64 `content` for a type-4 envelope. */
export async function sealMessage(recipientIdentityKey: ArrayBuffer | Uint8Array, inner: SealedInner): Promise<string> {
  const curve = await getCurve();
  const recipient = new Uint8Array(recipientIdentityKey);
  if (recipient.length !== 33 || recipient[0] !== 0x05) throw new Error("recipient identity key must be 33 bytes with 0x05 prefix");
  const eph = curve.generateKeyPair();
  const shared = curve.calculateAgreement(toArrayBuffer(recipient), eph.privKey);
  const key = await sealedKey(shared, recipient);
  const iv = randomBytes(12);
  const ct = await aesGcmEncrypt(key, iv, utf8Encode(JSON.stringify(inner)));
  return b64Encode(concatBytes(eph.pubKey, iv, ct));
}

export class SealedSenderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SealedSenderError";
  }
}

export async function unsealMessage(ourIdentity: KeyPairType, contentB64: string): Promise<SealedInner> {
  const curve = await getCurve();
  const bytes = b64Decode(contentB64);
  if (bytes.length < 33 + 12 + 16) throw new SealedSenderError("sealed envelope too short");
  const ephPub = bytes.subarray(0, 33);
  const iv = bytes.subarray(33, 45);
  const ct = bytes.subarray(45);
  let shared: ArrayBuffer;
  try {
    shared = curve.calculateAgreement(toArrayBuffer(ephPub.slice()), ourIdentity.privKey);
  } catch (e) {
    throw new SealedSenderError(`bad ephemeral key: ${(e as Error).message}`);
  }
  const key = await sealedKey(shared, new Uint8Array(ourIdentity.pubKey));
  let pt: Uint8Array;
  try {
    pt = await aesGcmDecrypt(key, iv, ct);
  } catch {
    throw new SealedSenderError("sealed envelope does not decrypt");
  }
  let inner: unknown;
  try {
    inner = JSON.parse(utf8Decode(pt));
  } catch {
    throw new SealedSenderError("sealed envelope is not JSON");
  }
  const o = inner as Record<string, unknown>;
  if (!o || typeof o.from !== "string" || !/^[a-z0-9_]{3,32}$/.test(o.from) || typeof o.type !== "number" || typeof o.content !== "string") {
    throw new SealedSenderError("sealed envelope malformed");
  }
  return { from: o.from, deviceId: typeof o.deviceId === "number" ? o.deviceId : DEVICE_ID, type: o.type, content: o.content };
}
