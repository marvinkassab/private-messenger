// Test helpers: real Curve25519 identities, signed exactly as docs/API.md says.

import { Curve25519Wrapper } from "@privacyresearch/curve25519-typescript";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { SELF } from "cloudflare:test";
import { b64Encode, hexEncode, sha256Hex, utf8 } from "../src/util";

export const BASE = "http://localhost";
export const BOOTSTRAP = "bootstrap-test-code";

let curvePromise: Promise<Curve25519Wrapper> | undefined;
export function curve(): Promise<Curve25519Wrapper> {
  return (curvePromise ??= Curve25519Wrapper.create());
}

export interface Identity {
  username: string;
  deviceId: number;
  identityKey: Uint8Array; // 33 bytes, 0x05 prefix
  identityKeyB64: string;
  privKey: ArrayBuffer;
  deliveryToken: Uint8Array;
  deliveryTokenB64: string;
}

export async function makeIdentity(username: string): Promise<Identity> {
  const c = await curve();
  const kp = c.keyPair(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const identityKey = new Uint8Array(33);
  identityKey[0] = 0x05;
  identityKey.set(new Uint8Array(kp.pubKey), 1);
  const deliveryToken = crypto.getRandomValues(new Uint8Array(32));
  return {
    username,
    deviceId: 1,
    identityKey,
    identityKeyB64: b64Encode(identityKey),
    privKey: kp.privKey,
    deliveryToken,
    deliveryTokenB64: b64Encode(deliveryToken),
  };
}

export async function xeddsaSign(privKey: ArrayBuffer, message: Uint8Array): Promise<Uint8Array> {
  const c = await curve();
  const buf = message.buffer.slice(message.byteOffset, message.byteOffset + message.byteLength) as ArrayBuffer;
  return new Uint8Array(c.sign(privKey, buf));
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

/** Builds the `Authorization: Signal ...` header for a request. */
export async function authHeader(
  id: Identity,
  method: string,
  path: string,
  body: Uint8Array = new Uint8Array(0),
  ts: number = nowSec(),
): Promise<string> {
  const message = `${method}\n${path}\n${ts}\n${await sha256Hex(body)}`;
  const sig = await xeddsaSign(id.privKey, utf8(message));
  return `Signal ${id.username}:${id.deviceId}:${ts}:${b64Encode(sig)}`;
}

/** Signed WebSocket URL query for /v1/ws. */
export async function wsUrl(id: Identity, ts: number = nowSec()): Promise<string> {
  const message = `GET\n/v1/ws\n${ts}\n${await sha256Hex(new Uint8Array(0))}`;
  const sig = await xeddsaSign(id.privKey, utf8(message));
  const q = new URLSearchParams({ u: id.username, d: String(id.deviceId), ts: String(ts), sig: b64Encode(sig) });
  return `${BASE}/v1/ws?${q.toString()}`;
}

export function encodeBody(body: unknown): Uint8Array {
  return body === undefined ? new Uint8Array(0) : utf8(JSON.stringify(body));
}

/** Sends an authenticated JSON request. */
export async function api(
  id: Identity,
  method: string,
  path: string,
  body?: unknown,
  extra: { headers?: Record<string, string>; ts?: number; origin?: string } = {},
): Promise<Response> {
  const bytes = encodeBody(body);
  const headers: Record<string, string> = {
    Authorization: await authHeader(id, method, path, bytes, extra.ts),
    ...(extra.headers ?? {}),
  };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (extra.origin) headers.Origin = extra.origin;
  return SELF.fetch(BASE + path, { method, headers, body: body === undefined ? undefined : bytes });
}

export async function makeSignedPreKey(id: Identity, keyId: number) {
  const c = await curve();
  const kp = c.keyPair(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const pub = new Uint8Array(33);
  pub[0] = 0x05;
  pub.set(new Uint8Array(kp.pubKey), 1);
  const sig = await xeddsaSign(id.privKey, pub);
  return { keyId, publicKey: b64Encode(pub), signature: b64Encode(sig) };
}

export async function makeOneTimePreKeys(count: number, firstId = 1) {
  const c = await curve();
  const out = [];
  for (let i = 0; i < count; i++) {
    const kp = c.keyPair(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const pub = new Uint8Array(33);
    pub[0] = 0x05;
    pub.set(new Uint8Array(kp.pubKey), 1);
    out.push({ keyId: firstId + i, publicKey: b64Encode(pub) });
  }
  return out;
}

/* ---- post-quantum key material (docs/POSTQUANTUM.md) ---- */

/** A real ML-DSA-65 identity, cached per test user. */
export function makePqIdentity() {
  return ml_dsa65.keygen();
}

/** A real ML-KEM-1024 signed prekey, signed under both identity keys. */
export async function makePqSignedPreKey(id: Identity, pqId: { secretKey: Uint8Array }, keyId: number) {
  const kp = ml_kem1024.keygen();
  const sig = await xeddsaSign(id.privKey, kp.publicKey);
  const pqSig = ml_dsa65.sign(kp.publicKey, pqId.secretKey);
  return {
    keyId,
    publicKey: b64Encode(kp.publicKey),
    signature: b64Encode(sig),
    pqSignature: b64Encode(pqSig),
  };
}

export function makePqOneTimePreKeys(count: number, firstId = 1) {
  const out = [];
  for (let i = 0; i < count; i++) out.push({ keyId: firstId + i, publicKey: b64Encode(ml_kem1024.keygen().publicKey) });
  return out;
}

/** The whole post-quantum half of a registration or key top-up. */
export async function pqHalf(id: Identity, pqId: ReturnType<typeof makePqIdentity>, opts: { prekeys?: number; firstId?: number; keyId?: number } = {}) {
  return {
    pqIdentityKey: b64Encode(pqId.publicKey),
    pqSignedPreKey: await makePqSignedPreKey(id, pqId, opts.keyId ?? 1),
    pqOneTimePreKeys: makePqOneTimePreKeys(opts.prekeys ?? 3, opts.firstId ?? 1),
  };
}

export async function registerBody(
  id: Identity,
  opts: { invite?: string; prekeys?: number; registrationId?: number; pq?: Record<string, unknown> } = {},
) {
  return {
    username: id.username,
    inviteCode: opts.invite ?? (await nextInvite()),
    identityKey: id.identityKeyB64,
    registrationId: opts.registrationId ?? 4242,
    deliveryToken: id.deliveryTokenB64,
    signedPreKey: await makeSignedPreKey(id, 1),
    oneTimePreKeys: await makeOneTimePreKeys(opts.prekeys ?? 5),
    ...(opts.pq ?? {}),
  };
}

let counter = 0;
export function uniqueName(prefix: string): string {
  counter += 1;
  return `${prefix}_${hexEncode(crypto.getRandomValues(new Uint8Array(3)))}${counter}`;
}

/* The bootstrap code is single-use, like every other invite, so only the
   first account in a test can use it. Everyone after that is invited by that
   first account, which is also how a real network grows.

   Storage is isolated per test, so the bootstrap code is unused again at the
   start of each one. That is the signal used here: when bootstrap succeeds we
   are in a fresh test and that user becomes the inviter; when it is refused as
   already used we are later in the same test and mint from the inviter we
   already have. */
let inviter: Identity | null = null;

/** Lets a test that spends the bootstrap code itself nominate the inviter. */
export function setInviter(id: Identity): void {
  inviter = id;
}

/**
 * An invite code that can be used right now: the bootstrap code while it is
 * still unclaimed, otherwise a freshly minted one. For tests that build the
 * registration body themselves instead of going through `registerUser`.
 */
export async function nextInvite(): Promise<string> {
  if (inviter) {
    const minted = await api(inviter, "POST", "/v1/invites");
    if (minted.status === 201) return (await minted.json<{ code: string }>()).code;
    // Storage is isolated per test, so between tests the remembered inviter
    // no longer exists. That is the signal to start again from bootstrap.
    inviter = null;
  }

  /* Spend the single-use bootstrap code on a root account that exists only to
     invite the accounts a test actually cares about. Doing it here rather than
     letting the first test account claim it means every test gets an invite,
     however it chooses to register. */
  const root = await makeIdentity(uniqueName("root"));
  const body = {
    username: root.username,
    inviteCode: BOOTSTRAP,
    identityKey: root.identityKeyB64,
    registrationId: 4242,
    deliveryToken: root.deliveryTokenB64,
    signedPreKey: await makeSignedPreKey(root, 1),
    oneTimePreKeys: await makeOneTimePreKeys(1),
  };
  const res = await api(root, "POST", "/v1/register", body);
  if (res.status !== 201) throw new Error(`bootstrap failed: ${res.status} ${await res.text()}`);
  inviter = root;

  const minted = await api(root, "POST", "/v1/invites");
  if (minted.status !== 201) throw new Error(`mint failed: ${minted.status} ${await minted.text()}`);
  return (await minted.json<{ code: string }>()).code;
}

/** Creates and registers a fresh user, bootstrapping or being invited. */
export async function registerUser(
  prefix = "user",
  opts: { prekeys?: number; invite?: string; pq?: Record<string, unknown> } = {},
): Promise<Identity> {
  const id = await makeIdentity(uniqueName(prefix));

  const res = await api(id, "POST", "/v1/register", await registerBody(id, opts));
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${await res.text()}`);
  return id;
}

export function randomContent(bytes = 64): string {
  // getRandomValues refuses more than 64 KB at a time, and attachments now
  // travel inside messages, so test payloads run to hundreds of kilobytes.
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i += 65536) {
    crypto.getRandomValues(out.subarray(i, Math.min(i + 65536, bytes)));
  }
  return b64Encode(out);
}

export async function sendTo(from: Identity, to: string, content = randomContent(), type = 1) {
  return api(from, "POST", `/v1/messages/${to}`, {
    messages: [{ destinationDeviceId: 1, type, content }],
    timestamp: Date.now(),
  });
}

/** Collects WebSocket frames as parsed JSON, with a promise-based reader. */
export class FrameReader {
  private queue: unknown[] = [];
  private waiters: Array<(v: unknown) => void> = [];
  constructor(ws: WebSocket) {
    ws.addEventListener("message", (ev) => {
      const frame = JSON.parse(String((ev as MessageEvent).data));
      const w = this.waiters.shift();
      if (w) w(frame);
      else this.queue.push(frame);
    });
  }
  next(timeoutMs = 5000): Promise<any> {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("timed out waiting for frame")), timeoutMs);
      this.waiters.push((v) => {
        clearTimeout(t);
        resolve(v);
      });
    });
  }
  pending(): number {
    return this.queue.length;
  }
}

export async function connectWs(id: Identity): Promise<{ ws: WebSocket; frames: FrameReader }> {
  const res = await SELF.fetch(await wsUrl(id), { headers: { Upgrade: "websocket" } });
  if (res.status !== 101) throw new Error(`ws connect failed: ${res.status} ${await res.text()}`);
  const ws = res.webSocket!;
  const frames = new FrameReader(ws);
  ws.accept();
  return { ws, frames };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
