// The server's half of docs/POSTQUANTUM.md: it stores the post-quantum key
// material as opaque bytes, checks lengths, and verifies the XEdDSA signature
// binding the ML-KEM prekey to the classical identity key. It never verifies
// ML-DSA — that is the client's job — but it must not let a caller register a
// half-upgraded bundle, because a client cannot tell that apart from a
// downgrade attack.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { describe, expect, it } from "vitest";
import { b64Encode } from "../src/util";
import {
  api,
  makeIdentity,
  makePqIdentity,
  makePqOneTimePreKeys,
  makePqSignedPreKey,
  pqHalf,
  registerBody,
  registerUser,
  uniqueName,
  xeddsaSign,
} from "./helpers";

describe("post-quantum key material", () => {
  it("serves the post-quantum half in a bundle and consumes one ML-KEM prekey at a time", async () => {
    const pqId = makePqIdentity();
    const bobId = await makeIdentity(uniqueName("bob"));
    const res = await api(bobId, "POST", "/v1/register", await registerBody(bobId, { pq: await pqHalf(bobId, pqId, { prekeys: 2 }) }));
    expect(res.status).toBe(201);

    const alice = await registerUser("alice");
    const b1 = await (await api(alice, "GET", `/v1/keys/${bobId.username}`)).json<any>();
    expect(b1.pqIdentityKey).toBe(b64Encode(pqId.publicKey));
    expect(b1.pqSignedPreKey.keyId).toBe(1);
    expect(b1.pqPreKey.keyId).toBe(1);

    const b2 = await (await api(alice, "GET", `/v1/keys/${bobId.username}`)).json<any>();
    expect(b2.pqPreKey.keyId).toBe(2);
    expect(b2.pqSignedPreKey).toEqual(b1.pqSignedPreKey);

    // exhausted: the signed prekey remains, the one-time key is simply absent
    const b3 = await (await api(alice, "GET", `/v1/keys/${bobId.username}`)).json<any>();
    expect(b3.pqPreKey).toBeUndefined();
    expect(b3.pqIdentityKey).toBe(b64Encode(pqId.publicKey));
    expect(b3.pqSignedPreKey).toEqual(b1.pqSignedPreKey);
  });

  it("the served ML-KEM prekey is usable: encapsulating to it yields the secret its holder decapsulates", async () => {
    const pqId = makePqIdentity();
    const bobKem = ml_kem1024.keygen();
    const bobId = await makeIdentity(uniqueName("bob"));
    const signature = await xeddsaSign(bobId.privKey, bobKem.publicKey);
    const body = await registerBody(bobId, {
      pq: {
        pqIdentityKey: b64Encode(pqId.publicKey),
        pqSignedPreKey: {
          keyId: 1,
          publicKey: b64Encode(bobKem.publicKey),
          signature: b64Encode(signature),
          pqSignature: b64Encode(ml_dsa65.sign(bobKem.publicKey, pqId.secretKey)),
        },
        pqOneTimePreKeys: [],
      },
    });
    expect((await api(bobId, "POST", "/v1/register", body)).status).toBe(201);

    const alice = await registerUser("alice");
    const bundle = await (await api(alice, "GET", `/v1/keys/${bobId.username}`)).json<any>();

    // Alice verifies the ML-DSA signature over the prekey, then encapsulates.
    const servedPub = Uint8Array.from(atob(bundle.pqSignedPreKey.publicKey), (ch) => ch.charCodeAt(0));
    const servedSig = Uint8Array.from(atob(bundle.pqSignedPreKey.pqSignature), (ch) => ch.charCodeAt(0));
    const servedIdentity = Uint8Array.from(atob(bundle.pqIdentityKey), (ch) => ch.charCodeAt(0));
    expect(ml_dsa65.verify(servedSig, servedPub, servedIdentity)).toBe(true);

    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(servedPub);
    const theirs = ml_kem1024.decapsulate(cipherText, bobKem.secretKey);
    expect(b64Encode(theirs)).toBe(b64Encode(sharedSecret));
  });

  it("rejects a half-upgraded bundle, so a downgrade cannot masquerade as a partial one", async () => {
    const pqId = makePqIdentity();
    const id1 = await makeIdentity(uniqueName("half"));
    const onlyIdentity = await registerBody(id1, { pq: { pqIdentityKey: b64Encode(pqId.publicKey) } });
    const r1 = await api(id1, "POST", "/v1/register", onlyIdentity);
    expect(r1.status).toBe(400);
    expect((await r1.json<any>()).message).toMatch(/together/i);

    const id2 = await makeIdentity(uniqueName("half"));
    const onlySigned = await registerBody(id2, { pq: { pqSignedPreKey: await makePqSignedPreKey(id2, pqId, 1) } });
    expect((await api(id2, "POST", "/v1/register", onlySigned)).status).toBe(400);

    const id3 = await makeIdentity(uniqueName("half"));
    const onlyOneTime = await registerBody(id3, { pq: { pqOneTimePreKeys: makePqOneTimePreKeys(2) } });
    const r3 = await api(id3, "POST", "/v1/register", onlyOneTime);
    expect(r3.status).toBe(400);
    expect((await r3.json<any>()).message).toMatch(/pqIdentityKey/i);
  });

  it("rejects an ML-KEM prekey not signed by the classical identity key", async () => {
    const pqId = makePqIdentity();
    const victim = await makeIdentity(uniqueName("victim"));
    const attacker = await makeIdentity(uniqueName("attacker"));
    const kp = ml_kem1024.keygen();
    const body = await registerBody(victim, {
      pq: {
        pqIdentityKey: b64Encode(pqId.publicKey),
        pqSignedPreKey: {
          keyId: 1,
          publicKey: b64Encode(kp.publicKey),
          // signed by somebody else: exactly the substitution the check exists for
          signature: b64Encode(await xeddsaSign(attacker.privKey, kp.publicKey)),
          pqSignature: b64Encode(ml_dsa65.sign(kp.publicKey, pqId.secretKey)),
        },
        pqOneTimePreKeys: [],
      },
    });
    const res = await api(victim, "POST", "/v1/register", body);
    expect(res.status).toBe(400);
    expect((await res.json<any>()).error).toBe("bad_signature");
  });

  it("rejects wrong-sized post-quantum keys", async () => {
    const pqId = makePqIdentity();
    const id = await makeIdentity(uniqueName("sized"));
    const good = await makePqSignedPreKey(id, pqId, 1);

    const shortIdentity = await registerBody(id, {
      pq: { pqIdentityKey: b64Encode(new Uint8Array(100)), pqSignedPreKey: good },
    });
    expect((await api(id, "POST", "/v1/register", shortIdentity)).status).toBe(400);

    const id2 = await makeIdentity(uniqueName("sized"));
    const shortKem = await registerBody(id2, {
      pq: {
        pqIdentityKey: b64Encode(pqId.publicKey),
        pqSignedPreKey: { ...good, publicKey: b64Encode(new Uint8Array(64)) },
      },
    });
    expect((await api(id2, "POST", "/v1/register", shortKem)).status).toBe(400);

    const id3 = await makeIdentity(uniqueName("sized"));
    const shortSig = await registerBody(id3, {
      pq: {
        pqIdentityKey: b64Encode(pqId.publicKey),
        pqSignedPreKey: { ...(await makePqSignedPreKey(id3, pqId, 1)), pqSignature: b64Encode(new Uint8Array(10)) },
      },
    });
    expect((await api(id3, "POST", "/v1/register", shortSig)).status).toBe(400);
  });

  it("counts and tops up ML-KEM one-time prekeys", async () => {
    const pqId = makePqIdentity();
    const id = await makeIdentity(uniqueName("topup"));
    await api(id, "POST", "/v1/register", await registerBody(id, { pq: await pqHalf(id, pqId, { prekeys: 2 }) }));

    const c1 = await (await api(id, "GET", "/v1/keys/count")).json<any>();
    expect(c1.pqOneTimePreKeyCount).toBe(2);

    const up = await api(id, "PUT", "/v1/keys", { pqOneTimePreKeys: makePqOneTimePreKeys(5, 3) });
    expect(up.status).toBe(200);
    expect((await up.json<any>()).pqOneTimePreKeyCount).toBe(7);

    // rotating the signed prekey keeps serving, under the new key id
    const rotated = await makePqSignedPreKey(id, pqId, 2);
    expect((await api(id, "PUT", "/v1/keys", { pqSignedPreKey: rotated })).status).toBe(200);
    const alice = await registerUser("alice");
    const bundle = await (await api(alice, "GET", `/v1/keys/${id.username}`)).json<any>();
    expect(bundle.pqSignedPreKey.keyId).toBe(2);
  });

  it("an account registered without the post-quantum half serves a bundle without it", async () => {
    const legacy = await registerUser("legacy");
    const alice = await registerUser("alice");
    const bundle = await (await api(alice, "GET", `/v1/keys/${legacy.username}`)).json<any>();
    expect(bundle.identityKey).toBeTruthy();
    expect(bundle.pqIdentityKey).toBeUndefined();
    expect(bundle.pqSignedPreKey).toBeUndefined();
    expect(bundle.pqPreKey).toBeUndefined();
  });
});
