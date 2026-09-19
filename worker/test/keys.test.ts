import { describe, expect, it } from "vitest";
import { api, makeOneTimePreKeys, makeSignedPreKey, registerUser } from "./helpers";

describe("prekeys", () => {
  it("fetching a bundle consumes one-time prekeys and omits them when exhausted", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob", { prekeys: 2 });

    const first = await api(alice, "GET", `/v1/keys/${bob.username}`);
    expect(first.status).toBe(200);
    const b1 = await first.json<any>();
    expect(b1.username).toBe(bob.username);
    expect(b1.deviceId).toBe(1);
    expect(b1.identityKey).toBe(bob.identityKeyB64);
    expect(b1.registrationId).toBe(4242);
    expect(b1.signedPreKey.keyId).toBe(1);
    expect(b1.preKey.keyId).toBe(1);

    const b2 = await (await api(alice, "GET", `/v1/keys/${bob.username}`)).json<any>();
    expect(b2.preKey.keyId).toBe(2);

    const b3 = await (await api(alice, "GET", `/v1/keys/${bob.username}`)).json<any>();
    expect(b3.preKey).toBeUndefined();
    expect(b3.signedPreKey).toEqual(b1.signedPreKey);

    const count = await (await api(bob, "GET", "/v1/keys/count")).json<any>();
    expect(count).toEqual({ oneTimePreKeyCount: 0 });
  });

  it("404 for an unknown user", async () => {
    const alice = await registerUser("alice");
    const res = await api(alice, "GET", "/v1/keys/nobody_here");
    expect(res.status).toBe(404);
  });

  it("requires auth", async () => {
    const alice = await registerUser("alice");
    const { SELF } = await import("cloudflare:test");
    const res = await SELF.fetch(`http://localhost/v1/keys/${alice.username}`);
    expect(res.status).toBe(401);
  });

  it("counts and tops up one-time prekeys, capping at 200", async () => {
    const bob = await registerUser("bob", { prekeys: 10 });
    expect(await (await api(bob, "GET", "/v1/keys/count")).json()).toEqual({ oneTimePreKeyCount: 10 });

    const up = await api(bob, "PUT", "/v1/keys", { oneTimePreKeys: await makeOneTimePreKeys(90, 11) });
    expect(up.status).toBe(200);
    expect(await up.json()).toEqual({ oneTimePreKeyCount: 100 });

    const tooMany = await api(bob, "PUT", "/v1/keys", { oneTimePreKeys: await makeOneTimePreKeys(101, 101) });
    expect(tooMany.status).toBe(400);
    expect(await (await api(bob, "GET", "/v1/keys/count")).json()).toEqual({ oneTimePreKeyCount: 100 });

    const exact = await api(bob, "PUT", "/v1/keys", { oneTimePreKeys: await makeOneTimePreKeys(100, 101) });
    expect(exact.status).toBe(200);
    expect(await exact.json()).toEqual({ oneTimePreKeyCount: 200 });
  });

  it("rotates the signed prekey and rejects a bad signature", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const spk2 = await makeSignedPreKey(bob, 2);
    const res = await api(bob, "PUT", "/v1/keys", { signedPreKey: spk2 });
    expect(res.status).toBe(200);
    const bundle = await (await api(alice, "GET", `/v1/keys/${bob.username}`)).json<any>();
    expect(bundle.signedPreKey).toEqual(spk2);

    const forged = await makeSignedPreKey(alice, 3);
    const bad = await api(bob, "PUT", "/v1/keys", { signedPreKey: forged });
    expect(bad.status).toBe(400);
  });
});
