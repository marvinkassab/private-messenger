// The operator of this server must not be able to tell when anything was
// said, or reconstruct a conversation's shape from what is stored. These
// tests are the standing proof of that, so a future change that quietly
// reintroduces a clock fails here.
//
// What the server legitimately knows is narrow and deliberate: usernames,
// their public keys, and that a mailbox currently holds n undelivered
// envelopes. Everything else is either absent or inside the ciphertext.

import { describe, expect, it } from "vitest";
import { api, registerUser, sendTo, randomContent } from "./helpers";

/** Every field name reachable from a value, however deeply nested. */
function fieldNames(value: unknown, into = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    for (const v of value) fieldNames(v, into);
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      into.add(k);
      fieldNames(v, into);
    }
  }
  return into;
}

/** Any number that looks like a wall clock, in seconds or milliseconds. */
function clockLikeNumbers(value: unknown, found: number[] = []): number[] {
  if (Array.isArray(value)) {
    for (const v of value) clockLikeNumbers(v, found);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value)) clockLikeNumbers(v, found);
  } else if (typeof value === "number" && Number.isFinite(value)) {
    const asMs = value > 1e12 && value < 4e12;
    const asSec = value > 1e9 && value < 4e9;
    if (asMs || asSec) found.push(value);
  }
  return found;
}

describe("the server keeps no clock", () => {
  it("a delivered envelope carries no timestamp in any field", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    await sendTo(alice, bob.username, randomContent(), 3);

    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(envelopes).toHaveLength(1);

    const names = fieldNames(envelopes[0]);
    for (const banned of ["timestamp", "serverTimestamp", "createdAt", "sentAt", "receivedAt", "time", "date", "day", "seq"]) {
      expect(names.has(banned)).toBe(false);
    }
    expect(clockLikeNumbers(envelopes[0])).toEqual([]);
  });

  it("the envelope id encodes no time: ids minted far apart share no prefix drift", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");

    // Two sends with a real gap between them. A ULID would put the elapsed
    // milliseconds straight into the leading characters.
    await sendTo(alice, bob.username, randomContent(), 3);
    const first = (await (await api(bob, "GET", "/v1/messages")).json<any>()).envelopes[0].id;
    await new Promise((r) => setTimeout(r, 1200));
    await sendTo(alice, bob.username, randomContent(), 1);
    const envelopes = (await (await api(bob, "GET", "/v1/messages")).json<any>()).envelopes;
    const second = envelopes[envelopes.length - 1].id;

    expect(first).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(second).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(second).not.toBe(first);
    // Sequence 1 then 2: the counter part differs only in its final characters,
    // and carries no information about the 1.2 seconds that elapsed.
    expect(first.slice(0, 8)).toBe(second.slice(0, 8));
    // Ordering still works, which is all the queue needs.
    expect(second > first).toBe(true);
  });

  it("ids are unguessable despite being sequential", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    for (let i = 0; i < 3; i++) await sendTo(alice, bob.username, randomContent(), 1);
    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    const ids = envelopes.map((e: any) => e.id);
    expect(new Set(ids).size).toBe(3);
    // The random half really is random: the tails must differ.
    const tails = ids.map((id: string) => id.slice(10));
    expect(new Set(tails).size).toBe(3);
  });

  it("a sender-supplied timestamp is ignored rather than stored", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const content = randomContent();

    // An older client still sending `timestamp` must not be able to write a
    // clock into the server's storage.
    const res = await api(alice, "POST", `/v1/messages/${bob.username}`, {
      messages: [{ destinationDeviceId: 1, type: 1, content }],
      timestamp: 1700000000000,
    });
    expect(res.status).toBe(200);

    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(envelopes).toHaveLength(1);
    expect(JSON.stringify(envelopes[0])).not.toContain("1700000000000");
    expect(clockLikeNumbers(envelopes[0])).toEqual([]);
  });

  it("a prekey bundle exposes keys and nothing about the account's history", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const bundle = await (await api(alice, "GET", `/v1/keys/${bob.username}`)).json<any>();

    const names = fieldNames(bundle);
    for (const banned of ["createdAt", "registeredAt", "lastSeen", "timestamp", "updatedAt"]) {
      expect(names.has(banned)).toBe(false);
    }
    expect(clockLikeNumbers(bundle)).toEqual([]);
  });

  it("acknowledged messages are gone, not archived", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    await sendTo(alice, bob.username, randomContent(), 3);

    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    const id = envelopes[0].id;
    expect((await api(bob, "DELETE", `/v1/messages/${id}`)).status).toBe(200);

    const after = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(after.envelopes).toHaveLength(0);
    // and the delete is idempotent, so a retry cannot resurrect it either
    expect((await api(bob, "DELETE", `/v1/messages/${id}`)).status).toBe(200);
    const again = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(again.envelopes).toHaveLength(0);
  });

  it("an unidentified send records neither who sent it nor when", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const content = randomContent();

    const res = await fetch("http://localhost/v1/messages/" + bob.username, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Unidentified-Access": bob.deliveryTokenB64,
      },
      body: JSON.stringify({ messages: [{ destinationDeviceId: 1, type: 1, content }], timestamp: Date.now() }),
    }).catch(() => null);
    // routed through SELF in this environment
    if (!res) {
      const { SELF } = await import("cloudflare:test");
      const r2 = await SELF.fetch("http://localhost/v1/messages/" + bob.username, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Unidentified-Access": bob.deliveryTokenB64 },
        body: JSON.stringify({ messages: [{ destinationDeviceId: 1, type: 1, content }], timestamp: Date.now() }),
      });
      expect(r2.status).toBe(200);
    }

    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(envelopes.length).toBeGreaterThan(0);
    const sealed = envelopes[envelopes.length - 1];
    expect(sealed.from).toBeUndefined();
    expect(clockLikeNumbers(sealed)).toEqual([]);
    expect(alice.username).toBeTruthy(); // alice is never named anywhere above
    expect(JSON.stringify(sealed)).not.toContain(alice.username);
  });
});
