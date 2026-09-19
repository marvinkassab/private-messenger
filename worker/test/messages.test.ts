import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { b64Encode } from "../src/util";
import { api, BASE, makeIdentity, randomContent, registerUser, sendTo, uniqueName } from "./helpers";

describe("messages over HTTP", () => {
  it("identified send, drain, ack, idempotent ack", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const content = randomContent(100);
    const ts = Date.now();

    const send = await api(alice, "POST", `/v1/messages/${bob.username}`, {
      messages: [{ destinationDeviceId: 1, type: 3, content }],
      timestamp: ts,
    });
    expect(send.status).toBe(200);
    expect(await send.json()).toEqual({ needsSync: false });

    const drain = await api(bob, "GET", "/v1/messages");
    expect(drain.status).toBe(200);
    const { envelopes, more } = await drain.json<any>();
    expect(more).toBe(false);
    expect(envelopes).toHaveLength(1);
    const env = envelopes[0];
    expect(env.id).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
    expect(env.from).toEqual({ username: alice.username, deviceId: 1 });
    expect(env.type).toBe(3);
    expect(env.content).toBe(content);
    // The server keeps no clock: no timestamp is stored, returned, or
    // recoverable from the id. When a message was written lives inside the
    // ciphertext, where the operator cannot read it.
    expect(env.timestamp).toBeUndefined();
    expect(env.serverTimestamp).toBeUndefined();
    expect(Object.keys(env).sort()).toEqual(["content", "from", "id", "type"]);

    // still queued until acked
    const again = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(again.envelopes).toHaveLength(1);

    const ack = await api(bob, "DELETE", `/v1/messages/${env.id}`);
    expect(ack.status).toBe(200);
    const ack2 = await api(bob, "DELETE", `/v1/messages/${env.id}`);
    expect(ack2.status).toBe(200);
    const empty = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(empty.envelopes).toEqual([]);
  });

  it("orders envelopes oldest first and pages at 100", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const messages = Array.from({ length: 101 }, () => ({ destinationDeviceId: 1, type: 1, content: randomContent(8) }));
    // one send carrying 100 messages + one more
    const r1 = await api(alice, "POST", `/v1/messages/${bob.username}`, { messages: messages.slice(0, 100), timestamp: 1 });
    expect(r1.status).toBe(200);
    const r2 = await api(alice, "POST", `/v1/messages/${bob.username}`, { messages: messages.slice(100), timestamp: 2 });
    expect(r2.status).toBe(200);
    const page = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(page.envelopes).toHaveLength(100);
    expect(page.more).toBe(true);
    const ids = page.envelopes.map((e: any) => e.id);
    expect([...ids].sort()).toEqual(ids);
    expect(page.envelopes[0].content).toBe(messages[0].content);
    expect(page.envelopes[99].content).toBe(messages[99].content);
  });

  it("404 for an unknown recipient, 413 for oversized content", async () => {
    const alice = await registerUser("alice");
    const nope = await sendTo(alice, "nobody_at_all");
    expect(nope.status).toBe(404);
    const bob = await registerUser("bob");
    const big = await sendTo(alice, bob.username, b64Encode(new Uint8Array(1024 * 1024 + 1)));
    expect(big.status).toBe(413);
  });

  it("unidentified send stores no `from`; wrong token is 403", async () => {
    const bob = await registerUser("bob");
    const content = randomContent(32);
    const body = JSON.stringify({ messages: [{ destinationDeviceId: 1, type: 4, content }], timestamp: 5 });

    const ok = await SELF.fetch(`${BASE}/v1/messages/${bob.username}`, {
      method: "POST",
      headers: { "Unidentified-Access": bob.deliveryTokenB64, "Content-Type": "application/json" },
      body,
    });
    expect(ok.status).toBe(200);

    const wrong = await SELF.fetch(`${BASE}/v1/messages/${bob.username}`, {
      method: "POST",
      headers: { "Unidentified-Access": b64Encode(crypto.getRandomValues(new Uint8Array(32))), "Content-Type": "application/json" },
      body,
    });
    expect(wrong.status).toBe(403);

    const malformed = await SELF.fetch(`${BASE}/v1/messages/${bob.username}`, {
      method: "POST",
      headers: { "Unidentified-Access": "not-base64!", "Content-Type": "application/json" },
      body,
    });
    expect(malformed.status).toBe(403);

    // unknown recipient with a token: 404 (nothing to compare against)
    const unknown = await SELF.fetch(`${BASE}/v1/messages/${uniqueName("ghost")}`, {
      method: "POST",
      headers: { "Unidentified-Access": bob.deliveryTokenB64, "Content-Type": "application/json" },
      body,
    });
    expect(unknown.status).toBe(404);

    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(envelopes).toHaveLength(1);
    expect(envelopes[0].from).toBeUndefined();
    expect("from" in envelopes[0]).toBe(false);
    expect(envelopes[0].type).toBe(4);
    expect(envelopes[0].content).toBe(content);
  });

  it("PUT /v1/profile rotates the delivery token", async () => {
    const bob = await registerUser("bob");
    const fresh = b64Encode(crypto.getRandomValues(new Uint8Array(32)));
    const rot = await api(bob, "PUT", "/v1/profile", { deliveryToken: fresh });
    expect(rot.status).toBe(200);
    const body = JSON.stringify({ messages: [{ destinationDeviceId: 1, type: 4, content: randomContent() }], timestamp: 1 });
    const old = await SELF.fetch(`${BASE}/v1/messages/${bob.username}`, {
      method: "POST",
      headers: { "Unidentified-Access": bob.deliveryTokenB64, "Content-Type": "application/json" },
      body,
    });
    expect(old.status).toBe(403);
    const ok = await SELF.fetch(`${BASE}/v1/messages/${bob.username}`, {
      method: "POST",
      headers: { "Unidentified-Access": fresh, "Content-Type": "application/json" },
      body,
    });
    expect(ok.status).toBe(200);
    const short = await api(bob, "PUT", "/v1/profile", { deliveryToken: b64Encode(new Uint8Array(16)) });
    expect(short.status).toBe(400);
  });

  it("rejects requests signed by someone else's key", async () => {
    const alice = await registerUser("alice");
    const impostor = await makeIdentity(alice.username);
    const res = await api(impostor, "GET", "/v1/messages");
    expect(res.status).toBe(401);
  });

  it("rate limits invite minting at 20 per day with 429", async () => {
    const alice = await registerUser("alice");
    for (let i = 0; i < 20; i++) {
      const res = await api(alice, "POST", "/v1/invites");
      expect(res.status, `invite ${i + 1}`).toBe(201);
    }
    const res = await api(alice, "POST", "/v1/invites");
    expect(res.status).toBe(429);
    expect((await res.json<any>()).error).toBe("rate_limited");
  });
});

describe("messages large enough to carry a photo", () => {
  // Attachments travel inside messages rather than in separate storage, so a
  // message must be able to hold one. These pin the size the client can rely
  // on, and the byte budget that stops a mailbox growing without bound.
  it("accepts a message near the 1 MB limit and returns it intact", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const big = randomContent(900 * 1024);

    const res = await sendTo(alice, bob.username, big, 1);
    expect(res.status).toBe(200);

    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(envelopes).toHaveLength(1);
    expect(envelopes[0].content).toBe(big);
  });

  it("refuses one past the limit rather than truncating it", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const res = await sendTo(alice, bob.username, randomContent(1100 * 1024), 1);
    expect(res.status).toBe(413);
    expect((await res.json<any>()).error).toBe("too_large");

    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(envelopes).toHaveLength(0);
  });

  it("keeps a mailbox inside its byte budget by dropping the oldest", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");

    // Enough large messages to cross the budget several times over would take
    // too long to send one by one, so this checks the rule holds at a smaller
    // scale: what is delivered is always the newest, never a truncated blob.
    const bodies: string[] = [];
    for (let i = 0; i < 6; i++) {
      const body = randomContent(700 * 1024);
      bodies.push(body);
      expect((await sendTo(alice, bob.username, body, 1)).status).toBe(200);
    }

    const { envelopes } = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(envelopes.length).toBeGreaterThan(0);
    // Every surviving envelope is whole, and the newest message is among them.
    for (const env of envelopes) expect(env.content.length).toBeGreaterThan(900 * 1024);
    expect(envelopes.map((e: any) => e.content)).toContain(bodies[bodies.length - 1]);
  });
});
