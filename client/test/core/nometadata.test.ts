/* The client must not put a clock on the wire.
 *
 * The server refuses to store one, but that only helps if the client stops
 * sending it: a timestamp in the request body is visible to the server's
 * operator and to anything terminating TLS in front of it, whatever the
 * server then does with it. These tests watch the actual bytes leaving the
 * client.
 *
 * The time a message was written still travels, inside the ciphertext, which
 * is why the receiver can order and display messages correctly. The last test
 * checks exactly that: absent outside, present inside.
 */

import { describe, expect, it } from "vitest";
import type { FetchLike } from "../../src/core/api";
import { FakeServer } from "./fakeServer";
import { makeClient, EventLog } from "./harness";

/** Every number in a JSON value that looks like a wall clock. */
function clockLike(value: unknown, found: number[] = []): number[] {
  if (Array.isArray(value)) {
    for (const v of value) clockLike(v, found);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value)) clockLike(v, found);
  } else if (typeof value === "number" && Number.isFinite(value)) {
    if ((value > 1e12 && value < 4e12) || (value > 1e9 && value < 4e9)) found.push(value);
  }
  return found;
}

/** Wraps a fetch so the test can read every request body that goes out. */
function recording(inner: FetchLike) {
  const bodies: Array<{ url: string; body: unknown }> = [];
  const wrapped: FetchLike = async (input, init) => {
    const url = input;
    if (init?.body && typeof init.body === "string") {
      try {
        bodies.push({ url, body: JSON.parse(init.body) });
      } catch {
        bodies.push({ url, body: init.body });
      }
    }
    return inner(input, init);
  };
  return { wrapped, bodies };
}

describe("the client sends no clock", () => {
  it("a send request body carries no timestamp of any kind", async () => {
    const server = new FakeServer();
    const rec = recording(server.fetch);

    const alice = makeClient(server, { fetch: rec.wrapped });
    const bob = makeClient(server);
    await alice.init();
    await bob.init();
    await alice.register("alice", server.bootstrapInvite, "Alice");
    await bob.register("bob", server.bootstrapInvite, "Bob");
    await alice.connect();
    await bob.connect();

    await alice.addContact("bob");
    await alice.sendText("u:bob", "no clock on this one");

    const sends = rec.bodies.filter((b) => /\/v1\/messages\//.test(b.url));
    expect(sends.length).toBeGreaterThan(0);
    for (const s of sends) {
      const body = s.body as Record<string, unknown>;
      expect(body.timestamp).toBeUndefined();
      expect(Object.keys(body)).toEqual(["messages"]);
      expect(clockLike(body)).toEqual([]);
    }
  });

  it("registration and key uploads carry no clock either", async () => {
    const server = new FakeServer();
    const rec = recording(server.fetch);
    const alice = makeClient(server, { fetch: rec.wrapped });
    await alice.init();
    await alice.register("alice", server.bootstrapInvite, "Alice");

    for (const sent of rec.bodies) {
      expect(clockLike(sent.body)).toEqual([]);
    }
  });

  it("the write time is absent outside the ciphertext but present inside it", async () => {
    const server = new FakeServer();
    const alice = makeClient(server);
    const bob = makeClient(server);
    const bobEvents = new EventLog(bob);
    await alice.init();
    await bob.init();
    await alice.register("alice", server.bootstrapInvite, "Alice");
    await bob.register("bob", server.bootstrapInvite, "Bob");
    await alice.connect();
    await bob.connect();

    await alice.addContact("bob");
    const before = Date.now();
    await alice.sendText("u:bob", "ordering still works");

    // Nothing the server holds reveals when this was written.
    const queued = server.sentEnvelopesTo("bob");
    expect(queued.length).toBeGreaterThan(0);
    for (const env of queued) {
      // The cast is deliberate: EnvelopeWire no longer declares these fields,
      // so TypeScript alone would reject the access. Checking at runtime as
      // well catches a server that starts sending them back anyway.
      const raw = env as unknown as Record<string, unknown>;
      expect(raw.timestamp).toBeUndefined();
      expect(raw.serverTimestamp).toBeUndefined();
      expect(clockLike(raw)).toEqual([]);
    }

    // But Bob recovers it by decrypting, which is what makes ordering work.
    await bobEvents.waitFor(
      (e) => e.type === "message" && e.message.body === "ordering still works",
      5000,
    );
    const messages = await bob.getMessages("u:alice");
    const received = messages.find((m) => m.body === "ordering still works");
    expect(received).toBeDefined();
    expect(received!.sentAt).toBeGreaterThanOrEqual(before - 1000);
    expect(received!.sentAt).toBeLessThanOrEqual(Date.now() + 1000);
  });
});
