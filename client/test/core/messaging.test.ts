import { beforeEach, describe, expect, it } from "vitest";
import type { Message, MessengerEvent } from "../../src/types";
import { EventLog, makeClient, registerAndConnect } from "./harness";
import { FakeServer } from "./fakeServer";

describe("registration and contacts", () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
  });

  it("registers Alice and Bob; Alice adding Bob gives Bob a chat and Alice's profile", async () => {
    const alice = makeClient(server);
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");

    const contact = await alice.addContact("bob");
    expect(contact.username).toBe("bob");
    expect(contact.hasDeliveryToken).toBe(false); // alice doesn't know bob's token yet

    // The whole handshake (alice's profile -> bob's auto-reply) is awaited synchronously
    // by the fake server, so by the time addContact() resolves both sides are caught up.
    const bobChat = await bob.getChat("u:alice");
    expect(bobChat?.kind).toBe("direct");
    const bobContact = await bob.getContact("alice");
    expect(bobContact?.displayName).toBe("Alice");

    const aliceContact = await alice.getContact("bob");
    expect(aliceContact?.hasDeliveryToken).toBe(true); // alice learned bob's token from his reply
  });

  it("rejects adding yourself", async () => {
    const alice = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await expect(alice.addContact("alice")).rejects.toThrow();
  });
});

describe("text messaging", () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
  });

  async function setup() {
    const alice = makeClient(server);
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await alice.addContact("bob");
    return { alice, bob };
  }

  it("delivers text both directions", async () => {
    const { alice, bob } = await setup();
    const bobLog = new EventLog(bob);

    // The handshake triggered by addContact is the very first envelope on this session, and it
    // is a PreKey message (type 3); see test/core/signal.test.ts for the type-3-then-type-1
    // progression at the Signal session layer itself (this layer seals subsequent envelopes,
    // see the "sends sealed" test below, so the outer envelope type no longer reflects it).
    const firstFromAlice = server.sentEnvelopesTo("bob")[0]!;
    expect(firstFromAlice.type).toBe(3); // PreKeyWhisperMessage
    expect(firstFromAlice.from?.username).toBe("alice");

    await alice.sendText("u:bob", "hello bob");
    const msgEvent = await bobLog.waitFor((e) => e.type === "message" && e.message.body === "hello bob");
    expect((msgEvent as { type: "message"; message: Message }).message.sender).toBe("alice");

    await bob.sendText("u:alice", "hi alice");
    const aliceChat = await alice.getChat("u:bob");
    expect(aliceChat?.lastMessage?.body).toBe("hi alice");
  });

  it("sends sealed (no `from`) once both sides know each other's delivery token", async () => {
    const { alice, bob } = await setup();
    const bobLog = new EventLog(bob);
    const aliceLog = new EventLog(alice);

    await alice.sendText("u:bob", "first sealed message?");
    await bobLog.waitFor((e) => e.type === "message" && e.message.body === "first sealed message?");
    await bob.sendText("u:alice", "reply, also sealed");
    await aliceLog.waitFor((e) => e.type === "message" && e.message.body === "reply, also sealed");

    const toBob = server.sentEnvelopesTo("bob");
    const lastToBob = toBob[toBob.length - 1]!;
    expect(lastToBob.type).toBe(4);
    expect(lastToBob.from).toBeUndefined();

    const toAlice = server.sentEnvelopesTo("alice");
    const lastToAlice = toAlice[toAlice.length - 1]!;
    expect(lastToAlice.type).toBe(4);
    expect(lastToAlice.from).toBeUndefined();
  });

  it("decrypts three messages delivered out of order", async () => {
    const bobTransport = server.transport();
    const alice = makeClient(server);
    const bob = makeClient(server, { transport: bobTransport });
    await registerAndConnect(alice, server, "alice", "Alice");
    await bob.init();
    await bob.register("bob", server.bootstrapInvite, "Bob");
    await bob.connect(); // wires bobTransport's handlers
    await alice.addContact("bob");

    // Take bob offline so alice's sends just queue, then feed them to his live handler ourselves,
    // in a scrambled order, to prove the Double Ratchet tolerates out-of-order arrival.
    bob.disconnect();

    await alice.sendText("u:bob", "one");
    await alice.sendText("u:bob", "two");
    await alice.sendText("u:bob", "three");

    const queued = server.queueOf("bob");
    expect(queued.length).toBe(3);
    const shuffled = [queued[2]!, queued[0]!, queued[1]!];

    const bobLog = new EventLog(bob);
    for (const env of shuffled) await bobTransport.simulate(env);

    await bobLog.waitFor((e) => e.type === "message" && e.message.body === "two");
    const msgs = await bob.getMessages("u:alice");
    const bodies = msgs.filter((m) => m.kind === "text").map((m) => m.body).sort();
    expect(bodies).toEqual(["one", "three", "two"]);
  });
});
