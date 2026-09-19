import { beforeEach, describe, expect, it } from "vitest";
import type { Message } from "../../src/types";
import { EventLog, makeClient, registerAndConnect } from "./harness";
import { FakeServer } from "./fakeServer";

describe("receipts, reactions, delete, disappearing", () => {
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

  it("marks a sent message delivered, then read", async () => {
    const { alice, bob } = await setup();
    const aliceLog = new EventLog(alice);

    const sent = await alice.sendText("u:bob", "ping");
    expect(sent.status).toBe("sent");

    await aliceLog.waitFor((e) => e.type === "message" && e.message.id === sent.id && e.message.status === "delivered");

    await bob.markRead("u:alice");
    await aliceLog.waitFor((e) => e.type === "message" && e.message.id === sent.id && e.message.status === "read");

    const [msgs] = [await alice.getMessages("u:bob")];
    const final = msgs.find((m) => m.id === sent.id);
    expect(final?.status).toBe("read");
  });

  it("reaction add/remove round-trips to the sender", async () => {
    const { alice, bob } = await setup();
    const bobLog = new EventLog(bob);
    const aliceLog = new EventLog(alice);
    const sent = await alice.sendText("u:bob", "react to this");
    await bobLog.waitFor((e) => e.type === "message" && e.message.id === sent.id);

    await bob.react(sent.id, "👍");
    await aliceLog.waitFor((e) => e.type === "message" && e.message.id === sent.id && !!e.message.reactions["👍"]?.includes("bob"));
    let mine = await alice.getMessages("u:bob");
    expect(mine.find((m) => m.id === sent.id)?.reactions["👍"]).toEqual(["bob"]);

    await bob.react(sent.id, "👍"); // same emoji again removes it
    await aliceLog.waitFor((e) => e.type === "message" && e.message.id === sent.id && !e.message.reactions["👍"]);
    mine = await alice.getMessages("u:bob");
    expect(mine.find((m) => m.id === sent.id)?.reactions["👍"]).toBeUndefined();
  });

  it("delete for everyone leaves a tombstone on both sides", async () => {
    const { alice, bob } = await setup();
    const bobLog = new EventLog(bob);
    const sent = await alice.sendText("u:bob", "oops");
    await bobLog.waitFor((e) => e.type === "message" && e.message.id === sent.id);

    await alice.deleteForEveryone(sent.id);
    await bobLog.waitFor((e) => e.type === "message" && e.message.id === sent.id && e.message.deleted === true);

    const aliceCopy = (await alice.getMessages("u:bob")).find((m) => m.id === sent.id) as Message;
    const bobCopy = (await bob.getMessages("u:alice")).find((m) => m.id === sent.id) as Message;
    expect(aliceCopy.deleted).toBe(true);
    expect(aliceCopy.body).toBe("");
    expect(bobCopy.deleted).toBe(true);
    expect(bobCopy.body).toBe("");
  });

  it("a non-sender cannot delete-for-everyone someone else's message", async () => {
    const { alice, bob } = await setup();
    const bobLog = new EventLog(bob);
    const sent = await alice.sendText("u:bob", "mine only");
    await bobLog.waitFor((e) => e.type === "message" && e.message.id === sent.id);
    await expect(bob.deleteForEveryone(sent.id)).rejects.toThrow();
  });

  it("disappearing messages carry an expiry and get swept from both sides", async () => {
    const { alice, bob } = await setup();
    const bobLog = new EventLog(bob);
    const aliceLog = new EventLog(alice);

    await alice.setDisappearing("u:bob", 1);
    await bobLog.waitFor((e) => e.type === "chat" && e.chat.id === "u:alice" && e.chat.disappearSeconds === 1);

    const sent = await alice.sendText("u:bob", "self destruct");
    expect(sent.expiresAt).toBeDefined();
    const bobMsgEvent = await bobLog.waitFor((e) => e.type === "message" && e.message.id === sent.id);
    expect((bobMsgEvent as { type: "message"; message: Message }).message.expiresAt).toBeDefined();

    await bobLog.waitFor((e) => e.type === "message" && e.message.id === sent.id && e.message.deleted === true, 4000);
    await aliceLog.waitFor((e) => e.type === "message" && e.message.id === sent.id && e.message.deleted === true, 4000);

    const bobCopy = (await bob.getMessages("u:alice")).find((m) => m.id === sent.id) as Message;
    const aliceCopy = (await alice.getMessages("u:bob")).find((m) => m.id === sent.id) as Message;
    expect(bobCopy.deleted).toBe(true);
    expect(aliceCopy.deleted).toBe(true);
  });
});
