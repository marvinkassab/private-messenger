import { beforeEach, describe, expect, it } from "vitest";
import type { Chat } from "../../src/types";
import { EventLog, makeClient, registerAndConnect } from "./harness";
import { FakeServer } from "./fakeServer";

describe("groups", () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
  });

  async function setupThree() {
    const alice = makeClient(server);
    const bob = makeClient(server);
    const carol = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await registerAndConnect(carol, server, "carol", "Carol");
    return { alice, bob, carol };
  }

  it("Alice creates a group of three, fans out, and Carol receives it", async () => {
    const { alice, bob, carol } = await setupThree();
    const bobLog = new EventLog(bob);
    const carolLog = new EventLog(carol);

    const chat = await alice.createGroup("Trip", ["bob", "carol"]);
    expect(chat.kind).toBe("group");
    expect(chat.group?.admins).toEqual(["alice"]);
    expect(chat.group?.members.sort()).toEqual(["alice", "bob", "carol"]);

    await bobLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id);
    await carolLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id);

    const bobChat = await bob.getChat(chat.id);
    const carolChat = await carol.getChat(chat.id);
    expect(bobChat?.title).toBe("Trip");
    expect(carolChat?.title).toBe("Trip");
    expect(carolChat?.group?.members.sort()).toEqual(["alice", "bob", "carol"]);
  });

  it("group admin rules: an admin can rename; a non-admin cannot", async () => {
    const { alice, bob, carol } = await setupThree();
    const bobLog = new EventLog(bob);
    const carolLog = new EventLog(carol);

    // Create the group with Bob already an admin isn't possible via createGroup's simple API
    // (only the creator starts as admin), so promote Bob first with an admin-only trick: Alice
    // cannot "patch admins" through updateGroup's public patch shape either -- so instead this
    // test verifies the rule the way the protocol actually exposes it: the creator (Alice) can
    // update, and a plain member (Carol) cannot.
    const chat = await alice.createGroup("Trip", ["bob", "carol"]);
    await bobLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id);
    await carolLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id);

    await expect(carol.updateGroup(chat.group!.id, { name: "Carol's Coup" })).rejects.toThrow();

    const renamed = await alice.updateGroup(chat.group!.id, { name: "Renamed Trip" });
    expect(renamed.title).toBe("Renamed Trip");
    await bobLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id && e.chat.title === "Renamed Trip");
    await carolLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id && e.chat.title === "Renamed Trip");
  });

  it("removing a member marks the chat read-only for them; the remover and remaining members can leave", async () => {
    const { alice, bob, carol } = await setupThree();
    const bobLog = new EventLog(bob);
    const carolLog = new EventLog(carol);
    const chat = await alice.createGroup("Trip", ["bob", "carol"]);
    await bobLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id);
    await carolLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id);

    await alice.updateGroup(chat.group!.id, { remove: ["carol"] });
    const carolChatEvent = await carolLog.waitFor((e) => e.type === "chat" && e.chat.id === chat.id && e.chat.group?.leftOrRemoved === true);
    expect((carolChatEvent as { type: "chat"; chat: Chat }).chat.group?.leftOrRemoved).toBe(true);

    // Carol, being removed, can no longer send.
    await expect(carol.sendText(chat.id, "can I still talk?")).rejects.toThrow();

    // Bob leaves voluntarily.
    await bob.leaveGroup(chat.group!.id);
    const bobChat = await bob.getChat(chat.id);
    expect(bobChat?.group?.leftOrRemoved).toBe(true);

    const aliceChat = await alice.getChat(chat.id);
    expect(aliceChat?.group?.members).toEqual(["alice"]);
  });
});
