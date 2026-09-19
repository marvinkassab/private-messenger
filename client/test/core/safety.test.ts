import { beforeEach, describe, expect, it } from "vitest";
import { EventLog, makeClient, registerAndConnect } from "./harness";
import { FakeServer } from "./fakeServer";
import { IdentityChangedError } from "../../src/core/messenger";

describe("safety numbers", () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
  });

  it("Alice-for-Bob equals Bob-for-Alice, and differs for Alice-Carol", async () => {
    const alice = makeClient(server);
    const bob = makeClient(server);
    const carol = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await registerAndConnect(carol, server, "carol", "Carol");

    await alice.addContact("bob");
    await alice.addContact("carol");

    const aliceForBob = await alice.safetyNumber("bob");
    const bobForAlice = await bob.safetyNumber("alice");
    expect(aliceForBob.digits).toHaveLength(60);
    expect(aliceForBob.digits).toBe(bobForAlice.digits);

    const aliceForCarol = await alice.safetyNumber("carol");
    expect(aliceForCarol.digits).not.toBe(aliceForBob.digits);

    expect(aliceForBob.verified).toBe(false);
    await alice.setVerified("bob", true);
    const verified = await alice.safetyNumber("bob");
    expect(verified.verified).toBe(true);
  });
});

describe("identity change", () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
  });

  it("blocks Alice's send after Bob re-registers with a new identity, until she accepts the change", async () => {
    const alice = makeClient(server);
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await alice.addContact("bob");
    await alice.sendText("u:bob", "before reset");

    // Bob "reinstalls": a brand new local store, brand new identity key, same username.
    bob.disconnect();
    const invite = await alice.mintInvite();
    const bob2 = makeClient(server);
    await bob2.init();
    await bob2.register("bob", invite.code, "Bob");
    await bob2.connect();

    const aliceLog = new EventLog(alice);
    // Bob's new device re-adds Alice, which reaches her as a fresh PreKey message signed by his
    // NEW identity key -- exactly what a real reinstall looks like from Alice's point of view.
    await bob2.addContact("alice");
    await aliceLog.waitFor((e) => e.type === "contact" && e.contact.username === "bob" && e.contact.identityChanged === true);

    const aliceForBob = await alice.getContact("bob");
    expect(aliceForBob?.identityChanged).toBe(true);
    expect(aliceForBob?.verified).toBe(false);

    await expect(alice.sendText("u:bob", "does this get through?")).rejects.toThrow(IdentityChangedError);
    const failedMsgs = await alice.getMessages("u:bob");
    expect(failedMsgs[failedMsgs.length - 1]?.status).toBe("failed");

    await alice.acceptIdentityChange("bob");
    const accepted = await alice.getContact("bob");
    expect(accepted?.identityChanged).toBe(false);

    const bob2Log = new EventLog(bob2);
    const sent = await alice.sendText("u:bob", "now it should work");
    expect(sent.status).toBe("sent");
    await bob2Log.waitFor((e) => e.type === "message" && e.message.body === "now it should work");
  });
});
