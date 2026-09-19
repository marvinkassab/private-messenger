import { beforeEach, describe, expect, it } from "vitest";
import { EventLog, makeClient, registerAndConnect } from "./harness";
import { FakeServer } from "./fakeServer";

describe("backup and restore", () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
  });

  it("exports and imports into a fresh instance, preserving identity and an ongoing session", async () => {
    const alice = makeClient(server);
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await alice.addContact("bob");
    await alice.sendText("u:bob", "before backup");

    const originalAccount = alice.account()!;
    const blob = await alice.exportBackup("s3cret-passphrase");

    const restored = makeClient(server);
    await restored.init();
    const restoredAccount = await restored.importBackup(blob, "s3cret-passphrase");
    expect(restoredAccount.identityKeyB64).toBe(originalAccount.identityKeyB64);
    expect(restoredAccount.username).toBe("alice");

    await restored.connect();
    const restoredLog = new EventLog(restored);
    await bob.sendText("u:alice", "after restore, still works");
    await restoredLog.waitFor((e) => e.type === "message" && e.message.body === "after restore, still works");

    const msgs = await restored.getMessages("u:bob");
    expect(msgs.some((m) => m.body === "after restore, still works")).toBe(true);
  });

  it("rejects the wrong passphrase", async () => {
    const alice = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    const blob = await alice.exportBackup("correct-horse");
    const fresh = makeClient(server);
    await fresh.init();
    await expect(fresh.importBackup(blob, "wrong-passphrase")).rejects.toThrow();
  });
});

describe("app lock", () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
  });

  it("blocks init/use until unlock() with the right passphrase", async () => {
    // Simulate an app restart: two Messenger instances pointed at the same underlying
    // IndexedDB (same dbName + a shared IDBFactory), the second one standing in for the
    // page reload that finds a passphrase already configured.
    const { IDBFactory } = await import("fake-indexeddb");
    const sharedFactory = new IDBFactory();
    const dbName = `pm-signal-lock-shared-${Math.random()}`;
    const a = makeClient(server, { dbName, indexedDB: sharedFactory });
    await a.init();
    await a.register("erin", server.bootstrapInvite, "Erin");
    await a.setLock("correcthorsebatterystaple");

    const b = makeClient(server, { dbName, indexedDB: sharedFactory });
    const { locked, account } = await b.init();
    expect(locked).toBe(true);
    expect(account?.username).toBe("erin"); // account metadata is not secret; the lock screen may show it

    await expect(b.listContacts()).rejects.toThrow();

    const badUnlock = await b.unlock("wrong-passphrase");
    expect(badUnlock).toBe(false);

    const goodUnlock = await b.unlock("correcthorsebatterystaple");
    expect(goodUnlock).toBe(true);
    expect(b.account()?.username).toBe("erin");
    await expect(b.listContacts()).resolves.toEqual([]);
  });
});
