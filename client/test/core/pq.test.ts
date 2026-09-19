/* The post-quantum hybrid layer, exercised through the Messenger facade (docs/POSTQUANTUM.md).
   pq.ts itself is proven correct by its own behavioural suite; these tests prove it is wired
   in correctly: registration publishes a valid bundle, sessions establish it, every message
   is actually wrapped (not just nominally), out-of-order delivery and the continuous re-key
   survive real use, downgrade is refused, a classical-only peer still works, and backup/
   restore preserves enough to keep decrypting. */

import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { beforeEach, describe, expect, it } from "vitest";
import { EventLog, makeClient, registerAndConnect } from "./harness";
import { FakeServer } from "./fakeServer";
import { PqDowngradeError } from "../../src/core/messenger";
import { generatePqIdentity, verifyPqPreKey } from "../../src/core/pq";
import { SignalSessions, SignalStore, xeddsaVerify } from "../../src/core/signal";
import { Store } from "../../src/core/store";
import { b64Decode, b64Encode } from "../../src/core/util";

(globalThis as { IDBKeyRange?: typeof IDBKeyRange }).IDBKeyRange = IDBKeyRange;

describe("post-quantum hybrid layer", () => {
  let server: FakeServer;

  beforeEach(() => {
    server = new FakeServer();
  });

  it("registration publishes a post-quantum half whose XEdDSA and ML-DSA signatures both verify", async () => {
    const alice = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");

    const mb = server.mailboxOf("alice")!;
    expect(mb.pqIdentityKey).toBeDefined();
    expect(mb.pqSignedPreKey).toBeDefined();
    expect(mb.pqOneTimePreKeys.size).toBe(100);

    const spkPub = b64Decode(mb.pqSignedPreKey!.publicKey);
    const classicalOk = await xeddsaVerify(mb.identityKey, spkPub, b64Decode(mb.pqSignedPreKey!.signature));
    expect(classicalOk).toBe(true);
    const pqOk = verifyPqPreKey(spkPub, b64Decode(mb.pqSignedPreKey!.pqSignature), b64Decode(mb.pqIdentityKey!));
    expect(pqOk).toBe(true);

    // Sizes match docs/POSTQUANTUM.md's table (ML-KEM-1024 public 1568 B, ML-DSA-65 public 1952 B).
    expect(spkPub.length).toBe(1568);
    expect(b64Decode(mb.pqIdentityKey!).length).toBe(1952);
  });

  it("Alice and Bob exchange messages with the hybrid layer active, in both directions", async () => {
    const alice = makeClient(server);
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await alice.addContact("bob");

    const aliceContact = await alice.getContact("bob");
    const bobContact = await bob.getContact("alice");
    expect(aliceContact?.pqIdentityKeyB64).toBeDefined();
    expect(bobContact?.pqIdentityKeyB64).toBeDefined();
    expect(aliceContact?.classicalOnly).toBeFalsy();
    expect(bobContact?.classicalOnly).toBeFalsy();

    const bobLog = new EventLog(bob);
    const aliceLog = new EventLog(alice);
    await alice.sendText("u:bob", "hello from alice");
    await bobLog.waitFor((e) => e.type === "message" && e.message.body === "hello from alice");
    await bob.sendText("u:alice", "hello from bob");
    await aliceLog.waitFor((e) => e.type === "message" && e.message.body === "hello from bob");

    // Steady-state overhead should be small (docs/POSTQUANTUM.md: "every other message: 50 B"
    // for the hybrid layer itself; this message is also sealed-sender and JSON-enveloped, so
    // a few hundred bytes total), well under the ~6.5 kB session-opener cost.
    const toBob = server.sentEnvelopesTo("bob");
    const openerLen = b64Decode(toBob[0]!.content).length;
    const lastOrdinary = b64Decode(toBob[toBob.length - 1]!.content);
    expect(lastOrdinary.length).toBeLessThan(600);
    expect(lastOrdinary.length).toBeLessThan(openerLen / 10);
  });

  it("the queued content is not decryptable as a Signal message body without the outer layer", async () => {
    const dbName = `pq-outer-${Math.random()}`;
    const idb = new IDBFactory();
    const alice = makeClient(server);
    const bob = makeClient(server, { dbName, indexedDB: idb });
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await alice.addContact("bob");

    const bobLog = new EventLog(bob);
    await alice.sendText("u:bob", "outer layer check");
    await bobLog.waitFor((e) => e.type === "message" && e.message.body === "outer layer check");

    const queued = server.sentEnvelopesTo("bob");
    const last = queued[queued.length - 1]!;

    // A raw handle onto bob's OWN classical Signal session (same underlying IndexedDB his
    // Messenger instance uses), entirely independent of this app's post-quantum wrapping.
    const rawStore = new Store({ dbName, indexedDB: idb });
    await rawStore.open();
    const rawSignalStore = new SignalStore(rawStore);
    const rawSessions = new SignalSessions(rawSignalStore);

    // The queued bytes ARE what bob's real classical session would need to decrypt an
    // ordinary message -- except they are the post-quantum-wrapped outer ciphertext, not the
    // Signal ciphertext itself, so decrypting them as one must fail.
    await expect(rawSessions.decrypt("alice", last.type, last.content)).rejects.toThrow();
  });

  it("out-of-order delivery still works end to end through the hybrid layer", async () => {
    const bobTransport = server.transport();
    const alice = makeClient(server);
    const bob = makeClient(server, { transport: bobTransport });
    await registerAndConnect(alice, server, "alice", "Alice");
    await bob.init();
    await bob.register("bob", server.bootstrapInvite, "Bob");
    await bob.connect();
    await alice.addContact("bob");

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

  it(
    "keeps working in both directions after a post-quantum re-key is forced",
    async () => {
      const alice = makeClient(server);
      const bob = makeClient(server);
      await registerAndConnect(alice, server, "alice", "Alice");
      await registerAndConnect(bob, server, "bob", "Bob");
      await alice.addContact("bob");

      const bobLog = new EventLog(bob);
      // REKEY_EVERY_MESSAGES = 100 (pq.ts): send enough alice->bob messages for one to land.
      for (let i = 0; i < 101; i++) {
        await alice.sendText("u:bob", `msg-${i}`);
      }
      await bobLog.waitFor((e) => e.type === "message" && e.message.body === "msg-100");

      const toBob = server.sentEnvelopesTo("bob");
      const sizes = toBob.map((e) => b64Decode(e.content).length);
      // The re-key message carries an extra ML-KEM ciphertext + fresh public key (~3.1 kB) on
      // top of the steady-state size; one message should stand out sharply from the rest.
      const ordinarySizes = sizes.slice(1, -1); // drop the (large) opener and the very last message
      const typical = Math.min(...ordinarySizes);
      expect(Math.max(...ordinarySizes)).toBeGreaterThan(typical + 2500);

      // Both directions still work after the re-key.
      const aliceLog = new EventLog(alice);
      await alice.sendText("u:bob", "post-rekey from alice");
      await bobLog.waitFor((e) => e.type === "message" && e.message.body === "post-rekey from alice");
      await bob.sendText("u:alice", "post-rekey from bob");
      await aliceLog.waitFor((e) => e.type === "message" && e.message.body === "post-rekey from bob");
    },
    30000,
  );

  it("refuses a contact whose bundle drops the post-quantum keys after previously having them", async () => {
    const alice = makeClient(server);
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await alice.addContact("bob");

    const before = await alice.getContact("bob");
    expect(before?.pqIdentityKeyB64).toBeDefined();

    server.stripPqKeys("bob");
    await expect(alice.addContact("bob")).rejects.toThrow(PqDowngradeError);

    // The existing (still fully protected) contact/session state must not have been touched.
    const after = await alice.getContact("bob");
    expect(after?.pqIdentityKeyB64).toBe(before?.pqIdentityKeyB64);
    expect(after?.classicalOnly).toBeFalsy();

    const bobLog = new EventLog(bob);
    await alice.sendText("u:bob", "still protected");
    await bobLog.waitFor((e) => e.type === "message" && e.message.body === "still protected");
  });

  it("a genuinely classical-only peer still works and is marked as such", async () => {
    const alice = makeClient(server);
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    // Simulate a pre-PQ account: strip bob's post-quantum keys before alice ever sees his bundle.
    server.stripPqKeys("bob");

    await alice.addContact("bob");
    const contact = await alice.getContact("bob");
    expect(contact?.classicalOnly).toBe(true);
    expect(contact?.pqIdentityKeyB64).toBeUndefined();

    const bobLog = new EventLog(bob);
    const aliceLog = new EventLog(alice);
    await alice.sendText("u:bob", "classical only, still works");
    await bobLog.waitFor((e) => e.type === "message" && e.message.body === "classical only, still works");
    await bob.sendText("u:alice", "reply, also classical only");
    await aliceLog.waitFor((e) => e.type === "message" && e.message.body === "reply, also classical only");
  });

  it("backup/restore preserves the post-quantum keys and a message sent afterward still decrypts", async () => {
    const alice = makeClient(server);
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await alice.addContact("bob");

    const bobLog1 = new EventLog(bob);
    await alice.sendText("u:bob", "before backup");
    await bobLog1.waitFor((e) => e.type === "message" && e.message.body === "before backup");

    const blob = await alice.exportBackup("correct horse battery staple");

    const alice2 = makeClient(server);
    await alice2.importBackup(blob, "correct horse battery staple");
    await alice2.connect();

    const contact = await alice2.getContact("bob");
    expect(contact?.pqIdentityKeyB64).toBeDefined();

    const bobLog2 = new EventLog(bob);
    const sent = await alice2.sendText("u:bob", "after restore");
    expect(sent.status).toBe("sent");
    await bobLog2.waitFor((e) => e.type === "message" && e.message.body === "after restore");

    // The reverse direction, proving alice2's restored pq identity/signed prekey are usable.
    const alice2Log = new EventLog(alice2);
    await bob.sendText("u:alice", "reply after restore");
    await alice2Log.waitFor((e) => e.type === "message" && e.message.body === "reply after restore");
  });

  it("safety numbers cover both identity keys: changing only the ML-DSA identity changes the number", async () => {
    const dbName = `pq-safety-${Math.random()}`;
    const idb = new IDBFactory();
    const alice = makeClient(server, { dbName, indexedDB: idb });
    const bob = makeClient(server);
    await registerAndConnect(alice, server, "alice", "Alice");
    await registerAndConnect(bob, server, "bob", "Bob");
    await alice.addContact("bob");

    const before = await alice.safetyNumber("bob");
    expect(before.digits).toHaveLength(60);

    // Rotate ONLY the ML-DSA identity alice has on file for bob (leaving the classical
    // identity key untouched), via a raw store handle sharing her Messenger instance's
    // IndexedDB -- the classical-only fingerprint would be blind to this change.
    const rawStore = new Store({ dbName, indexedDB: idb });
    await rawStore.open();
    const contact = (await rawStore.get<{ pqIdentityKeyB64?: string }>("contacts", "bob"))!;
    const rotated = generatePqIdentity();
    contact.pqIdentityKeyB64 = b64Encode(rotated.publicKey);
    await rawStore.put("contacts", "bob", contact);

    const after = await alice.safetyNumber("bob");
    expect(after.digits).toHaveLength(60);
    expect(after.digits).not.toBe(before.digits);
  });
});
