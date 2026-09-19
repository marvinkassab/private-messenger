/* Exercises the Signal session layer directly (client/src/core/signal.ts), independent of the
   Messenger facade's sealed-sender policy, to verify the PreKey-then-Whisper message-type
   progression precisely: the first message on a freshly established session is a
   PreKeyWhisperMessage (type 3); once the initiator has decrypted any reply, her subsequent
   messages become plain WhisperMessages (type 1). The responder never sends type 3 at all. */

import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { beforeEach, describe, expect, it } from "vitest";
import type { PreKeyBundleWire } from "../../src/types";
import { PREKEY_TYPE, SignalSessions, SignalStore, WHISPER_TYPE, generateIdentity, generatePreKeys, generateSignedPreKey, preKeyWire, sealMessage, signedPreKeyWire, unsealMessage } from "../../src/core/signal";
import { Store } from "../../src/core/store";
import { b64Encode, utf8Decode, utf8Encode } from "../../src/core/util";

(globalThis as { IDBKeyRange?: typeof IDBKeyRange }).IDBKeyRange = IDBKeyRange;

interface Peer {
  username: string;
  store: Store;
  signalStore: SignalStore;
  sessions: SignalSessions;
  bundle: PreKeyBundleWire;
}

async function makePeer(username: string): Promise<Peer> {
  const store = new Store({ dbName: `sig-${username}-${Math.random()}`, indexedDB: new IDBFactory() });
  await store.open();
  const signalStore = new SignalStore(store);
  const identity = await generateIdentity();
  await signalStore.setIdentity(identity);
  const spk = await generateSignedPreKey(identity.identityKeyPair, 1);
  await signalStore.storeSignedPreKey(1, spk.keyPair);
  const [pk] = await generatePreKeys(1, 1);
  await signalStore.storePreKey(pk!.keyId, pk!.keyPair);
  const sessions = new SignalSessions(signalStore);
  const bundle: PreKeyBundleWire = {
    username,
    deviceId: 1,
    identityKey: b64Encode(identity.identityKeyPair.pubKey),
    registrationId: identity.registrationId,
    signedPreKey: signedPreKeyWire(spk),
    preKey: preKeyWire(pk!),
  };
  return { username, store, signalStore, sessions, bundle };
}

describe("signal session type progression", () => {
  let alice: Peer;
  let bob: Peer;

  beforeEach(async () => {
    alice = await makePeer("alice");
    bob = await makePeer("bob");
  });

  it("is PreKey (3) for the initiator's first message, then Whisper (1) after a reply is decrypted; the responder is always Whisper", async () => {
    await alice.sessions.processBundle(bob.bundle);

    const m1 = await alice.sessions.encrypt("bob", utf8Encode("hello"));
    expect(m1.type).toBe(PREKEY_TYPE);

    // Alice hasn't heard back yet: her session still carries a pendingPreKey, so she keeps
    // sending PreKey messages even for a second message.
    const m1b = await alice.sessions.encrypt("bob", utf8Encode("still waiting"));
    expect(m1b.type).toBe(PREKEY_TYPE);

    const decrypted1 = await bob.sessions.decrypt("alice", m1.type, m1.content);
    expect(utf8Decode(decrypted1)).toBe("hello");

    // Bob is the responder: his session was established by decrypting, never by processBundle,
    // so he never has a pendingPreKey and always sends plain Whisper messages.
    const reply = await bob.sessions.encrypt("alice", utf8Encode("hi back"));
    expect(reply.type).toBe(WHISPER_TYPE);

    // Once Alice decrypts Bob's reply, her side of the ratchet advances and drops pendingPreKey.
    const decryptedReply = await alice.sessions.decrypt("bob", reply.type, reply.content);
    expect(utf8Decode(decryptedReply)).toBe("hi back");

    const m2 = await alice.sessions.encrypt("bob", utf8Encode("now on the ratchet"));
    expect(m2.type).toBe(WHISPER_TYPE);

    const decrypted2 = await bob.sessions.decrypt("alice", m2.type, m2.content);
    expect(utf8Decode(decrypted2)).toBe("now on the ratchet");
  });

  it("tolerates out-of-order delivery: three Whisper messages decrypt correctly regardless of arrival order", async () => {
    await alice.sessions.processBundle(bob.bundle);
    const first = await alice.sessions.encrypt("bob", utf8Encode("0"));
    await bob.sessions.decrypt("alice", first.type, first.content); // establish bob's side + clear pendingPreKey via a reply
    const reply = await bob.sessions.encrypt("alice", utf8Encode("ack"));
    await alice.sessions.decrypt("bob", reply.type, reply.content);

    const c1 = await alice.sessions.encrypt("bob", utf8Encode("one"));
    const c2 = await alice.sessions.encrypt("bob", utf8Encode("two"));
    const c3 = await alice.sessions.encrypt("bob", utf8Encode("three"));
    expect([c1.type, c2.type, c3.type]).toEqual([WHISPER_TYPE, WHISPER_TYPE, WHISPER_TYPE]);

    // deliver 3, 1, 2
    const d3 = utf8Decode(await bob.sessions.decrypt("alice", c3.type, c3.content));
    const d1 = utf8Decode(await bob.sessions.decrypt("alice", c1.type, c1.content));
    const d2 = utf8Decode(await bob.sessions.decrypt("alice", c2.type, c2.content));
    expect([d1, d2, d3]).toEqual(["one", "two", "three"]);
  });
});

describe("sealed sender wrap/unseal", () => {
  it("round-trips an inner Signal message and is unreadable without the recipient's identity key", async () => {
    const alice = await makePeer("alice");
    const bob = await makePeer("bob");
    await alice.sessions.processBundle(bob.bundle);
    const cipher = await alice.sessions.encrypt("bob", utf8Encode("psst"));

    const bobIdentity = await bob.signalStore.getIdentityKeyPair();
    const bobPub = new Uint8Array(bobIdentity!.pubKey);
    const sealed = await sealMessage(bobPub, { from: "alice", deviceId: 1, type: cipher.type, content: cipher.content });

    const unsealed = await unsealMessage(bobIdentity!, sealed);
    expect(unsealed.from).toBe("alice");
    expect(unsealed.type).toBe(cipher.type);
    const plaintext = await bob.sessions.decrypt("alice", unsealed.type, unsealed.content);
    expect(utf8Decode(plaintext)).toBe("psst");

    // Someone else's identity key cannot open it.
    const eve = await makePeer("eve");
    const eveIdentity = await eve.signalStore.getIdentityKeyPair();
    await expect(unsealMessage(eveIdentity!, sealed)).rejects.toThrow();
  });
});
