# Client protocol

Everything the server carries is Signal Protocol ciphertext. This document
defines what the client puts **inside** those ciphertexts and how groups,
attachments, receipts, and sealed sender work on top of pairwise sessions.

## Sessions

- Library: `@privacyresearch/libsignal-protocol-typescript` (X3DH + Double
  Ratchet, a port of Signal's own JavaScript implementation).
- Address: `SignalProtocolAddress(username, deviceId)`. One device per user in
  this version, `deviceId = 1`.
- Session setup: fetch the recipient's bundle (`GET /v1/keys/:username`),
  `SessionBuilder.processPreKey(bundle)`. The first message is then a
  PreKeyWhisperMessage (`type 3`); later ones are WhisperMessages (`type 1`).
- Identity trust: the store implements Signal's trust-on-first-use. A changed
  identity key for a known contact is rejected until the user accepts it in the
  UI ("safety number changed"), and the contact's `verified` flag is cleared.
- Prekey hygiene: keep 100 one-time prekeys on the server, top up when
  `GET /v1/keys/count` falls below 20. Rotate the signed prekey every 7 days,
  keeping the previous one for 14 days so in-flight PreKey messages still work.
- Storage: IndexedDB database `pm-signal` with object stores `identity`,
  `prekeys`, `signedPreKeys`, `sessions`, `identities` (trusted keys), and the
  app's own stores `contacts`, `chats`, `messages`, `attachments`, `kv`. Tests
  use `fake-indexeddb`. Session records are opaque strings from the library.

## Content

The plaintext of every Signal message is UTF-8 JSON:

```ts
interface Content {
  v: 1;
  id: string;            // 16 random bytes, hex; the message id everywhere
  ts: number;            // sender's clock, ms
  group?: string;        // group id when the message belongs to a group chat
  kind: "text" | "attachment" | "reaction" | "delete" | "receipt" |
        "typing" | "group" | "profile" | "disappear";
  body?: string;         // text: the message. reaction: the emoji ("" removes)
  replyTo?: string;      // text/attachment: id of the quoted message
  ref?: string;          // reaction/delete/receipt: target message id(s), comma-separated for receipts
  attachment?: {         // kind = attachment
    id: string;          // server attachment id
    key: string;         // b64 32-byte AES-256-GCM key
    iv: string;          // b64 12-byte nonce
    digest: string;      // b64 sha256 of the ciphertext, checked before decrypt
    mime: string; size: number; name?: string; width?: number; height?: number;
    caption?: string;
  };
  receipt?: "delivered" | "read";
  group_update?: GroupUpdate;   // kind = group
  profile?: { name?: string; deliveryToken?: string };   // kind = profile
  disappear?: number;    // kind = disappear: seconds, 0 = off
  expires?: number;      // seconds after receipt to delete, copied from the chat setting at send time
}
```

Rules:

- The **sender** is the session the message decrypted on, never a field in
  the content. That is what makes it unforgeable.
- Unknown `kind` values are ignored, not errors.
- `id` must be unique per sender; duplicates are dropped (at-least-once
  delivery from the server).

## Groups

The server has no notion of groups. A group is a client-side object
replicated by control messages, and a group message is **the same content
encrypted separately to every member's session** (fan-out). This is how
Signal did groups before Sender Keys, and it is fine to about 50 members.

```ts
interface GroupUpdate {
  id: string;            // 16 random bytes hex, chosen by the creator
  revision: number;      // monotonically increasing, creator/admins only
  name: string;
  creator: string;       // username
  admins: string[];
  members: string[];     // full list, including the sender
  action: "create" | "update" | "leave";
}
```

- Creating: the creator sends `kind:"group", action:"create"` to every
  member. Each member stores the group and opens a chat `g:<id>`.
- Changing name or membership: an admin sends `action:"update"` with a higher
  `revision` and the full new state to every member of the **new** list, and
  also to removed members so their client can mark the chat read-only.
  Clients apply an update only if the sender is in the current `admins` list
  (or is the creator) and `revision` is greater than what they hold.
- Leaving: any member sends `action:"leave"` with the members list minus
  themselves; others remove them without needing an admin.
- Sending to a group: fan out to `members` minus self. A member whose session
  does not exist yet gets a fresh session (bundle fetch) transparently.
- A message from someone not in the group's member list is dropped.

## Attachments

1. Generate a random 32-byte key and 12-byte IV. Encrypt the file bytes with
   AES-256-GCM (WebCrypto). Compute `digest = sha256(ciphertext)`.
2. `POST /v1/attachments` with the ciphertext. Get `id`.
3. Send a `kind:"attachment"` content carrying id, key, iv, digest and
   metadata. Images are downscaled to at most 2048 px on the long edge and
   JPEG-encoded before step 1, unless the user chooses "original".
4. Receivers download by id, verify the digest, decrypt, and keep the
   plaintext in the `attachments` store, referenced by message id.

## Receipts, typing, reactions, deletes

- On decrypting a text/attachment message, the receiver sends
  `kind:"receipt", receipt:"delivered", ref:"<ids>"` back to the sender
  (batched up to 50 ids per receipt, at most one receipt per second per
  peer). Read receipts are sent when the chat is open and visible, if the
  user has them enabled (default on).
- `kind:"typing"` with `body:"start"|"stop"`, sent at most every 5 seconds
  while typing, never stored, never pushed (sent only when the peer is
  likely online; the server does not know, so simply send them and accept
  waste).
- Reactions: `kind:"reaction", ref:<message id>, body:<emoji>`; an empty
  body removes the sender's reaction. One reaction per sender per message.
- Delete for everyone: `kind:"delete", ref:<message id>`, honoured only when
  the sender is the message's original sender. The receiver keeps a tombstone
  ("This message was deleted").

## Disappearing messages

`kind:"disappear", disappear:<seconds>` sets the chat's timer for everyone
in the chat (in a group, admins only). Every subsequent message carries
`expires` at send time; the receiver deletes it `expires` seconds after
decrypting it, and the sender deletes it `expires` seconds after sending.
The receiving client also asks the server to drop the attachment blob early
if it can; if not, the 30-day lifecycle catches it.

## Sealed sender (unidentified delivery)

Goal: the server should not learn who sent a message once two people are in
contact.

1. Each account has a 32-byte `deliveryToken` registered with the server.
2. The first message to a new contact is sent identified (`Authorization`)
   and includes `kind:"profile"` with our name and token, and the reply does
   the same, so both sides learn each other's tokens.
3. From then on, sends use `Unidentified-Access: <token>` and the server
   stores no `from`. Because the envelope then has no sender, the client
   wraps the Signal ciphertext in a **sealed envelope**:

```
ephemeral = new Curve25519 key pair
shared    = X25519(ephemeral.priv, recipientIdentityKey)
key       = HKDF-SHA256(shared, salt = "pm-sealed-v1", info = recipientIdentityKey, 32 bytes)
inner     = JSON { from: username, deviceId, type, content }   (the Signal message)
content   = base64( ephemeral.pub(33) || iv(12) || AES-256-GCM(key, iv, inner) )
type      = 4   (in the API body; "sealed")
```

The receiver decrypts with its identity private key, then runs the inner
message through the sender's session as usual; the Double Ratchet MAC is
what authenticates the claimed sender. A sealed envelope whose inner
message fails to decrypt is discarded.

`type: 4` in `POST /v1/messages` is therefore reserved for sealed envelopes;
the server treats it as opaque like any other type.

## Safety numbers

Signal's `FingerprintGenerator(5200).createFor(localUsername, localIdentityKey,
remoteUsername, remoteIdentityKey)` produces the 60-digit safety number
(same algorithm and iteration count as Signal). Show it as 12 groups of 5,
plus a QR of the same string. "Mark as verified" sets `contact.verified`;
an identity change clears it and shows a warning bar in the chat.

## Local encryption at rest (app lock)

Optional. When the user sets a passphrase, a key is derived with PBKDF2-SHA256
(310,000 iterations, 16-byte salt) and the IndexedDB stores `identity`,
`prekeys`, `signedPreKeys`, `sessions`, and `messages` are written encrypted
(AES-256-GCM per record). Without the passphrase the app shows only the lock
screen. This is Signal's PIN/screen lock equivalent for a web client.

## Backup

`exportBackup(passphrase)` produces a JSON file with the identity key pair,
registration id, delivery token, contacts, groups, and sessions, encrypted
as above. Importing on another browser restores the same account; the server
does not need to know. Messages are not included (the server keeps no
history either; this matches Signal's model where history lives on devices).
