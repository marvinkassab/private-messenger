# Feature parity with Signal

An honest inventory. The first table is what works today and is covered by
tests; the second is what Signal has that this does not, split by whether it
is planned, deliberately out of scope, or impossible in a web app.

## Working today

| Feature | Notes |
| --- | --- |
| One-to-one messaging | X3DH and the Double Ratchet, per-message forward secrecy |
| Groups | Create, rename, add and remove members, leave; admin rules enforced on both the sending and receiving side |
| **Delete for everyone** | The sender can erase a message from every member's device; it leaves a tombstone, and the attachment blob is dropped locally too. Only the original sender can do it, which is enforced on receipt, not just in the UI |
| Delete for me | Removes a message from this device only |
| Reactions | One emoji per person per message, sending the same one again removes it |
| Replies | Quoted context attached to a message |
| Disappearing messages | Per chat, 1 hour to 4 weeks, applied on both ends |
| Read receipts | Delivered and read, batched and throttled |
| Typing indicators | Never stored, never pushed |
| Photos and files | Encrypted on the device with a per-file key; the server stores ciphertext under a random id |
| Safety numbers | Signal's own 60-digit algorithm, with a QR code and a verified flag |
| Identity-change protection | A contact's key changing blocks sending until you accept it |
| Sealed sender | After the first exchange the server no longer learns who sent a message |
| Invite-only registration | No phone numbers; every account needs a single-use invite from a member |
| Encrypted backup | Passphrase-locked export and import, to move an account to another browser |
| App lock | A passphrase that encrypts the keys at rest |
| Push notifications | Empty payload; the text is built on the device after decrypting |
| Post-quantum layer | Beyond Signal's parameters. See POSTQUANTUM.md |

## Planned

Ordered by how much they matter for a family, not by effort.

### Voice messages
Record with `MediaRecorder`, encode to Opus in a WebM container, encrypt with
the existing attachment pipeline, and send as `kind:"attachment"` with a
`voice: true` marker and a duration. The receiver shows a waveform and a play
button rather than a file card. No protocol change is needed beyond the marker;
the transport already carries it.

### Forward a message
Re-sends the content to another chat as a new message, with no quote and no
implication that the original sender wrote it there. Attachments are re-sent by
reference where the blob is still on the server, and re-uploaded otherwise, so
forwarding never silently fails.

### Edit a message
`kind:"edit"`, `ref` pointing at the original id, carrying the new body.
Honoured only when the sender matches the original sender, exactly like delete.
The receiver keeps the original text so the UI can show "edited" and, on
request, the history. A 24-hour limit, as Signal has, so an old message cannot
be quietly rewritten.

### Block and unblock
Purely local, and deliberately so: telling the server would tell the operator
who has fallen out with whom. A blocked contact's messages are dropped at
receipt, before they reach the chat list, and sending to them is refused. They
see no difference, which is the point.

### Mute a chat
Local, per chat, with a duration. Suppresses notifications without suppressing
delivery.

### Mentions in groups
`@username` in the body plus a `mentions` array of usernames, so a rename does
not break who was mentioned. A mention notifies even in a muted group, which is
the behaviour people expect.

### Group invite links
A link carrying the group id and a key, so someone can be added without an
admin typing their username. Expires, and can be revoked by rotating the key.
This is the one item here that needs real design work: it changes who can join
a group from "an admin added you" to "anyone with the link", so it ships with
admin approval on by default.

### View-once photos
A marker on the attachment; the receiver deletes the blob and the key after the
first view and keeps a tombstone. Honest framing in the UI: it stops a casual
second look, not a screenshot.

### Archive and pin chats
Local list state.

### Search
Across message bodies on the device. The server cannot help, since it cannot
read anything, so this is a local index over what this device holds.

## Out of scope for now

| Feature | Why |
| --- | --- |
| Voice and video calls | Needs WebRTC, TURN servers, and call signalling. Doable on this foundation, since the group key can key the media, but it is a project of its own |
| Multi-device | The wire format carries a device id everywhere so it can be added, but it needs device linking, session fan-out per device, and message sync between your own devices |
| Stickers | Cosmetic, and a whole pack format |
| Link previews | Fetching a preview leaks the link to whoever hosts it unless it is fetched through a proxy, which then learns it instead |
| Message requests | Invite-only registration already does this job: nobody can reach you without an invite from someone already in |

## Not possible in a web app

| Feature | Why |
| --- | --- |
| Notifications when the page is closed | A web page cannot run in the background. Installing it to the home screen gets push wake-ups, but there is no equivalent of a resident app |
| Protection against a compromised browser | An extension with the right permissions can read the page. A native app has the operating system between it and other software; a web page does not |
| Registration lock / PIN recovery | Signal's PIN recovers an account on a new phone from its servers. Here the account lives only on your devices, so the encrypted backup is the recovery path, and losing both the devices and the backup means losing the account |
