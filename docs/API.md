# Server API (Cloudflare Worker)

The server is a dumb, sharded mailbox. It never sees plaintext. It stores
public key bundles so people can start Signal sessions with each other, queues
encrypted envelopes until the recipient's device fetches them, holds encrypted
attachment blobs, and pokes devices with an empty Web Push when something
arrives. It does not know about groups, names, or contents.

Base URL: `https://<worker>/v1`. All bodies are JSON unless stated. Binary
values are **standard base64** strings.

## Storage model (Durable Objects only, no D1)

- `Mailbox` Durable Object, one per username, named with `idFromName(username)`.
  Holds: identity key, registration id, delivery token, signed prekey,
  one-time prekeys, the envelope queue, the push subscription, and any live
  WebSocket connections (hibernation API). SQLite-backed storage.
- `Invite` Durable Object, one per invite code, named with `idFromName(code)`.
  Holds creator, expiry, and whether it was used.
- R2 bucket `ATTACHMENTS` for encrypted blobs. Key = attachment id.
- Worker secrets: `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY`, `VAPID_SUBJECT`,
  and optional `BOOTSTRAP_INVITE` (a code that always works, for the first
  users; the operator clears it afterwards).

Per-username sharding is what makes this scale: no table is global, every
request touches exactly one user's object (plus the recipient's on send).

## Identity and authentication

Every account has one **Curve25519 identity key** (the Signal identity key,
33 bytes with the 0x05 prefix) and, in this version, exactly one device with
`deviceId = 1`. The wire format keeps `deviceId` everywhere so multi-device
can be added without changing the API.

Requests are authenticated by **signing them with the identity key** (XEdDSA,
which is what `Curve.calculateSignature` in the Signal library produces and
`Curve.verifySignature` checks). No passwords, no bearer tokens.

```
ts       = unix seconds, as a decimal string
bodyHash = hex(sha256(raw request body)), or sha256 of the empty string if none
message  = METHOD + "\n" + PATH (no query string) + "\n" + ts + "\n" + bodyHash
sig      = XEdDSA_sign(identityPrivateKey, utf8(message))

Authorization: Signal <username>:<deviceId>:<ts>:<base64(sig)>
```

The server rejects a request when `|now - ts| > 300` seconds or the signature
does not verify against the identity key stored for that username. The
registration request is signed the same way, but verified against the identity
key **inside its body**, since the user does not exist yet.

For the WebSocket, the same four values travel as query parameters
`u`, `d`, `ts`, `sig`, with PATH `/v1/ws` and an empty body hash.

### Unidentified (sealed) sending

`POST /v1/messages/:username` accepts, instead of `Authorization`, the header
`Unidentified-Access: <base64 deliveryToken>` where the token is the 32-byte
secret the recipient set at registration. The server compares it in constant
time. It then stores the envelope **without** a `from` field: the server never
learns who sent it. Recipients hand their token to contacts inside encrypted
messages, so only people they already talk to can send unidentified.

## Errors

JSON `{ "error": "<code>", "message": "<human text>" }` with an appropriate
status: 400 bad request, 401 bad or missing auth, 403 (invite invalid, token
wrong), 404 unknown user or attachment, 409 username taken, 410 prekeys
exhausted (never returned; exhaustion just omits the one-time key), 413 too
large, 429 rate limited.

## Endpoints

### POST /v1/register

Signed with the new identity key (see above). Body:

```json
{
  "username": "marvin",
  "inviteCode": "k7Q2...",
  "identityKey": "<b64 33 bytes>",
  "registrationId": 12345,
  "deliveryToken": "<b64 32 bytes>",
  "signedPreKey": { "keyId": 1, "publicKey": "<b64 33>", "signature": "<b64 64>" },
  "oneTimePreKeys": [ { "keyId": 1, "publicKey": "<b64 33>" }, ... up to 100 ]
}
```

Rules: `username` matches `^[a-z0-9_]{3,32}$`; the invite code must exist,
be unexpired and unused (or equal `BOOTSTRAP_INVITE`); the signed prekey's
signature must verify under `identityKey`. On success the invite is marked
used by this username. Response `201 { "username": "marvin", "deviceId": 1 }`.

### GET /v1/keys/:username   (auth)

Fetches a prekey bundle for starting a session, **consuming** one one-time
prekey if any remain.

```json
{
  "username": "bob", "deviceId": 1,
  "identityKey": "<b64>", "registrationId": 4242,
  "signedPreKey": { "keyId": 1, "publicKey": "<b64>", "signature": "<b64>" },
  "preKey": { "keyId": 17, "publicKey": "<b64>" }        // may be absent
}
```

404 if the user does not exist. Rate limit: 60 bundle fetches per minute per
requesting user.

### PUT /v1/keys   (auth)

Replace the signed prekey and/or append one-time prekeys.

```json
{ "signedPreKey": { ... }, "oneTimePreKeys": [ ... ] }   // either optional
```

Response `{ "oneTimePreKeyCount": 87 }`. The server keeps at most 200
one-time prekeys; extra ones are rejected with 400.

### GET /v1/keys/count   (auth)

`{ "oneTimePreKeyCount": 87 }` so the client can top up below 20.

### PUT /v1/profile   (auth)

`{ "deliveryToken": "<b64 32>" }` rotates the unidentified-access token.

### POST /v1/messages/:username   (auth **or** Unidentified-Access)

```json
{
  "messages": [
    { "destinationDeviceId": 1, "type": 3, "content": "<b64 ciphertext>" }
  ],
  "timestamp": 1758240000000
}
```

`type` is the Signal message type: `3` = PreKeyWhisperMessage (first message
of a session), `1` = WhisperMessage. `content` is the serialized Signal
ciphertext, at most 64 KB. One envelope per message is queued in the
recipient's mailbox and, if the recipient has a live WebSocket, pushed on it
immediately. Otherwise the recipient's push subscription, if any, gets an
empty Web Push (debounced to one per 10 seconds per user).

Response `200 { "needsSync": false }`. 404 unknown recipient. 413 too large.
Rate limit: 300 sends per minute per sender (identified) or per recipient
(unidentified).

### GET /v1/messages   (auth)

Drain the queue over HTTP (for clients without a socket, and on reconnect).

```json
{ "envelopes": [ Envelope, ... ], "more": false }
```

Returns at most 100 envelopes, oldest first. They stay queued until acked.

### DELETE /v1/messages/:id   (auth)

Acknowledge (delete) one envelope. Idempotent.

### Envelope

```json
{
  "id": "01J8...",                  // ULID-like, sortable
  "from": { "username": "alice", "deviceId": 1 },   // absent for unidentified sends
  "type": 3,
  "content": "<b64>",
  "timestamp": 1758240000000,       // sender-supplied
  "serverTimestamp": 1758240000123
}
```

Queue limits: 1,000 envelopes per user, oldest dropped; envelopes older than
30 days are deleted.

### WebSocket /v1/ws?u=&d=&ts=&sig=

Server → client frames (JSON):

- `{ "type": "envelope", "envelope": Envelope }`
- `{ "type": "queue-empty" }` sent once after connect when the backlog has
  been flushed, and again whenever the queue drains.

Client → server frames:

- `{ "type": "ack", "id": "<envelope id>" }` deletes the envelope.
- `{ "type": "ping" }` → `{ "type": "pong" }`

On connect the server streams the entire backlog, oldest first. Unacked
envelopes are re-sent on the next connect. The server uses the hibernation
API so idle sockets cost nothing.

### POST /v1/attachments   (auth)

Raw body: the client-encrypted blob (`Content-Type: application/octet-stream`),
at most 25 MB. Response `201 { "id": "<64 hex>" }`. The id is random and is the
only way to find the blob; the key to decrypt it travels inside a Signal
message.

### GET /v1/attachments/:id   (no auth)

Streams the blob. 404 if unknown or expired (30-day R2 lifecycle rule,
documented in the README).

### POST /v1/invites   (auth)

Mints a single-use invite code valid 7 days. `201 { "code": "...", "expiresAt": 1758... }`.
Rate limit: 20 per day per user.

### PUT /v1/push   (auth)

Web Push subscription as the browser produces it:
`{ "endpoint": "https://...", "keys": { "p256dh": "<b64url>", "auth": "<b64url>" } }`.
`DELETE /v1/push` removes it. Pushes are sent with VAPID, empty payload,
`TTL: 86400`, `Urgency: high`.

### GET /v1/health

`{ "ok": true }`.

## Rate limiting and abuse

Counters live in the relevant `Mailbox` object (per user, per minute window).
Per-IP limits and bot protection are Cloudflare WAF rules in front of the
Worker, not code. Registration is invite-only, which is the main abuse
control for a friends-and-family network.

## CORS

The Worker allows the client origin(s) listed in the `ALLOWED_ORIGINS` var
(comma separated), with `Authorization, Unidentified-Access, Content-Type`
headers and `GET, POST, PUT, DELETE, OPTIONS` methods.
