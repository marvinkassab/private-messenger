# Private Messenger

End-to-end encrypted messaging for people you know, on the **Signal
Protocol**, running entirely on Cloudflare. Invite-only, no phone numbers,
no accounts to buy, and a server that never sees a word.

- **Client:** a static web app (installable PWA) on Cloudflare Pages.
- **Server:** one Cloudflare Worker with a Durable Object mailbox per user,
  R2 for encrypted attachments, and Web Push for wake-ups. No database
  server, no VM, nothing to patch.
- **Crypto:** X3DH key agreement and the Double Ratchet from Signal's own
  protocol library (TypeScript port), wrapped in a **post-quantum hybrid
  layer** (ML-KEM-1024 + ML-DSA-65) that Signal's classical design does not
  have. Plus sealed sender, Signal-style safety numbers, disappearing
  messages, and an optional passphrase lock for keys at rest.

```
 phone / laptop                      Cloudflare                          phone / laptop
┌──────────────┐    HTTPS + WSS   ┌──────────────────────────┐   HTTPS + WSS   ┌──────────────┐
│ client (PWA) │◄───────────────►│ Worker  /v1/*             │◄───────────────►│ client (PWA) │
│  Signal lib  │                  │  ├ Mailbox DO  (per user) │                 │  Signal lib  │
│  IndexedDB   │                  │  │   keys · queue · ws    │                 │  IndexedDB   │
│  service wkr │                  │  ├ Invite DO   (per code) │                 │  service wkr │
└──────────────┘                  │  └ R2  encrypted blobs    │                 └──────────────┘
        ▲                         └──────────────────────────┘                        ▲
        └──────────── Web Push (empty payload, VAPID) ────────────────────────────────┘
```

## What you, running this, can and cannot see

You will operate the server, so the honest question is not "is it encrypted"
but "what could you hand over if someone made you". The answer is kept as
close to nothing as a working messenger allows.

**The server stores no clock of any kind.** Not the time a message was sent,
not the time it arrived, not when an account was created. Message ids used to
be ULIDs, whose leading characters encode the creation time to the
millisecond; they are now a sequence number with random padding, so ordering
still works and the time does not survive anywhere. Eight tests in
`worker/test/nometadata.test.ts` exist solely to keep it that way.

| You can see | You cannot see |
| --- | --- |
| Usernames and their public keys | Any message, photo, file, reaction, or group name |
| That a mailbox holds *n* undelivered envelopes | When anything was written, sent, or read |
| Roughly how large those envelopes are | Who sent them, once two people are in contact |
| | Who is in which group, or that groups exist at all |
| | Display names, contacts, or verification state |

Messages are deleted the moment the recipient acknowledges them. The history
of a conversation exists only on the participants' own devices, in their
browser's encrypted storage, exactly like the portfolio tracker's holdings.
Nothing accumulates on the server for you to lose or be asked for.

### What still cannot be hidden, and why

Being straight about the limits matters more than the table above:

- **IP addresses.** Anything a device connects to sees where it connected
  from. Cloudflare's own edge logs exist regardless of what this code does.
  A user who cares should use a VPN or Tor.
- **Traffic timing.** You do not store when a message arrived, but a party
  watching the network as it happens sees the connection. Removing that needs
  cover traffic and batching, which costs battery and delay; it is not here.
- **Push endpoints**, for anyone who enables notifications. That is a URL
  issued by Apple or Google identifying a device. It is stored only if the
  user turns push on, and the push itself carries no content.
- **The fact that an account exists.** Usernames and public keys have to be
  visible or nobody could start a conversation.

The only way to remove the first two is to not run the transport at all. If
that matters more than reliability, the same client can be pointed at public
relays instead, and then nobody runs a server, including you.

## How it works, briefly

- **Accounts.** A username plus a Curve25519 identity key generated on the
  device. Registration needs a single-use invite code minted by an existing
  member, so the network is closed. Every API request is signed with the
  identity key; there are no passwords.
- **Sessions.** Each account publishes a signed prekey and a stock of
  one-time prekeys. To message someone, the client fetches their bundle,
  runs X3DH, and from then on the Double Ratchet gives every message its own
  key: forward secrecy and self-healing after a compromise.
- **Groups.** The server has no concept of them. A group is client-side
  state replicated by encrypted control messages; a group message is
  encrypted separately to every member's session. Fine up to roughly 50
  people per group; for huge groups Signal moved to Sender Keys, which is
  the natural next step here too.
- **Attachments.** Encrypted on the device with a fresh AES-256-GCM key,
  uploaded to R2 under a random id, and the key travels inside the message.
  R2 deletes blobs after 30 days.
- **Safety numbers.** Signal's own 60-digit fingerprint algorithm, so two
  people can compare in person or scan a QR, and mark each other verified.
  If a contact's key ever changes, sending is blocked until you accept it.
- **Push.** The server sends an empty Web Push when a message is queued and
  your device has no open socket. The notification text is built on the
  device after it fetches and decrypts.

Full specifications: [docs/API.md](docs/API.md) and
[docs/PROTOCOL.md](docs/PROTOCOL.md).

## Scale

Nothing in the design is global. Each user is one Durable Object, placed
near them, holding only their keys and queue; a message touches the sender's
object and the recipient's. Cloudflare runs these across its edge, so the
architecture goes from one family to millions of users without changing
shape. What changes with scale is operations: abuse controls, support,
costs, and, for large groups, Sender Keys. Cloudflare's pricing for Durable
Objects, R2, and Workers is per request and per GB, with a free tier that
comfortably covers a family.

## Repository layout

```
client/   Vite + TypeScript PWA. src/core = Signal sessions, storage, transport;
          src/ui = the app; src/mock = in-memory Messenger for UI work.
worker/   Cloudflare Worker: router, Mailbox and Invite Durable Objects, R2, push.
docs/     API and protocol specifications.
e2e/      Full-stack test: real Worker, real client build, real Chromium.
.github/  CI (tests on every push) and Deploy (Worker + Pages on main).
```

## Running it locally

```
npm run install:all
npm run dev:worker        # http://127.0.0.1:8787
npm run dev:client        # http://localhost:5173, talks to the local worker
```

Create `worker/.dev.vars` with `BOOTSTRAP_INVITE=anything-you-like` and use
that as the invite code for your first local account. Tests:

```
npm test                  # worker + client unit and integration tests
npm run e2e               # full stack in Chromium
```

## Setting it up on GitHub and Cloudflare

Nothing here pushes to Cloudflare. Cloudflare is connected to the GitHub
repository and builds itself on every push to `main`. No API token is needed,
and no Cloudflare credential ever has to leave your browser.

### 1. GitHub

Create a repository, for example `private-messenger`, and push this code to
`main`. That is all GitHub needs; the included workflow only runs tests.

### 2. The Worker (the server)

**Workers & Pages → Create → Workers → Import a repository**, choose this
repository, then set:

| Field | Value |
| --- | --- |
| Root directory | `worker` |
| Build command | `npm run build` |
| Deploy command | `npx wrangler deploy` |

The root directory matters. Left at `/`, the build runs the *client's* build
with none of its dependencies installed, and wrangler finds no config, which
is exactly how the first attempt fails. Pointed at `worker`, all three
commands are correct as written: wrangler picks up `worker/wrangler.toml`
beside it, and the build step is a no-op because wrangler compiles the Worker
itself during the deploy.

Before the first deploy, open **R2** in the sidebar once and create a bucket
named exactly `private-messenger-attachments`. Add a lifecycle rule under its
settings to delete objects after 30 days. The Worker binds to it by name.

Then, in the Worker's **Settings → Variables and Secrets**, add four secrets
(type *Secret*, not *Text*):

| Name | Value |
| --- | --- |
| `VAPID_PUBLIC_KEY` | from the command below |
| `VAPID_PRIVATE_KEY` | from the command below |
| `VAPID_SUBJECT` | `mailto:you@example.com` |
| `BOOTSTRAP_INVITE` | any long random string; this is your first invite code |

Generate the push keys on your own machine, with Node installed:

```
node -e "const k=require('crypto').generateKeyPairSync('ec',{namedCurve:'prime256v1'});const b=(x)=>x.toString('base64url');console.log('PUBLIC  '+b(k.publicKey.export({type:'spki',format:'der'}).subarray(-65)));console.log('PRIVATE '+b(k.privateKey.export({type:'pkcs8',format:'der'}).subarray(36,68)))"
```

`keep_vars` is set in `worker/wrangler.toml`, so later deploys leave these
secrets, and anything else configured in the dashboard, untouched.

### 3. The client (the app)

**Workers & Pages → Create → Pages → Connect to Git**, choose the same
repository, then set:

| Field | Value |
| --- | --- |
| Framework preset | None |
| Build command | `cd client && npm install --legacy-peer-deps && npm run build` |
| Build output directory | `client/dist` |
| Environment variable | `VITE_API_URL` = the Worker URL from step 2 |

### 4. Let the two halves find each other

Edit `ALLOWED_ORIGINS` in `worker/wrangler.toml` to your Pages URL, for
example `https://private-messenger.pages.dev`, commit and push. The Worker
redeploys itself. A browser origin not listed there is refused, so the app
would load and then fail to reach the server.

Optionally add a custom domain to the Pages project, such as
`chat.yourdomain.com`, and list that too.

From here on, the whole pipeline is one `git push`: the tests run on GitHub,
and Cloudflare rebuilds and deploys both halves. The deploy finishes a little
after the push returns, on Cloudflare's side, so a new build can take a reload
or two to reach a phone.

### 5. First users

Open the site, register with `BOOTSTRAP_INVITE` as the invite code, then mint
invites from Settings for everyone else and send them the links. When
everyone is in, delete the `BOOTSTRAP_INVITE` secret in the dashboard so
nobody else can register with it.

### If the repository connection is ever removed

The manual fallback, from your own machine:

```
cd worker
npm install --legacy-peer-deps
npx wrangler login
npx wrangler deploy
```

## What is Signal-grade here, and what is not

**The same as Signal:** X3DH and the Double Ratchet (per-message forward
secrecy and post-compromise security), safety numbers with the same
algorithm, sealed sender, disappearing messages, invite-only with no phone
numbers, attachments encrypted with per-file keys, nothing readable on the
server.

**Stronger than Signal, on paper:** a post-quantum hybrid layer wraps every
Signal ciphertext, so an attacker must break both independently. It uses
ML-KEM-1024 (NIST category 5) where Signal's PQXDH uses ML-KEM-768
(category 3), re-keys the post-quantum secret continuously rather than only
at session setup, and adds ML-DSA-65 signatures so identity is post-quantum
too, which Signal's design does not cover. Steady-state cost measured at
50 bytes and 0.086 ms per message. The design, its threat model, and its
limits are in [docs/POSTQUANTUM.md](docs/POSTQUANTUM.md).

The honest caveat: stronger parameters are not the same as safer software.
Signal's protocol has been attacked by professionals for a decade; this has
been reviewed by nobody.

**Not yet the same:**

- One device per account. Signal links several; the wire format already
  carries a device id so this can be added.
- Groups use pairwise fan-out (Signal's original design), not Sender Keys.
- Sealed sender uses no server-issued sender certificates, so it relies on
  the delivery token alone to gate who may send unidentified.
- No voice or video calls.
- Web app, not native: push notifications need the PWA installed (on iOS,
  added to the home screen), and there is no protection against a
  compromised browser.
- The protocol library is a maintained TypeScript port of Signal's
  JavaScript implementation, and this app around it has not been audited.
  Do not use it where a mistake would endanger someone.

## License

MIT.
