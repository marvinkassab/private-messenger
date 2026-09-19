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

## What the server can and cannot see

Everything that leaves a device is Signal ciphertext. The server stores and
forwards it; it cannot read it, and neither can Cloudflare.

| The server knows | The server does not know |
| --- | --- |
| Usernames and their public keys | Any message text, photo, file, reaction, or group name |
| That an envelope was queued for user X, and when | Who sent it, once two people are in contact (sealed sender) |
| Envelope sizes | Who is in which group, or that groups exist at all |
| Push subscriptions and IP addresses | Display names, safety-number checks, anything about contacts |

The first message between two people is sent identified so they can swap
delivery tokens; every message after that is sealed.

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

You need a GitHub account and a Cloudflare account (the free plan works).

### 1. GitHub

1. Create a repository, for example `private-messenger`, and push this code
   to its `main` branch.
2. In the repository, open **Settings → Secrets and variables → Actions**.
   Add two **secrets**: `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`
   (created in step 2 below), and two **variables**: `API_URL` and
   `PAGES_PROJECT` (values from steps 3 and 4).

### 2. Cloudflare account pieces

1. Dashboard sidebar: copy your **Account ID**.
2. **My Profile → API Tokens → Create Token → Edit Cloudflare Workers**
   template. Add the permission **Account → Cloudflare Pages → Edit** and
   **Account → Workers R2 Storage → Edit**. Copy the token.
3. **R2 → Create bucket** named `private-messenger-attachments`. In the
   bucket's **Settings → Object lifecycle rules**, add a rule that deletes
   objects 30 days after upload.

### 3. The Worker (API)

From your machine, once, with Node 22 installed:

```
cd worker
npm install --legacy-peer-deps
npx wrangler login
node -e "const k=require('crypto').generateKeyPairSync('ec',{namedCurve:'prime256v1'});const b=(x)=>x.toString('base64url');console.log('VAPID_PUBLIC_KEY='+b(k.publicKey.export({type:'spki',format:'der'}).subarray(-65)));console.log('VAPID_PRIVATE_KEY='+b(k.privateKey.export({type:'pkcs8',format:'der'}).subarray(36,68)))"
npx wrangler secret put VAPID_PUBLIC_KEY      # paste the value printed above
npx wrangler secret put VAPID_PRIVATE_KEY
npx wrangler secret put VAPID_SUBJECT         # mailto:you@example.com
npx wrangler secret put BOOTSTRAP_INVITE      # any long random string; your first invite
npx wrangler deploy
```

The deploy prints the Worker URL, like
`https://private-messenger.<account>.workers.dev`. That is `API_URL`.
Then edit `worker/wrangler.toml` and set `ALLOWED_ORIGINS` to your Pages URL
from step 4 (and your custom domain, if any), commit, and push; the Deploy
workflow redeploys it.

### 4. The client (Pages)

1. **Workers & Pages → Create → Pages → Connect to Git**, choose the
   repository.
2. Build settings: framework **None**, build command
   `cd client && npm install --legacy-peer-deps && npm run build`,
   build output directory `client/dist`, and an environment variable
   `VITE_API_URL` = your Worker URL.
3. Deploy. The project name you chose is `PAGES_PROJECT`; the site is at
   `https://<project>.pages.dev`.
4. Optional: **Custom domains → Set up a custom domain**, for example
   `chat.yourdomain.com`. Add it to `ALLOWED_ORIGINS` too.

After this, every push to `main` runs the tests and redeploys both halves
through GitHub Actions. You can also skip Actions entirely and let Pages
build from Git on its own; the workflow is there so the Worker and the
client always ship together.

### 5. First users

Open the site, register with `BOOTSTRAP_INVITE` as the invite code, then
mint invites from Settings for everyone else and send them the links.
When everyone you want is in, clear the bootstrap code:

```
cd worker && npx wrangler secret delete BOOTSTRAP_INVITE
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
