#!/usr/bin/env bash
# One-time Cloudflare setup.
#
# Everything here needs to run as you, because it creates things in your
# Cloudflare account. It is safe to re-run: each step checks whether it has
# already been done.
#
#   export CLOUDFLARE_API_TOKEN=...      # from the dashboard, see README
#   export CLOUDFLARE_ACCOUNT_ID=...     # from the dashboard sidebar
#   ./scripts/setup-cloudflare.sh
#
# It creates the R2 bucket, generates and stores the push keys, sets your
# first invite code, deploys the Worker, and prints the two values to paste
# into GitHub so every later push deploys itself.

set -euo pipefail

cd "$(dirname "$0")/.."
BUCKET="private-messenger-attachments"

if [[ -z "${CLOUDFLARE_API_TOKEN:-}" || -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
  cat >&2 <<'EOF'
Set these first, then run this again:

  export CLOUDFLARE_API_TOKEN=...
  export CLOUDFLARE_ACCOUNT_ID=...

The token comes from Cloudflare: My Profile -> API Tokens -> Create Token ->
"Edit Cloudflare Workers" template, then add these two permissions before
creating it:

  Account -> Workers R2 Storage -> Edit
  Account -> Cloudflare Pages   -> Edit

The account ID is in the right-hand sidebar of the Cloudflare dashboard home.
EOF
  exit 1
fi

say() { printf '\n== %s\n' "$1"; }
wr() { (cd worker && npx wrangler "$@"); }

say "Installing dependencies"
(cd worker && npm install --legacy-peer-deps --workspaces=false >/dev/null)
(cd client && npm install --legacy-peer-deps --workspaces=false >/dev/null)

say "Creating the R2 bucket for encrypted attachments"
if wr r2 bucket list 2>/dev/null | grep -q "$BUCKET"; then
  echo "already exists: $BUCKET"
else
  wr r2 bucket create "$BUCKET"
fi

say "Generating push keys"
# VAPID keys let the server wake a device. The push itself carries no content:
# the phone fetches and decrypts locally, so the notification text is built on
# the device.
KEYS=$(node -e '
const c = require("crypto");
const k = c.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const b = (x) => x.toString("base64url");
console.log(b(k.publicKey.export({ type: "spki", format: "der" }).subarray(-65)));
console.log(b(k.privateKey.export({ type: "pkcs8", format: "der" }).subarray(36, 68)));
')
VAPID_PUBLIC=$(echo "$KEYS" | sed -n 1p)
VAPID_PRIVATE=$(echo "$KEYS" | sed -n 2p)
BOOTSTRAP=$(node -e 'console.log(require("crypto").randomBytes(24).toString("base64url"))')

say "Storing secrets on the Worker"
printf '%s' "$VAPID_PUBLIC"  | wr secret put VAPID_PUBLIC_KEY
printf '%s' "$VAPID_PRIVATE" | wr secret put VAPID_PRIVATE_KEY
printf '%s' "mailto:admin@example.com" | wr secret put VAPID_SUBJECT
printf '%s' "$BOOTSTRAP"     | wr secret put BOOTSTRAP_INVITE

say "Deploying the Worker"
wr deploy

cat <<EOF

-------------------------------------------------------------------
Done. Two things left, both in your browser.

1. Your first invite code (this is how you create your own account):

     $BOOTSTRAP

   Keep it until everyone has joined, then remove it so nobody else can
   register with it:

     cd worker && npx wrangler secret delete BOOTSTRAP_INVITE

2. Connect the client to Cloudflare Pages:

   Workers & Pages -> Create -> Pages -> Connect to Git -> this repository

     Build command:            cd client && npm install --legacy-peer-deps && npm run build
     Build output directory:   client/dist
     Environment variable:     VITE_API_URL = the Worker URL printed above

   Then put the Worker URL into ALLOWED_ORIGINS in worker/wrangler.toml,
   replacing it with your Pages URL, commit, and push.

To make every future push deploy itself, add these in GitHub under
Settings -> Secrets and variables -> Actions:

   Secret    CLOUDFLARE_API_TOKEN    (the one you just used)
   Secret    CLOUDFLARE_ACCOUNT_ID   $CLOUDFLARE_ACCOUNT_ID
   Variable  API_URL                 the Worker URL printed above
   Variable  PAGES_PROJECT           the Pages project name you chose
-------------------------------------------------------------------
EOF
