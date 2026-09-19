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

say "Checking the API token"
# Failing here with a clear name beats failing three steps later with a 403
# whose message does not say which permission is missing.
set +e
TOKEN_CHECK=$(curl -sS --max-time 20 -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/user/tokens/verify" 2>&1)
CURL_STATUS=$?
set -e
if [[ $CURL_STATUS -ne 0 ]]; then
  # Distinguish "cannot reach Cloudflare" from "Cloudflare said no": blaming
  # the token for a proxy or offline machine sends you looking in the wrong place.
  echo "Could not reach api.cloudflare.com, so the token was never checked." >&2
  echo "Check your network or proxy, then run this again." >&2
  echo "$TOKEN_CHECK" >&2
  exit 1
fi
if ! echo "$TOKEN_CHECK" | grep -q '"success":true'; then
  echo "Cloudflare rejected the API token." >&2
  echo "$TOKEN_CHECK" >&2
  exit 1
fi
echo "token accepted"

R2_OK=yes
if ! curl -sS --max-time 20 -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/r2/buckets" \
  | grep -q '"success":true'; then
  R2_OK=no
  cat >&2 <<'MISSING'

This token cannot see R2, so the bucket for encrypted attachments will be
skipped. Everything else still works; without the bucket, messages and
groups are fine but photos and files will fail to send.

Two ways to fix it, either is fine:

  a) Add this row to the token and run this again. On the token screen each
     permission has three dropdowns and the first defaults to "Zone" --
     change it to "Account", then search for R2:

       Account -> Workers R2 Storage -> Edit

  b) Or make the bucket yourself in the dashboard, which needs no token at
     all: R2 -> Create bucket -> name it exactly

       private-messenger-attachments

     then set a 30-day lifecycle rule on it under the bucket's Settings.

Continuing without it.
MISSING
fi
[[ "$R2_OK" == yes ]] && echo "R2 permission present"

say "Installing dependencies"
(cd worker && npm install --legacy-peer-deps --workspaces=false >/dev/null)
(cd client && npm install --legacy-peer-deps --workspaces=false >/dev/null)

say "Creating the R2 bucket for encrypted attachments"
if [[ "$R2_OK" != yes ]]; then
  echo "skipped: the token has no R2 permission (see the note above)"
elif wr r2 bucket list 2>/dev/null | grep -q "$BUCKET"; then
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
