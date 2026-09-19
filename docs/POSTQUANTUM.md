# Beyond Signal: the post-quantum hybrid layer

## What "stronger than Signal" can honestly mean

Signal's Double Ratchet with X25519 and AES-256 is not breakable by any
classical computer, now or later. There is no bigger number to pick that makes
today's confidentiality meaningfully better. So "stronger" cannot mean a
longer key; it has to mean **a threat Signal's classical layer does not cover**.
There is exactly one such threat that matters today, plus two smaller ones:

1. **Harvest now, decrypt later.** An adversary records ciphertext today and
   decrypts it when a cryptographically relevant quantum computer exists.
   Every classical key agreement, X25519 included, falls to Shor's algorithm.
   This is the real gap, and it is the one this layer closes.
2. **Authentication forgery** by the same future machine: a quantum adversary
   could forge Curve25519 signatures and impersonate a contact.
3. **Single-primitive risk.** If any one primitive turns out to be flawed,
   everything protected by it alone is lost.

Signal itself closed (1) at session setup with **PQXDH** (X25519 + ML-KEM-768)
in 2023, and added a post-quantum ratchet later. The TypeScript protocol
library this app uses is a port of Signal's *older* JavaScript implementation:
classical X3DH only, with no post-quantum component at all. So this layer

- brings us past the library we build on,
- uses **ML-KEM-1024** (NIST security category 5) where Signal's PQXDH uses
  ML-KEM-768 (category 3),
- re-keys the post-quantum secret **continuously** rather than only at
  session setup, and
- adds **ML-DSA-65** identity signatures so authentication is post-quantum
  too, which PQXDH does not address.

## The one rule

**The hybrid layer is additive and never replaces Signal.** Plaintext is
always sealed by the Double Ratchet first; the post-quantum layer wraps that
ciphertext. An attacker must break **both** independently.

- If this layer has a bug, the Signal layer still protects the message.
- If a quantum computer breaks X25519, this layer still protects it.
- Neither layer can be weaker than the pair.

This is the standard hybrid discipline: the combined construction is at least
as strong as the strongest component, never as weak as the weakest.

## Primitives

| Purpose | Primitive | Parameters | Source |
| --- | --- | --- | --- |
| PQ key encapsulation | ML-KEM (FIPS 203) | ML-KEM-1024, category 5 | `@noble/post-quantum` |
| PQ signatures | ML-DSA (FIPS 204) | ML-DSA-65, category 3 | `@noble/post-quantum` |
| Classical agreement | X25519 | — | Signal library / `@noble/curves` |
| Outer AEAD | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce | `@noble/ciphers` |
| KDF | HKDF-SHA-512 | — | `@noble/hashes` |

Measured in this project's own sandbox: ML-KEM-1024 encapsulate 1.4 ms,
decapsulate 1.7 ms; public key 1568 B, ciphertext 1568 B. ML-DSA-65: public
key 1952 B, signature 3309 B.

Measured cost of the layer as specified here, from its reference
implementation and test suite:

| | overhead | time |
| --- | --- | --- |
| Session opener (2 KEM ciphertexts + ML-DSA signature) | 6495 B | ~5 ms |
| Re-key message (1 KEM ciphertext + new public key + signature) | ~6.4 kB | ~5 ms |
| Every other message | **50 B** | **0.086 ms** |

So the post-quantum layer is effectively free in steady state; its cost lands
on session setup and on roughly one message in a hundred.

## Key material per account

Added to the existing Curve25519 identity key and prekeys:

- **`pqIdentityKey`** — an ML-DSA-65 keypair. Its public half is published
  with the identity key and is covered by the safety number.
- **`pqSignedPreKey`** — an ML-KEM-1024 keypair, its public key signed by
  *both* the Curve25519 identity key and the ML-DSA identity key. Rotated
  every 7 days; the previous one is kept 14 days.
- **`pqOneTimePreKeys`** — a stock of 100 ML-KEM-1024 public keys, consumed
  one per new session, exactly like classical one-time prekeys.

The prekey bundle (`GET /v1/keys/:username`) gains:

```json
{
  "pqIdentityKey":  "<b64 ML-DSA-65 public key>",
  "pqSignedPreKey": { "keyId": 1, "publicKey": "<b64 ML-KEM-1024>",
                      "signature": "<b64 XEdDSA>", "pqSignature": "<b64 ML-DSA>" },
  "pqPreKey":       { "keyId": 17, "publicKey": "<b64 ML-KEM-1024>" }
}
```

The server stores and serves these as opaque bytes. It validates lengths only.

## Session establishment (hybrid X3DH + KEM)

On top of the library's ordinary X3DH:

1. Fetch the bundle. Verify `pqSignedPreKey` under **both** signatures. A
   failure of either aborts the session; a missing post-quantum half is
   accepted only when the contact's client predates this layer, and the chat
   is then marked "classical only" in the UI.
2. Run classical X3DH as before, producing `SK_classical`.
3. Encapsulate to the recipient's ML-KEM signed prekey, and separately to the
   one-time ML-KEM prekey when one is present, producing ciphertexts
   `ct_signed`, `ct_onetime` and secrets `ss_signed`, `ss_onetime`.
4. Derive the hybrid root:

```
PQ_root = HKDF-SHA512(
    ikm  = SK_classical || ss_signed || ss_onetime,
    salt = "pm-pq-hybrid-v1",
    info = initiatorIdentity || responderIdentity || pqIdentityKeys,
    len  = 64 )
    -> pqChainKey (32 B) || pqHeaderKey (32 B)
```

`SK_classical` stays inside the Signal library and continues to drive the
Double Ratchet untouched. `PQ_root` drives only the outer layer.

5. The initiator's first message carries `ct_signed` and `ct_onetime` in the
   outer header so the responder can decapsulate.

Because `SK_classical` is an input to `PQ_root`, the outer layer is bound to
the classical session: an attacker who breaks only the KEM still cannot
derive the outer key.

## The outer layer, per message

```
pqMessageKey, nextChainKey = HKDF-SHA512(pqChainKey, info = "pm-pq-msg" || counter)
inner   = Signal ciphertext (the existing type 1 / 3 body)
nonce   = 24 random bytes
outer   = XChaCha20-Poly1305(pqMessageKey, nonce, inner,
                             aad = header bytes)
wire    = version(1) || flags(1) || counter(4) || nonce(24) ||
          [ct_signed(1568) || ct_onetime(1568)]?  ||  [rekey_ct(1568)]?  ||
          outer
```

The chain key ratchets forward on every message (`pqChainKey := nextChainKey`)
and the used message key is destroyed, so the outer layer has its own forward
secrecy independent of Signal's.

### Out-of-order delivery

Networks reorder. When a message arrives with a counter ahead of the expected
one, the receiver ratchets forward to it and **stashes the message keys it
skipped**, so the laggards still open when they arrive; at most 1000 keys are
held, and a jump beyond that is rejected. A key is deleted the moment it is
used, which also makes replay impossible: a second copy of a message finds
its key gone. This mirrors Signal's own skipped-message-key store.

## Continuous post-quantum ratchet

A KEM ratchet that only runs at session setup gives post-quantum *forward*
secrecy but no post-quantum *post-compromise* security: an adversary who
steals the chain key reads everything after it. So the layer re-keys:

- Every **100 messages**, or every **24 hours**, whichever comes first, a
  sender generates a fresh ML-KEM-1024 keypair, encapsulates to the peer's
  current public key, and includes `rekey_ct` plus its new public key in the
  header.
- The receiver decapsulates and both sides fold the new secret in:

```
pqChainKey = HKDF-SHA512(pqChainKey || ss_rekey, salt = "pm-pq-rekey-v1", len = 32)
```

After a re-key, an adversary holding the old chain key is locked out again.
This is the post-quantum analogue of the Double Ratchet's DH step, and it is
the feature that makes this layer genuinely continuous rather than one-shot.

Re-keys are piggybacked on normal messages: no extra round trip, and the
~1.6 KB cost lands on roughly one message in a hundred.

## Authentication

**ML-DSA-65 signs exactly the messages that introduce new key material:** the
session opener and every re-key, over `(header || sha512(outer))`.

Ordinary messages are *not* signed, and do not need to be. Their outer AEAD
key descends from the ML-KEM shared secret, so forging one requires breaking
ML-KEM itself, not a classical signature. Signing every message would add
3309 B to each one to protect against an adversary who has already broken
ML-KEM, in which case the signature is the least of the problem.

An earlier draft of this document signed one message in ten and claimed the
rest were "covered by the outer AEAD tag chained into the next signed
header". That was wrong: nothing chained those tags, so nine messages in ten
carried no post-quantum authentication at all. Signing the key-introducing
messages, and relying on the PQ-derived AEAD for the rest, is both correct
and cheaper.

## Safety numbers

The fingerprint covers **both** identity keys:

```
fingerprintInput = curve25519IdentityKey || mlDsaIdentityKey
```

fed to the existing Signal `FingerprintGenerator` (5200 iterations). The
displayed number is still 60 digits, so the user experience is unchanged, but
a quantum adversary cannot produce a colliding identity. Numbers generated
before this layer will not match afterwards; that is a deliberate one-time
break, surfaced in the UI as "safety number updated for post-quantum
protection" rather than as an attack warning.

## Group messages

Groups fan out pairwise, so every recipient's copy is protected by that
pair's own hybrid session. No group-specific post-quantum work is needed.
The ~1.6 KB re-key overhead multiplies by member count on re-key messages,
which is the main reason the re-key interval is 100 messages rather than 10.

## Attachments

The per-file AES-256-GCM key is already symmetric and quantum-resistant at
256 bits. What needs protecting is its *delivery*, which happens inside a
message and is therefore already covered by the hybrid layer. No change.

## Backups and storage at rest

Backup and app-lock encryption move from PBKDF2-SHA256 to **Argon2id**
(memory-hard: 64 MiB, 3 passes, parallelism 1), which resists the GPU and
ASIC cracking that PBKDF2 does not. Symmetric encryption stays
XChaCha20-Poly1305 with a 256-bit key.

## Negotiation and downgrade protection

The bundle says what a contact supports. Once a session has been established
with the hybrid layer, the client **records that fact** and refuses to fall
back to classical-only for that contact, even if a later bundle omits the
post-quantum keys. A server that strips post-quantum material to force a
downgrade therefore breaks the session visibly instead of silently weakening
it. Clients that never had the layer are shown as "classical only" with an
explicit badge.

## What this does not fix

- **Metadata.** The server still learns that a mailbox received an envelope
  and when. Sealed sender hides who sent it; it does not hide timing or size.
  Real metadata resistance needs cover traffic and batching, which costs
  battery and latency, and is not part of this layer.
- **Endpoint compromise.** Malware on the device reads plaintext regardless
  of any protocol. This is the limit that no encryption layer can pass.
- **Implementation risk.** Every layer added is code that can be wrong. That
  is exactly why the hybrid rule above is absolute: this layer can only add
  protection, never subtract it.

## Honest summary

| Property | Signal today | This app |
| --- | --- | --- |
| Classical confidentiality | Double Ratchet, X25519, AES-256 | identical, unchanged |
| PQ key agreement | PQXDH, ML-KEM-768, at setup | ML-KEM-1024, at setup |
| PQ ratchet | sparse PQ ratchet | re-key every 100 messages / 24 h |
| PQ authentication | none (classical signatures) | ML-DSA-65 |
| Backup KDF | Argon2id | Argon2id |
| Audited | yes, extensively | **no** |

The last row is the one that matters most. Signal's protocol is deployed to
billions of devices and has been attacked by professionals for a decade. This
app has stronger *parameters* and one genuinely additional property
(post-quantum authentication), and it has been reviewed by nobody. Stronger
on paper is not the same as safer in practice. For anything where being wrong
would endanger someone, use Signal.
