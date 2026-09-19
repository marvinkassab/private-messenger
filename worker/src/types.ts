import type { Mailbox } from "./mailbox";
import type { Invite } from "./invite";

export interface Env {
  MAILBOX: DurableObjectNamespace<Mailbox>;
  INVITE: DurableObjectNamespace<Invite>;
  ATTACHMENTS: R2Bucket;
  ALLOWED_ORIGINS?: string;
  VAPID_PUBLIC_KEY?: string;
  VAPID_PRIVATE_KEY?: string;
  VAPID_SUBJECT?: string;
  BOOTSTRAP_INVITE?: string;
}

export interface SignedPreKey {
  keyId: number;
  publicKey: string; // b64, 33 bytes
  signature: string; // b64, 64 bytes
}

export interface OneTimePreKey {
  keyId: number;
  publicKey: string; // b64, 33 bytes
}

/* Post-quantum key material (docs/POSTQUANTUM.md). The server treats these as
   opaque bytes: it checks lengths and the XEdDSA signature binding the ML-KEM
   prekey to the classical identity key, and nothing else. It cannot and need
   not verify ML-DSA. */
export const ML_KEM_1024_PUBLIC = 1568;
export const ML_DSA_65_PUBLIC = 1952;
export const ML_DSA_65_SIGNATURE = 3309;

export interface PqSignedPreKey {
  keyId: number;
  publicKey: string; // b64, ML-KEM-1024 public key, 1568 bytes
  signature: string; // b64, XEdDSA over publicKey under the identity key, 64 bytes
  pqSignature: string; // b64, ML-DSA-65 over publicKey, 3309 bytes
}

export interface PqOneTimePreKey {
  keyId: number;
  publicKey: string; // b64, ML-KEM-1024 public key, 1568 bytes
}

export interface PreKeyBundle {
  username: string;
  deviceId: number;
  identityKey: string;
  registrationId: number;
  signedPreKey: SignedPreKey;
  preKey?: OneTimePreKey;
  /* Absent only for an account registered by a client without the
     post-quantum layer. Clients treat that as a downgrade and refuse it for
     any contact they have previously seen with these fields present. */
  pqIdentityKey?: string;
  pqSignedPreKey?: PqSignedPreKey;
  pqPreKey?: PqOneTimePreKey;
}

export interface Envelope {
  id: string;
  from?: { username: string; deviceId: number };
  type: number;
  content: string;
  timestamp: number;
  serverTimestamp: number;
}

export interface IncomingMessage {
  destinationDeviceId: number;
  type: number;
  content: string;
}

export interface PushSubscription {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

declare global {
  // Lets `import { env } from "cloudflare:test"` be typed in tests.
  namespace Cloudflare {
    interface Env {
      MAILBOX: DurableObjectNamespace<Mailbox>;
      INVITE: DurableObjectNamespace<Invite>;
      ATTACHMENTS: R2Bucket;
      ALLOWED_ORIGINS?: string;
      VAPID_PUBLIC_KEY?: string;
      VAPID_PRIVATE_KEY?: string;
      VAPID_SUBJECT?: string;
      BOOTSTRAP_INVITE?: string;
    }
  }
}
