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

export interface PreKeyBundle {
  username: string;
  deviceId: number;
  identityKey: string;
  registrationId: number;
  signedPreKey: SignedPreKey;
  preKey?: OneTimePreKey;
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
