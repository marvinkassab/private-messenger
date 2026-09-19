/* Shared types between the core (crypto + transport) and the UI.
   The UI depends only on the `Messenger` interface. The core implements it.
   Keep this file free of imports so both sides can use it in tests. */

export type Username = string;
export type ChatId = string;            // "u:<username>" for direct chats, "g:<groupId>" for groups
export type ConnectionState = "offline" | "connecting" | "online";

export interface Account {
  username: Username;
  deviceId: number;
  identityKeyB64: string;               // our public identity key, base64 (33 bytes)
  registrationId: number;
  displayName: string;
  createdAt: number;
}

export interface Contact {
  username: Username;
  displayName?: string;                 // as they told us in a profile message
  identityKeyB64: string;
  verified: boolean;                    // safety number marked verified by the user
  identityChanged?: boolean;            // key changed since we last trusted it; blocks sending until accepted
  addedAt: number;
  hasDeliveryToken: boolean;            // we can send to them sealed
  pqIdentityKeyB64?: string;            // their ML-DSA-65 identity public key, once known (docs/POSTQUANTUM.md)
  classicalOnly?: boolean;              // confirmed: this contact has no post-quantum keys (pre-PQ client)
}

export interface GroupState {
  id: string;
  name: string;
  creator: Username;
  admins: Username[];
  members: Username[];
  revision: number;
  leftOrRemoved?: boolean;              // we are no longer a member; chat is read-only
}

export interface Chat {
  id: ChatId;
  kind: "direct" | "group";
  title: string;
  members: Username[];                  // for direct chats: [peer]
  group?: GroupState;
  lastMessage?: { body: string; sentAt: number; sender: Username; kind: Message["kind"] };
  unread: number;
  disappearSeconds: number;             // 0 = off
  updatedAt: number;
  typing?: Username[];                  // peers currently typing (transient, not persisted)
}

export interface AttachmentMeta {
  id: string;
  mime: string;
  size: number;
  name?: string;
  width?: number;
  height?: number;
  caption?: string;
}

export interface Message {
  id: string;
  chatId: ChatId;
  sender: Username;
  mine: boolean;
  sentAt: number;                       // sender clock
  receivedAt: number;                   // our clock
  kind: "text" | "attachment" | "system";
  body: string;                         // text, caption, or system line
  attachment?: AttachmentMeta;          // present when kind = attachment; bytes via downloadAttachment()
  replyTo?: string;
  reactions: Record<string, Username[]>;   // emoji -> who
  status: "pending" | "sent" | "delivered" | "read" | "failed";
  deleted?: boolean;
  expiresAt?: number;                   // ms epoch when this message self-destructs
}

export interface SafetyNumber {
  digits: string;                       // 60 digits
  verified: boolean;
  identityChanged: boolean;
}

export type MessengerEvent =
  | { type: "connection"; state: ConnectionState }
  | { type: "message"; message: Message }             // new or updated message (status, reactions, delete)
  | { type: "chat"; chat: Chat }                      // new or updated chat
  | { type: "contact"; contact: Contact }             // new or updated contact
  | { type: "typing"; chatId: ChatId; users: Username[] }
  | { type: "error"; message: string };

export interface Messenger {
  /* lifecycle */
  init(): Promise<{ account: Account | null; locked: boolean }>;
  register(username: Username, inviteCode: string, displayName: string): Promise<Account>;
  account(): Account | null;
  connect(): Promise<void>;
  disconnect(): void;
  connectionState(): ConnectionState;
  on(handler: (e: MessengerEvent) => void): () => void;   // returns unsubscribe

  /* contacts */
  addContact(username: Username): Promise<Contact>;   // fetches their bundle, opens a session, sends a profile message; creates the direct chat
  listContacts(): Promise<Contact[]>;
  getContact(username: Username): Promise<Contact | undefined>;
  safetyNumber(username: Username): Promise<SafetyNumber>;
  setVerified(username: Username, verified: boolean): Promise<void>;
  acceptIdentityChange(username: Username): Promise<void>;
  setDisplayName(name: string): Promise<void>;        // updates account and sends a profile message to all contacts

  /* chats and messages */
  listChats(): Promise<Chat[]>;
  getChat(id: ChatId): Promise<Chat | undefined>;
  getMessages(chatId: ChatId, opts?: { before?: number; limit?: number }): Promise<Message[]>;   // newest last
  sendText(chatId: ChatId, body: string, opts?: { replyTo?: string }): Promise<Message>;
  sendAttachment(chatId: ChatId, file: Blob, opts?: { name?: string; caption?: string; original?: boolean }): Promise<Message>;
  downloadAttachment(messageId: string): Promise<Blob>;   // cached after first download
  retry(messageId: string): Promise<Message>;
  react(messageId: string, emoji: string): Promise<void>;   // same emoji again removes
  deleteForEveryone(messageId: string): Promise<void>;
  deleteLocally(messageId: string): Promise<void>;
  markRead(chatId: ChatId): Promise<void>;
  setTyping(chatId: ChatId, typing: boolean): void;
  setDisappearing(chatId: ChatId, seconds: number): Promise<void>;

  /* groups */
  createGroup(name: string, members: Username[]): Promise<Chat>;
  updateGroup(groupId: string, patch: { name?: string; add?: Username[]; remove?: Username[] }): Promise<Chat>;
  leaveGroup(groupId: string): Promise<void>;

  /* invites, push, lock, backup */
  mintInvite(): Promise<{ code: string; expiresAt: number; link: string }>;
  enablePush(): Promise<boolean>;
  disablePush(): Promise<void>;
  pushEnabled(): boolean;
  setLock(passphrase: string | null): Promise<void>;
  unlock(passphrase: string): Promise<boolean>;
  exportBackup(passphrase: string): Promise<Blob>;
  importBackup(file: Blob, passphrase: string): Promise<Account>;
  wipe(): Promise<void>;
}

/* Wire types shared with the server (see docs/API.md) */
export interface PreKeyBundleWire {
  username: Username;
  deviceId: number;
  identityKey: string;
  registrationId: number;
  signedPreKey: { keyId: number; publicKey: string; signature: string };
  preKey?: { keyId: number; publicKey: string };
  /* Post-quantum half (docs/POSTQUANTUM.md); absent when the account predates the layer. */
  pqIdentityKey?: string;
  pqSignedPreKey?: { keyId: number; publicKey: string; signature: string; pqSignature: string };
  pqPreKey?: { keyId: number; publicKey: string };
}
/* Carries no time of any kind: the server stores none, and when a message was
   written lives inside the ciphertext. The id is a sortable sequence. */
export interface EnvelopeWire {
  id: string;
  from?: { username: Username; deviceId: number };
  type: number;                         // 1 whisper, 3 prekey, 4 sealed
  content: string;
}
