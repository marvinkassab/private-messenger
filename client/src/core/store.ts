/* IndexedDB layer: database "pm-signal" with the object stores from PROTOCOL.md.
   Works with real IndexedDB in browsers and fake-indexeddb in Node tests.

   Records are stored as { k, v } (plaintext) or { k, e } (AES-256-GCM ciphertext
   under the app-lock key) plus a few plaintext index fields for messages
   (chat id, sent time, expiry) so ordering and the expiry sweep keep working
   while the bodies are encrypted. */

import {
  PBKDF2_ITERATIONS,
  aesGcmDecrypt,
  aesGcmEncrypt,
  b64Decode,
  b64Encode,
  concatBytes,
  deriveKeyBytes,
  fromJsonSafe,
  randomBytes,
  toJsonSafe,
  utf8Decode,
  utf8Encode,
} from "./util";

export const DB_NAME = "pm-signal";
export const DB_VERSION = 1;

export const STORE_NAMES = [
  "identity",
  "prekeys",
  "signedPreKeys",
  "sessions",
  "identities",
  "contacts",
  "chats",
  "messages",
  "attachments",
  "kv",
] as const;
export type StoreName = (typeof STORE_NAMES)[number];

/** Stores that are encrypted at rest when an app-lock passphrase is set (PROTOCOL.md). */
export const ENCRYPTED_STORES: ReadonlySet<StoreName> = new Set<StoreName>([
  "identity",
  "prekeys",
  "signedPreKeys",
  "sessions",
  "messages",
]);

export interface RecordIndex {
  c?: string;  // chat id (messages)
  t?: number;  // sent time (messages)
  x?: number;  // expiry ms epoch (messages)
}

interface Rec extends RecordIndex {
  k: string;
  v?: unknown;
  e?: ArrayBuffer;
}

interface LockConfig {
  salt: string;        // b64 16 bytes
  iterations: number;
  check: string;       // b64 iv || gcm("pm-lock-check")
}

export class LockedError extends Error {
  constructor() {
    super("store is locked");
    this.name = "LockedError";
  }
}

export interface StoreOptions {
  dbName?: string;
  indexedDB?: IDBFactory;
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error("IndexedDB request failed"));
  });
}

function txDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("IndexedDB transaction failed"));
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
  });
}

export class Store {
  readonly dbName: string;
  private readonly factory: IDBFactory;
  private db: IDBDatabase | null = null;
  private key: Uint8Array | null = null;        // app-lock key when unlocked
  private lockConfig: LockConfig | null = null;

  constructor(opts: StoreOptions = {}) {
    this.dbName = opts.dbName ?? DB_NAME;
    const f = opts.indexedDB ?? (globalThis as { indexedDB?: IDBFactory }).indexedDB;
    if (!f) throw new Error("IndexedDB is not available");
    this.factory = f;
  }

  async open(): Promise<void> {
    if (this.db) return;
    const openReq = this.factory.open(this.dbName, DB_VERSION);
    openReq.onupgradeneeded = () => {
      const db = openReq.result;
      for (const name of STORE_NAMES) {
        if (!db.objectStoreNames.contains(name)) {
          const os = db.createObjectStore(name, { keyPath: "k" });
          if (name === "messages") {
            os.createIndex("chat", ["c", "t"], { unique: false });
            os.createIndex("expires", "x", { unique: false });
          }
        }
      }
    };
    this.db = await req(openReq);
    this.db.onversionchange = () => {
      this.db?.close();
      this.db = null;
    };
    this.lockConfig = ((await this.getPlain("kv", "lock")) as LockConfig | undefined) ?? null;
  }

  close(): void {
    this.db?.close();
    this.db = null;
    this.key = null;
  }

  /** Deletes the whole database. */
  async destroy(): Promise<void> {
    this.close();
    await req(this.factory.deleteDatabase(this.dbName));
    this.lockConfig = null;
  }

  async clearAll(): Promise<void> {
    const db = this.require();
    const tx = db.transaction([...STORE_NAMES], "readwrite");
    for (const name of STORE_NAMES) tx.objectStore(name).clear();
    await txDone(tx);
    this.lockConfig = null;
    this.key = null;
  }

  /* ---------- app lock ---------- */

  hasLock(): boolean {
    return this.lockConfig !== null;
  }

  /** True when a passphrase is configured and has not been entered this session. */
  isLocked(): boolean {
    return this.lockConfig !== null && this.key === null;
  }

  async unlock(passphrase: string): Promise<boolean> {
    if (!this.lockConfig) return true;
    const key = await deriveKeyBytes(passphrase, b64Decode(this.lockConfig.salt), this.lockConfig.iterations);
    const check = b64Decode(this.lockConfig.check);
    try {
      const pt = await aesGcmDecrypt(key, check.subarray(0, 12), check.subarray(12), utf8Encode("pm-lock-check"));
      if (utf8Decode(pt) !== "pm-lock-check") return false;
    } catch {
      return false;
    }
    this.key = key;
    return true;
  }

  /** Set (re-encrypting every sensitive record) or clear (decrypting) the app lock. */
  async setLock(passphrase: string | null): Promise<void> {
    if (this.isLocked()) throw new LockedError();
    let newKey: Uint8Array | null = null;
    let newConfig: LockConfig | null = null;
    if (passphrase !== null) {
      const salt = randomBytes(16);
      newKey = await deriveKeyBytes(passphrase, salt, PBKDF2_ITERATIONS);
      const iv = randomBytes(12);
      const ct = await aesGcmEncrypt(newKey, iv, utf8Encode("pm-lock-check"), utf8Encode("pm-lock-check"));
      newConfig = { salt: b64Encode(salt), iterations: PBKDF2_ITERATIONS, check: b64Encode(concatBytes(iv, ct)) };
    }
    // Re-encode every sensitive record under the new key (or plaintext).
    for (const name of ENCRYPTED_STORES) {
      const recs = await this.rawAll(name);
      const rewritten: Rec[] = [];
      for (const r of recs) {
        const value = await this.decodeRecord(name, r);
        rewritten.push(await this.encodeRecord(name, r.k, value, r, newKey));
      }
      const tx = this.require().transaction(name, "readwrite");
      const os = tx.objectStore(name);
      os.clear();
      for (const r of rewritten) os.put(r);
      await txDone(tx);
    }
    if (newConfig) await this.putPlain("kv", "lock", newConfig);
    else await this.deletePlain("kv", "lock");
    this.lockConfig = newConfig;
    this.key = newKey;
  }

  /* ---------- generic records ---------- */

  async get<T = unknown>(store: StoreName, key: string): Promise<T | undefined> {
    const r = await this.rawGet(store, key);
    if (!r) return undefined;
    return (await this.decodeRecord(store, r)) as T;
  }

  async put(store: StoreName, key: string, value: unknown, idx?: RecordIndex): Promise<void> {
    const rec = await this.encodeRecord(store, key, value, idx ?? {}, this.key);
    const tx = this.require().transaction(store, "readwrite");
    tx.objectStore(store).put(rec);
    await txDone(tx);
  }

  async delete(store: StoreName, key: string): Promise<void> {
    const tx = this.require().transaction(store, "readwrite");
    tx.objectStore(store).delete(key);
    await txDone(tx);
  }

  async clear(store: StoreName): Promise<void> {
    const tx = this.require().transaction(store, "readwrite");
    tx.objectStore(store).clear();
    await txDone(tx);
  }

  async keys(store: StoreName): Promise<string[]> {
    const tx = this.require().transaction(store, "readonly");
    const ks = await req(tx.objectStore(store).getAllKeys());
    return ks.map(String);
  }

  async getAll<T = unknown>(store: StoreName): Promise<Array<{ key: string; value: T }>> {
    const recs = await this.rawAll(store);
    const out: Array<{ key: string; value: T }> = [];
    for (const r of recs) out.push({ key: r.k, value: (await this.decodeRecord(store, r)) as T });
    return out;
  }

  async count(store: StoreName): Promise<number> {
    const tx = this.require().transaction(store, "readonly");
    return req(tx.objectStore(store).count());
  }

  /* ---------- messages (indexed) ---------- */

  /** Messages of a chat ordered by sent time ascending; `before` (exclusive) and `limit` select the newest window. */
  async messagesByChat<T = unknown>(chatId: string, opts: { before?: number; limit?: number } = {}): Promise<T[]> {
    const before = opts.before ?? Number.MAX_SAFE_INTEGER;
    const tx = this.require().transaction("messages", "readonly");
    const range = IDBKeyRange.bound([chatId, -Infinity], [chatId, before], false, true);
    const recs = (await req(tx.objectStore("messages").index("chat").getAll(range))) as Rec[];
    const slice = opts.limit !== undefined && opts.limit >= 0 ? recs.slice(Math.max(0, recs.length - opts.limit)) : recs;
    const out: T[] = [];
    for (const r of slice) out.push((await this.decodeRecord("messages", r)) as T);
    return out;
  }

  async expiredMessages<T = unknown>(now: number): Promise<Array<{ key: string; value: T }>> {
    const tx = this.require().transaction("messages", "readonly");
    const recs = (await req(tx.objectStore("messages").index("expires").getAll(IDBKeyRange.upperBound(now)))) as Rec[];
    const out: Array<{ key: string; value: T }> = [];
    for (const r of recs) out.push({ key: r.k, value: (await this.decodeRecord("messages", r)) as T });
    return out;
  }

  /* ---------- internals ---------- */

  private require(): IDBDatabase {
    if (!this.db) throw new Error("store is not open");
    return this.db;
  }

  private async rawGet(store: StoreName, key: string): Promise<Rec | undefined> {
    const tx = this.require().transaction(store, "readonly");
    return (await req(tx.objectStore(store).get(key))) as Rec | undefined;
  }

  private async rawAll(store: StoreName): Promise<Rec[]> {
    const tx = this.require().transaction(store, "readonly");
    return (await req(tx.objectStore(store).getAll())) as Rec[];
  }

  private async getPlain(store: StoreName, key: string): Promise<unknown> {
    const r = await this.rawGet(store, key);
    return r?.v;
  }

  private async putPlain(store: StoreName, key: string, value: unknown): Promise<void> {
    const tx = this.require().transaction(store, "readwrite");
    tx.objectStore(store).put({ k: key, v: value } satisfies Rec);
    await txDone(tx);
  }

  private async deletePlain(store: StoreName, key: string): Promise<void> {
    const tx = this.require().transaction(store, "readwrite");
    tx.objectStore(store).delete(key);
    await txDone(tx);
  }

  private aad(store: StoreName, key: string): Uint8Array {
    return utf8Encode(`${store}/${key}`);
  }

  private async encodeRecord(store: StoreName, key: string, value: unknown, idx: RecordIndex, key32: Uint8Array | null): Promise<Rec> {
    const rec: Rec = { k: key };
    if (idx.c !== undefined) rec.c = idx.c;
    if (idx.t !== undefined) rec.t = idx.t;
    if (idx.x !== undefined) rec.x = idx.x;
    if (ENCRYPTED_STORES.has(store)) {
      if (this.lockConfig && !key32 && this.key === null) throw new LockedError();
      const k = key32;
      if (k) {
        const iv = randomBytes(12);
        const pt = utf8Encode(JSON.stringify(toJsonSafe(value)));
        const ct = await aesGcmEncrypt(k, iv, pt, this.aad(store, key));
        rec.e = concatBytes(iv, ct).buffer as ArrayBuffer;
        return rec;
      }
    }
    rec.v = value;
    return rec;
  }

  private async decodeRecord(store: StoreName, r: Rec): Promise<unknown> {
    if (r.e !== undefined) {
      if (!this.key) throw new LockedError();
      const bytes = new Uint8Array(r.e);
      const pt = await aesGcmDecrypt(this.key, bytes.subarray(0, 12), bytes.subarray(12), this.aad(store, r.k));
      return fromJsonSafe(JSON.parse(utf8Decode(pt)));
    }
    return r.v;
  }
}
