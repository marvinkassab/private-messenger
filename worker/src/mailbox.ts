// One Durable Object per username (idFromName(username)), SQLite-backed.
//
// Holds the account's keys, its envelope queue, push subscription, rate
// counters and any live WebSockets (hibernation API). Every method here is
// invoked over RPC from the Worker; only the WebSocket upgrade goes through
// `fetch`.

import { DurableObject } from "cloudflare:workers";
import { deliveryTokensMatch } from "./auth";
import { getPushTransport, PUSH_DEBOUNCE_MS, sendWebPush, vapidConfigFromEnv } from "./push";
import type { Env, Envelope, IncomingMessage, OneTimePreKey, PqOneTimePreKey, PqSignedPreKey, PreKeyBundle, PushSubscription, SignedPreKey } from "./types";
import { b64Decode, createIdGenerator } from "./util";

export const MAX_ONE_TIME_PREKEYS = 200;
export const MAX_QUEUE = 1000;
export const ENVELOPE_TTL_DAYS = 30;
export const DRAIN_LIMIT = 100;

export interface RegisterInput {
  identityKey: string; // b64 33 bytes (already validated by the Worker)
  registrationId: number;
  deliveryToken: string; // b64 32 bytes
  signedPreKey: SignedPreKey;
  oneTimePreKeys: OneTimePreKey[];
  pqIdentityKey?: string;
  pqSignedPreKey?: PqSignedPreKey;
  pqOneTimePreKeys?: PqOneTimePreKey[];
}

export type SendResult = { status: "ok" } | { status: "unknown" } | { status: "forbidden" } | { status: "rate_limited" };

type EnvelopeRow = {
  id: string;
  from_username: string | null;
  from_device: number | null;
  type: number;
  content: string;
  seq: number;
  day: number;
};

export class Mailbox extends DurableObject<Env> {
  private sql: SqlStorage;
  private newId = createIdGenerator();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS prekeys (
        key_id INTEGER PRIMARY KEY,
        public_key TEXT NOT NULL,
        seq INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS pq_prekeys (
        key_id INTEGER PRIMARY KEY,
        public_key TEXT NOT NULL,
        seq INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS envelopes (
        id TEXT PRIMARY KEY,
        from_username TEXT,
        from_device INTEGER,
        type INTEGER NOT NULL,
        content TEXT NOT NULL,
        seq INTEGER NOT NULL,
        day INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS envelopes_seq ON envelopes (seq);
      CREATE INDEX IF NOT EXISTS envelopes_day ON envelopes (day);
      CREATE TABLE IF NOT EXISTS counters (
        kind TEXT NOT NULL,
        win INTEGER NOT NULL,
        n INTEGER NOT NULL,
        PRIMARY KEY (kind, win)
      );
    `);
    // Answer pings without waking a hibernated object.
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair('{"type":"ping"}', '{"type":"pong"}'));
  }

  // ---- meta helpers ----

  private getMeta<T>(k: string): T | null {
    const row = this.sql.exec<{ v: string }>("SELECT v FROM meta WHERE k = ?", k).toArray()[0];
    return row ? (JSON.parse(row.v) as T) : null;
  }

  private setMeta(k: string, v: unknown): void {
    this.sql.exec("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", k, JSON.stringify(v));
  }

  private delMeta(k: string): void {
    this.sql.exec("DELETE FROM meta WHERE k = ?", k);
  }

  // ---- account ----

  async exists(): Promise<boolean> {
    return this.getMeta<string>("identityKey") !== null;
  }

  /** The stored identity key (b64, 33 bytes) or null for an unknown user. */
  async getIdentityKey(): Promise<string | null> {
    return this.getMeta<string>("identityKey");
  }

  /** Creates the account. Returns false when the username is already taken. */
  async register(input: RegisterInput): Promise<boolean> {
    if (await this.exists()) return false;
    this.ctx.storage.transactionSync(() => {
      this.setMeta("identityKey", input.identityKey);
      this.setMeta("registrationId", input.registrationId);
      this.setMeta("deliveryToken", input.deliveryToken);
      this.setMeta("signedPreKey", input.signedPreKey);
      this.insertPreKeys(input.oneTimePreKeys);
      if (input.pqIdentityKey) this.setMeta("pqIdentityKey", input.pqIdentityKey);
      if (input.pqSignedPreKey) this.setMeta("pqSignedPreKey", input.pqSignedPreKey);
      if (input.pqOneTimePreKeys?.length) this.insertPqPreKeys(input.pqOneTimePreKeys);
    });
    return true;
  }

  // ---- keys ----

  private insertPreKeys(keys: OneTimePreKey[]): void {
    for (const k of keys) {
      this.sql.exec(
        "INSERT INTO prekeys (key_id, public_key, seq) VALUES (?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM prekeys)) " +
          "ON CONFLICT(key_id) DO UPDATE SET public_key = excluded.public_key",
        k.keyId,
        k.publicKey,
      );
    }
  }

  private insertPqPreKeys(keys: PqOneTimePreKey[]): void {
    for (const k of keys) {
      this.sql.exec(
        "INSERT INTO pq_prekeys (key_id, public_key, seq) VALUES (?, ?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM pq_prekeys)) " +
          "ON CONFLICT(key_id) DO UPDATE SET public_key = excluded.public_key",
        k.keyId,
        k.publicKey,
      );
    }
  }

  async pqPreKeyCount(): Promise<number> {
    return Number(this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM pq_prekeys").one().n);
  }

  async preKeyCount(): Promise<number> {
    return Number(this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM prekeys").one().n);
  }

  /**
   * Replaces the signed prekey (keeping the previous one) and/or appends
   * one-time prekeys. The Worker has already checked the signature.
   */
  async putKeys(
    signedPreKey: SignedPreKey | null,
    oneTimePreKeys: OneTimePreKey[],
    pq: { signedPreKey?: PqSignedPreKey | null; oneTimePreKeys?: PqOneTimePreKey[] } = {},
  ): Promise<{ count: number; pqCount: number } | { error: "too_many" }> {
    return this.ctx.storage.transactionSync(() => {
      if (oneTimePreKeys.length > 0) {
        const existing = this.sql
          .exec<{ key_id: number }>("SELECT key_id FROM prekeys")
          .toArray()
          .map((r) => r.key_id);
        const ids = new Set(existing);
        for (const k of oneTimePreKeys) ids.add(k.keyId);
        if (ids.size > MAX_ONE_TIME_PREKEYS) return { error: "too_many" as const };
        this.insertPreKeys(oneTimePreKeys);
      }
      if (signedPreKey) {
        const current = this.getMeta<SignedPreKey>("signedPreKey");
        if (current && current.keyId !== signedPreKey.keyId) this.setMeta("previousSignedPreKey", current);
        this.setMeta("signedPreKey", signedPreKey);
      }
      if (pq.oneTimePreKeys?.length) {
        const ids = new Set(
          this.sql.exec<{ key_id: number }>("SELECT key_id FROM pq_prekeys").toArray().map((r) => r.key_id),
        );
        for (const k of pq.oneTimePreKeys) ids.add(k.keyId);
        if (ids.size > MAX_ONE_TIME_PREKEYS) return { error: "too_many" as const };
        this.insertPqPreKeys(pq.oneTimePreKeys);
      }
      if (pq.signedPreKey) {
        const current = this.getMeta<PqSignedPreKey>("pqSignedPreKey");
        if (current && current.keyId !== pq.signedPreKey.keyId) this.setMeta("previousPqSignedPreKey", current);
        this.setMeta("pqSignedPreKey", pq.signedPreKey);
      }
      return {
        count: Number(this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM prekeys").one().n),
        pqCount: Number(this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM pq_prekeys").one().n),
      };
    });
  }

  /** Bundle for session setup; consumes one one-time prekey when available. */
  async fetchBundle(username: string): Promise<PreKeyBundle | null> {
    const identityKey = this.getMeta<string>("identityKey");
    const signedPreKey = this.getMeta<SignedPreKey>("signedPreKey");
    const registrationId = this.getMeta<number>("registrationId");
    if (!identityKey || !signedPreKey || registrationId === null) return null;
    const bundle: PreKeyBundle = { username, deviceId: 1, identityKey, registrationId, signedPreKey };
    const row = this.sql
      .exec<{ key_id: number; public_key: string }>("SELECT key_id, public_key FROM prekeys ORDER BY seq ASC LIMIT 1")
      .toArray()[0];
    if (row) {
      this.sql.exec("DELETE FROM prekeys WHERE key_id = ?", row.key_id);
      bundle.preKey = { keyId: row.key_id, publicKey: row.public_key };
    }
    const pqIdentityKey = this.getMeta<string>("pqIdentityKey");
    const pqSignedPreKey = this.getMeta<PqSignedPreKey>("pqSignedPreKey");
    if (pqIdentityKey && pqSignedPreKey) {
      bundle.pqIdentityKey = pqIdentityKey;
      bundle.pqSignedPreKey = pqSignedPreKey;
      const pqRow = this.sql
        .exec<{ key_id: number; public_key: string }>("SELECT key_id, public_key FROM pq_prekeys ORDER BY seq ASC LIMIT 1")
        .toArray()[0];
      if (pqRow) {
        this.sql.exec("DELETE FROM pq_prekeys WHERE key_id = ?", pqRow.key_id);
        bundle.pqPreKey = { keyId: pqRow.key_id, publicKey: pqRow.public_key };
      }
    }
    return bundle;
  }

  // ---- profile ----

  async setDeliveryToken(tokenB64: string): Promise<void> {
    this.setMeta("deliveryToken", tokenB64);
  }

  // ---- rate limiting ----

  /**
   * Increments the counter `kind` for the current window and returns whether
   * the call is within `limit`.
   */
  async bump(kind: string, limit: number, windowSeconds: number): Promise<boolean> {
    const win = Math.floor(Date.now() / 1000 / windowSeconds);
    const n = Number(
      this.sql
        .exec<{ n: number }>(
          "INSERT INTO counters (kind, win, n) VALUES (?, ?, 1) ON CONFLICT(kind, win) DO UPDATE SET n = n + 1 RETURNING n",
          kind,
          win,
        )
        .one().n,
    );
    if (n === 1) this.sql.exec("DELETE FROM counters WHERE kind = ? AND win < ?", kind, win);
    return n <= limit;
  }

  // ---- messages ----

  /**
   * Identified send: the Worker has already authenticated `from` and applied
   * the sender's rate limit.
   */
  async enqueue(from: { username: string; deviceId: number } | null, messages: IncomingMessage[]): Promise<SendResult> {
    if (!(await this.exists())) return { status: "unknown" };
    this.store(from, messages);
    return { status: "ok" };
  }

  /** Unidentified send: checks the delivery token and the recipient-side rate limit. */
  async unidentifiedSend(token: Uint8Array, messages: IncomingMessage[]): Promise<SendResult> {
    if (!(await this.exists())) return { status: "unknown" };
    const storedB64 = this.getMeta<string>("deliveryToken");
    const stored = storedB64 ? b64Decode(storedB64) : null;
    if (!deliveryTokensMatch(token, stored)) return { status: "forbidden" };
    if (!(await this.bump("recv", 300, 60))) return { status: "rate_limited" };
    this.store(null, messages);
    return { status: "ok" };
  }

  /** Day number, the only time value kept, and only so stale rows can be swept. */
  private today(): number {
    return Math.floor(Date.now() / 86400000);
  }

  private nextSeq(): number {
    const seq = (this.getMeta<number>("seq") ?? 0) + 1;
    this.setMeta("seq", seq);
    return seq;
  }

  private store(from: { username: string; deviceId: number } | null, messages: IncomingMessage[]): void {
    const day = this.today();
    const envelopes: Envelope[] = [];
    this.ctx.storage.transactionSync(() => {
      this.prune();
      for (const m of messages) {
        const seq = this.nextSeq();
        const env: Envelope = { id: this.newId(seq), type: m.type, content: m.content };
        if (from) env.from = { username: from.username, deviceId: from.deviceId };
        this.sql.exec(
          "INSERT INTO envelopes (id, from_username, from_device, type, content, seq, day) VALUES (?, ?, ?, ?, ?, ?, ?)",
          env.id,
          from ? from.username : null,
          from ? from.deviceId : null,
          env.type,
          env.content,
          seq,
          day,
        );
        envelopes.push(env);
      }
      // Cap the queue at MAX_QUEUE, dropping the oldest.
      const n = Number(this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes").one().n);
      if (n > MAX_QUEUE) {
        this.sql.exec("DELETE FROM envelopes WHERE id IN (SELECT id FROM envelopes ORDER BY id ASC LIMIT ?)", n - MAX_QUEUE);
      }
    });
    const delivered = this.broadcast(envelopes);
    if (!delivered) this.maybePush(Date.now());
  }

  /** Deletes envelopes past their 30-day lifetime. */
  private prune(): void {
    this.sql.exec("DELETE FROM envelopes WHERE day < ?", this.today() - ENVELOPE_TTL_DAYS);
  }

  private rowToEnvelope(r: EnvelopeRow): Envelope {
    const env: Envelope = { id: r.id, type: r.type, content: r.content };
    if (r.from_username !== null) env.from = { username: r.from_username, deviceId: r.from_device ?? 1 };
    return env;
  }

  async drain(limit = DRAIN_LIMIT): Promise<{ envelopes: Envelope[]; more: boolean }> {
    this.prune();
    const rows = this.sql.exec<EnvelopeRow>("SELECT * FROM envelopes ORDER BY id ASC LIMIT ?", limit + 1).toArray();
    const more = rows.length > limit;
    return { envelopes: rows.slice(0, limit).map((r) => this.rowToEnvelope(r)), more };
  }

  /** Deletes one envelope. Idempotent. Emits queue-empty to live sockets when the queue drains. */
  async ack(id: string): Promise<void> {
    const before = this.queueSize();
    this.sql.exec("DELETE FROM envelopes WHERE id = ?", id);
    if (before > 0 && this.queueSize() === 0) this.sendAll({ type: "queue-empty" });
  }

  private queueSize(): number {
    return Number(this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM envelopes").one().n);
  }

  // ---- push ----

  async setPushSubscription(sub: PushSubscription): Promise<void> {
    this.setMeta("push", sub);
  }

  async deletePushSubscription(): Promise<void> {
    this.delMeta("push");
  }

  private maybePush(now: number): void {
    const sub = this.getMeta<PushSubscription>("push");
    if (!sub) return;
    const cfg = vapidConfigFromEnv(this.env);
    if (!cfg) return;
    const last = this.getMeta<number>("lastPushAt") ?? 0;
    if (now - last < PUSH_DEBOUNCE_MS) return;
    this.setMeta("lastPushAt", now);
    this.ctx.waitUntil(
      sendWebPush(sub, cfg, getPushTransport()).then((result) => {
        if (result === "gone") this.delMeta("push");
      }),
    );
  }

  // ---- WebSockets (hibernation API) ----

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server);
    this.streamBacklog(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  private streamBacklog(ws: WebSocket): void {
    this.prune();
    let after = "";
    for (;;) {
      const rows = this.sql
        .exec<EnvelopeRow>("SELECT * FROM envelopes WHERE id > ? ORDER BY id ASC LIMIT ?", after, DRAIN_LIMIT)
        .toArray();
      for (const r of rows) {
        if (!this.send(ws, { type: "envelope", envelope: this.rowToEnvelope(r) })) return;
      }
      if (rows.length < DRAIN_LIMIT) break;
      after = rows[rows.length - 1].id;
    }
    this.send(ws, { type: "queue-empty" });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string" || message.length > 4096) return;
    let frame: { type?: unknown; id?: unknown };
    try {
      frame = JSON.parse(message);
    } catch {
      return;
    }
    if (!frame || typeof frame !== "object") return;
    switch (frame.type) {
      case "ping":
        this.send(ws, { type: "pong" });
        break;
      case "ack":
        if (typeof frame.id === "string" && frame.id.length <= 64) await this.ack(frame.id);
        break;
      default:
        break;
    }
  }

  async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
    try {
      ws.close(code === 1005 || code === 1006 ? 1000 : code, reason.slice(0, 120));
    } catch {
      // already closed
    }
    void wasClean;
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    try {
      ws.close(1011, "error");
    } catch {
      // already closed
    }
  }

  private send(ws: WebSocket, frame: unknown): boolean {
    try {
      ws.send(JSON.stringify(frame));
      return true;
    } catch {
      try {
        ws.close(1011, "send failed");
      } catch {
        // ignore
      }
      return false;
    }
  }

  /** Sends a frame to every live socket. Returns true when at least one delivery succeeded. */
  private sendAll(frame: unknown): boolean {
    let any = false;
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== WebSocket.READY_STATE_OPEN && ws.readyState !== 1) continue;
      if (this.send(ws, frame)) any = true;
    }
    return any;
  }

  private broadcast(envelopes: Envelope[]): boolean {
    let any = false;
    for (const ws of this.ctx.getWebSockets()) {
      if (ws.readyState !== WebSocket.READY_STATE_OPEN && ws.readyState !== 1) continue;
      let ok = true;
      for (const envelope of envelopes) {
        if (!this.send(ws, { type: "envelope", envelope })) {
          ok = false;
          break;
        }
      }
      if (ok) any = true;
    }
    return any;
  }
}
