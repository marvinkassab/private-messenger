// One Durable Object per invite code (idFromName(code)). Single use, 7 days.
// Because a Durable Object processes one request at a time, `claim` is atomic:
// two registrations racing for the same code cannot both succeed.

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./types";

export const INVITE_TTL_MS = 7 * 24 * 3600 * 1000;

interface InviteRecord {
  creator: string;
  createdAt: number;
  expiresAt: number;
  usedBy: string | null;
  usedAt: number | null;
}

export type ClaimResult = { ok: true } | { ok: false; reason: "unknown" | "expired" | "used" };

export class Invite extends DurableObject<Env> {
  private async load(): Promise<InviteRecord | undefined> {
    return this.ctx.storage.get<InviteRecord>("invite");
  }

  /** Creates the invite. Returns its expiry. */
  async mint(creator: string, now = Date.now()): Promise<{ expiresAt: number }> {
    const existing = await this.load();
    if (existing) throw new Error("invite code collision");
    const rec: InviteRecord = { creator, createdAt: now, expiresAt: now + INVITE_TTL_MS, usedBy: null, usedAt: null };
    await this.ctx.storage.put("invite", rec);
    // Clean up after expiry so unused codes do not linger forever.
    await this.ctx.storage.setAlarm(rec.expiresAt + 60_000);
    return { expiresAt: rec.expiresAt };
  }

  /**
   * Claims the bootstrap code, creating its record on first use.
   *
   * The bootstrap code is the one invite nobody mints: it comes from a secret
   * so the very first account can exist at all. It used to be accepted every
   * time the secret was set, which made it a permanent skeleton key to the
   * whole server for anyone who ever saw it. Now it is claimed exactly once,
   * like any other invite, and the operator gets a fresh one by rotating the
   * secret. It never expires before use, since there is nobody to re-issue it.
   */
  async claimBootstrap(username: string, now = Date.now()): Promise<ClaimResult> {
    const existing = await this.load();
    if (existing) {
      return existing.usedBy !== null ? { ok: false, reason: "used" } : this.claim(username, now);
    }
    const rec: InviteRecord = {
      creator: "bootstrap",
      createdAt: now,
      expiresAt: Number.MAX_SAFE_INTEGER,
      usedBy: username,
      usedAt: now,
    };
    await this.ctx.storage.put("invite", rec);
    return { ok: true };
  }

  /** Atomically marks the invite used by `username`. */
  async claim(username: string, now = Date.now()): Promise<ClaimResult> {
    const rec = await this.load();
    if (!rec) return { ok: false, reason: "unknown" };
    if (rec.usedBy !== null) return { ok: false, reason: "used" };
    if (rec.expiresAt <= now) return { ok: false, reason: "expired" };
    rec.usedBy = username;
    rec.usedAt = now;
    await this.ctx.storage.put("invite", rec);
    return { ok: true };
  }

  /** Undo a claim when the registration that claimed it failed afterwards. */
  async release(username: string): Promise<void> {
    const rec = await this.load();
    if (rec && rec.usedBy === username) {
      rec.usedBy = null;
      rec.usedAt = null;
      await this.ctx.storage.put("invite", rec);
    }
  }

  async info(): Promise<InviteRecord | null> {
    return (await this.load()) ?? null;
  }

  async alarm(): Promise<void> {
    const rec = await this.load();
    if (rec && rec.expiresAt <= Date.now()) await this.ctx.storage.deleteAll();
  }
}
