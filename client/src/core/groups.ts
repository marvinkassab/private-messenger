/* Pure group-state rules from docs/PROTOCOL.md. No I/O. */

import type { GroupState } from "../types";
import type { GroupUpdate } from "./content";

export type GroupApplyResult =
  | { ok: true; state: GroupState; change: "created" | "updated" | "left" | "removed-us" }
  | { ok: false; reason: string };

export function isGroupAdmin(g: Pick<GroupState, "creator" | "admins">, user: string): boolean {
  return g.creator === user || g.admins.includes(user);
}

/**
 * Apply an incoming group control message.
 * @param current what we hold for this group id, if anything
 * @param update the validated group_update
 * @param from the session the message decrypted on (the only trustworthy sender)
 * @param me our username
 */
export function applyGroupUpdate(
  current: GroupState | undefined,
  update: GroupUpdate,
  from: string,
  me: string,
): GroupApplyResult {
  if (update.action === "create") {
    if (current) return { ok: false, reason: "group already exists" };
    if (update.creator !== from) return { ok: false, reason: "creator is not the sender" };
    if (!update.members.includes(from)) return { ok: false, reason: "creator not in members" };
    const state: GroupState = {
      id: update.id,
      name: update.name,
      creator: update.creator,
      admins: update.admins.includes(update.creator) ? update.admins : [update.creator, ...update.admins],
      members: update.members,
      revision: update.revision,
    };
    if (!update.members.includes(me)) state.leftOrRemoved = true;
    return { ok: true, state, change: "created" };
  }
  if (!current) return { ok: false, reason: "unknown group" };
  if (!current.members.includes(from)) return { ok: false, reason: "sender is not a member" };

  if (update.action === "leave") {
    if (from === me) return { ok: false, reason: "own leave echoed" };
    const state: GroupState = {
      ...current,
      members: current.members.filter((m) => m !== from),
      admins: current.admins.filter((m) => m !== from),
    };
    return { ok: true, state, change: "updated" };
  }

  // update: admins (or the creator) only, strictly increasing revision
  if (!isGroupAdmin(current, from)) return { ok: false, reason: "sender is not an admin" };
  if (update.revision <= current.revision) return { ok: false, reason: "stale revision" };
  if (update.creator !== current.creator) return { ok: false, reason: "creator cannot change" };
  const state: GroupState = {
    id: current.id,
    name: update.name,
    creator: current.creator,
    admins: update.admins.includes(current.creator) ? update.admins : [current.creator, ...update.admins],
    members: update.members,
    revision: update.revision,
  };
  if (!update.members.includes(me)) {
    state.leftOrRemoved = true;
    return { ok: true, state, change: "removed-us" };
  }
  if (current.leftOrRemoved) {
    // an admin re-added us
    state.leftOrRemoved = false;
  }
  return { ok: true, state, change: "updated" };
}

/** Human-readable diff for system messages. */
export function describeGroupChange(prev: GroupState | undefined, next: GroupState, from: string, action: GroupUpdate["action"]): string {
  if (action === "create") return `${from} created the group "${next.name}"`;
  if (action === "leave") return `${from} left the group`;
  const lines: string[] = [];
  if (prev && prev.name !== next.name) lines.push(`${from} renamed the group to "${next.name}"`);
  const added = next.members.filter((m) => !prev?.members.includes(m));
  const removed = (prev?.members ?? []).filter((m) => !next.members.includes(m));
  if (added.length) lines.push(`${from} added ${added.join(", ")}`);
  if (removed.length) lines.push(`${from} removed ${removed.join(", ")}`);
  return lines.length ? lines.join("; ") : `${from} updated the group`;
}
