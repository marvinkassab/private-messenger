/* The plaintext of every Signal message: `Content` from docs/PROTOCOL.md.
   Validation is lenient about unknown kinds (they are ignored, not errors)
   and strict about the shape of the kinds we know. */

import { utf8Decode, utf8Encode } from "./util";

export const CONTENT_KINDS = [
  "text",
  "attachment",
  "reaction",
  "delete",
  "receipt",
  "typing",
  "group",
  "profile",
  "disappear",
] as const;
export type ContentKind = (typeof CONTENT_KINDS)[number];

export interface AttachmentPointer {
  id: string;
  key: string;      // b64 32-byte AES-256-GCM key
  iv: string;       // b64 12-byte nonce
  digest: string;   // b64 sha256 of the ciphertext
  mime: string;
  size: number;
  name?: string;
  width?: number;
  height?: number;
  caption?: string;
}

export interface GroupUpdate {
  id: string;
  revision: number;
  name: string;
  creator: string;
  admins: string[];
  members: string[];
  action: "create" | "update" | "leave";
}

export interface Content {
  v: 1;
  id: string;
  ts: number;
  group?: string;
  kind: ContentKind | (string & {});
  body?: string;
  replyTo?: string;
  ref?: string;
  attachment?: AttachmentPointer;
  receipt?: "delivered" | "read";
  group_update?: GroupUpdate;
  profile?: { name?: string; deliveryToken?: string };
  disappear?: number;
  expires?: number;
}

const ID_RE = /^[0-9a-f]{32}$/;
const USERNAME_RE = /^[a-z0-9_]{3,32}$/;
const MAX_BODY = 64 * 1024;

export class ContentError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ContentError";
  }
}

function isStr(v: unknown, max = MAX_BODY): v is string {
  return typeof v === "string" && v.length <= max;
}
function isNum(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}
function isUsernameList(v: unknown): v is string[] {
  return Array.isArray(v) && v.length <= 1000 && v.every((u) => typeof u === "string" && USERNAME_RE.test(u));
}

export function validateGroupUpdate(v: unknown): GroupUpdate {
  if (!v || typeof v !== "object") throw new ContentError("group_update missing");
  const g = v as Record<string, unknown>;
  if (!isStr(g.id, 64) || !ID_RE.test(g.id)) throw new ContentError("group id");
  if (!isNum(g.revision) || g.revision < 0 || !Number.isInteger(g.revision)) throw new ContentError("group revision");
  if (!isStr(g.name, 256)) throw new ContentError("group name");
  if (!isStr(g.creator, 32) || !USERNAME_RE.test(g.creator)) throw new ContentError("group creator");
  if (!isUsernameList(g.admins)) throw new ContentError("group admins");
  if (!isUsernameList(g.members)) throw new ContentError("group members");
  if (g.action !== "create" && g.action !== "update" && g.action !== "leave") throw new ContentError("group action");
  return {
    id: g.id,
    revision: g.revision,
    name: g.name,
    creator: g.creator,
    admins: Array.from(new Set(g.admins)),
    members: Array.from(new Set(g.members)),
    action: g.action,
  };
}

function validateAttachment(v: unknown): AttachmentPointer {
  if (!v || typeof v !== "object") throw new ContentError("attachment missing");
  const a = v as Record<string, unknown>;
  if (!isStr(a.id, 128) || !/^[0-9a-f]{1,128}$/.test(a.id)) throw new ContentError("attachment id");
  if (!isStr(a.key, 64) || !isStr(a.iv, 32) || !isStr(a.digest, 64)) throw new ContentError("attachment keys");
  if (!isStr(a.mime, 255)) throw new ContentError("attachment mime");
  if (!isNum(a.size) || a.size < 0) throw new ContentError("attachment size");
  const out: AttachmentPointer = { id: a.id, key: a.key, iv: a.iv, digest: a.digest, mime: a.mime, size: a.size };
  if (a.name !== undefined) {
    if (!isStr(a.name, 255)) throw new ContentError("attachment name");
    out.name = a.name;
  }
  if (a.width !== undefined) {
    if (!isNum(a.width)) throw new ContentError("attachment width");
    out.width = a.width;
  }
  if (a.height !== undefined) {
    if (!isNum(a.height)) throw new ContentError("attachment height");
    out.height = a.height;
  }
  if (a.caption !== undefined) {
    if (!isStr(a.caption)) throw new ContentError("attachment caption");
    out.caption = a.caption;
  }
  return out;
}

/** Throws ContentError when malformed. Unknown kinds pass through (callers ignore them). */
export function validateContent(v: unknown): Content {
  if (!v || typeof v !== "object") throw new ContentError("content is not an object");
  const c = v as Record<string, unknown>;
  if (c.v !== 1) throw new ContentError("unsupported content version");
  if (!isStr(c.id, 32) || !ID_RE.test(c.id)) throw new ContentError("bad content id");
  if (!isNum(c.ts) || c.ts < 0) throw new ContentError("bad ts");
  if (!isStr(c.kind, 32)) throw new ContentError("bad kind");
  const out: Content = { v: 1, id: c.id, ts: c.ts, kind: c.kind };
  if (c.group !== undefined) {
    if (!isStr(c.group, 32) || !ID_RE.test(c.group)) throw new ContentError("bad group id");
    out.group = c.group;
  }
  if (c.expires !== undefined) {
    if (!isNum(c.expires) || c.expires < 0) throw new ContentError("bad expires");
    out.expires = c.expires;
  }
  if (c.replyTo !== undefined) {
    if (!isStr(c.replyTo, 32) || !ID_RE.test(c.replyTo)) throw new ContentError("bad replyTo");
    out.replyTo = c.replyTo;
  }
  switch (c.kind) {
    case "text":
      if (!isStr(c.body)) throw new ContentError("text needs body");
      out.body = c.body;
      break;
    case "attachment":
      out.attachment = validateAttachment(c.attachment);
      if (c.body !== undefined) {
        if (!isStr(c.body)) throw new ContentError("bad body");
        out.body = c.body;
      }
      break;
    case "reaction":
      if (!isStr(c.ref, 32) || !ID_RE.test(c.ref)) throw new ContentError("reaction needs ref");
      if (!isStr(c.body, 64)) throw new ContentError("reaction needs body");
      out.ref = c.ref;
      out.body = c.body;
      break;
    case "delete":
      if (!isStr(c.ref, 32) || !ID_RE.test(c.ref)) throw new ContentError("delete needs ref");
      out.ref = c.ref;
      break;
    case "receipt":
      if (c.receipt !== "delivered" && c.receipt !== "read") throw new ContentError("bad receipt");
      if (!isStr(c.ref, 33 * 50)) throw new ContentError("receipt needs ref");
      if (!c.ref.split(",").every((id) => ID_RE.test(id))) throw new ContentError("bad receipt ids");
      out.receipt = c.receipt;
      out.ref = c.ref;
      break;
    case "typing":
      if (c.body !== "start" && c.body !== "stop") throw new ContentError("bad typing body");
      out.body = c.body;
      break;
    case "group":
      out.group_update = validateGroupUpdate(c.group_update);
      if (out.group !== undefined && out.group !== out.group_update.id) throw new ContentError("group id mismatch");
      out.group = out.group_update.id;
      break;
    case "profile": {
      if (!c.profile || typeof c.profile !== "object") throw new ContentError("profile missing");
      const p = c.profile as Record<string, unknown>;
      const profile: { name?: string; deliveryToken?: string } = {};
      if (p.name !== undefined) {
        if (!isStr(p.name, 256)) throw new ContentError("bad profile name");
        profile.name = p.name;
      }
      if (p.deliveryToken !== undefined) {
        if (!isStr(p.deliveryToken, 64) || !/^[A-Za-z0-9+/]{43}=$/.test(p.deliveryToken)) throw new ContentError("bad delivery token");
        profile.deliveryToken = p.deliveryToken;
      }
      out.profile = profile;
      break;
    }
    case "disappear":
      if (!isNum(c.disappear) || c.disappear < 0 || !Number.isInteger(c.disappear)) throw new ContentError("bad disappear");
      out.disappear = c.disappear;
      break;
    default:
      // unknown kind: keep the envelope fields, the dispatcher ignores it
      break;
  }
  return out;
}

export function encodeContent(c: Content): Uint8Array {
  return utf8Encode(JSON.stringify(c));
}

export function decodeContent(bytes: ArrayBuffer | Uint8Array): Content {
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(bytes));
  } catch {
    throw new ContentError("content is not JSON");
  }
  return validateContent(parsed);
}

export function isKnownKind(kind: string): kind is ContentKind {
  return (CONTENT_KINDS as readonly string[]).includes(kind);
}
