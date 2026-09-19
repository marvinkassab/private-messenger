// Encrypted attachment blobs in R2. The Worker never sees plaintext; the id
// is random and is the only handle to the blob.

import { createHash } from "node:crypto";
import { ApiError, type Env } from "./types";
import { randomHex } from "./util";

export const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;
const ID_RE = /^[0-9a-f]{64}$/;

export function isAttachmentId(id: string): boolean {
  return ID_RE.test(id);
}

export interface UploadResult {
  id: string;
  /** hex sha256 of the raw body, for the request signature */
  bodyHashHex: string;
  size: number;
}

/**
 * Streams the request body into R2 while hashing it. The caller verifies the
 * request signature against `bodyHashHex` afterwards and calls
 * `deleteAttachment` when it does not verify.
 */
export async function storeAttachment(request: Request, env: Env): Promise<UploadResult> {
  const lengthHeader = request.headers.get("content-length");
  const declared = lengthHeader === null ? null : Number(lengthHeader);
  if (declared !== null && (!Number.isInteger(declared) || declared < 0)) throw new ApiError(400, "bad_request", "invalid Content-Length");
  if (declared !== null && declared > MAX_ATTACHMENT_BYTES) throw new ApiError(413, "too_large", "attachment exceeds 25 MB");
  if (!request.body || declared === 0) throw new ApiError(400, "bad_request", "empty body");

  const id = randomHex(32);
  const hash = createHash("sha256");
  let size = 0;
  const tooLarge = () => new ApiError(413, "too_large", "attachment exceeds 25 MB");
  const httpMetadata = { contentType: "application/octet-stream" };

  if (declared === null) {
    // Chunked upload without a length: buffer up to the limit.
    const chunks: Uint8Array[] = [];
    const reader = request.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_ATTACHMENT_BYTES) {
        await reader.cancel().catch(() => {});
        throw tooLarge();
      }
      hash.update(value);
      chunks.push(value);
    }
    if (size === 0) throw new ApiError(400, "bad_request", "empty body");
    const buf = new Uint8Array(size);
    let off = 0;
    for (const c of chunks) {
      buf.set(c, off);
      off += c.byteLength;
    }
    await env.ATTACHMENTS.put(id, buf, { httpMetadata });
    return { id, bodyHashHex: hash.digest("hex"), size };
  }

  // Known length: stream straight into R2 while hashing and counting. R2
  // needs a known length to stream; FixedLengthStream provides it and fails
  // the upload if the body does not match Content-Length.
  let sizeError: ApiError | undefined;
  const counter = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      size += chunk.byteLength;
      if (size > MAX_ATTACHMENT_BYTES) {
        sizeError = tooLarge();
        controller.error(sizeError);
        return;
      }
      hash.update(chunk);
      controller.enqueue(chunk);
    },
  });
  const fixed = new FixedLengthStream(declared);
  let pipeError: unknown;
  // Attach the handler right away so a pipe failure is never an unhandled rejection.
  const piping = request.body
    .pipeThrough(counter)
    .pipeTo(fixed.writable)
    .catch((e) => {
      pipeError = e;
    });
  try {
    await env.ATTACHMENTS.put(id, fixed.readable, { httpMetadata });
    await piping;
    if (pipeError !== undefined) throw pipeError;
  } catch (e) {
    await piping;
    await env.ATTACHMENTS.delete(id).catch(() => {});
    if (sizeError) throw sizeError;
    if (e instanceof ApiError) throw e;
    throw new ApiError(400, "bad_request", "upload failed: body did not match Content-Length");
  }
  return { id, bodyHashHex: hash.digest("hex"), size };
}

export async function deleteAttachment(env: Env, id: string): Promise<void> {
  await env.ATTACHMENTS.delete(id);
}

export async function getAttachment(env: Env, id: string): Promise<Response> {
  if (!isAttachmentId(id)) throw new ApiError(404, "not_found", "unknown attachment");
  const obj = await env.ATTACHMENTS.get(id);
  if (!obj) throw new ApiError(404, "not_found", "unknown attachment");
  const headers = new Headers({
    "Content-Type": "application/octet-stream",
    "Content-Length": String(obj.size),
    "Cache-Control": "private, max-age=86400, immutable",
    ETag: obj.httpEtag,
  });
  return new Response(obj.body, { status: 200, headers });
}
