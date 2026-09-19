/* Attachment crypto and image downscaling (docs/PROTOCOL.md "Attachments"). */

import type { AttachmentPointer } from "./content";
import { aesGcmDecrypt, aesGcmEncrypt, b64Decode, b64Encode, bytesEqual, randomBytes, sha256 } from "./util";

export const MAX_IMAGE_EDGE = 2048;
export const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

export interface EncryptedAttachment {
  ciphertext: Uint8Array;
  key: string;     // b64 32 bytes
  iv: string;      // b64 12 bytes
  digest: string;  // b64 sha256(ciphertext)
}

export async function encryptAttachment(plaintext: Uint8Array): Promise<EncryptedAttachment> {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const ciphertext = await aesGcmEncrypt(key, iv, plaintext);
  const digest = await sha256(ciphertext);
  return { ciphertext, key: b64Encode(key), iv: b64Encode(iv), digest: b64Encode(digest) };
}

export class AttachmentDigestError extends Error {
  constructor() {
    super("attachment digest mismatch");
    this.name = "AttachmentDigestError";
  }
}

/** Verifies the digest before decrypting, as the protocol requires. */
export async function decryptAttachment(
  ciphertext: Uint8Array,
  pointer: Pick<AttachmentPointer, "key" | "iv" | "digest">,
): Promise<Uint8Array> {
  const digest = await sha256(ciphertext);
  if (!bytesEqual(digest, b64Decode(pointer.digest))) throw new AttachmentDigestError();
  return aesGcmDecrypt(b64Decode(pointer.key), b64Decode(pointer.iv), ciphertext);
}

export function isImageMime(mime: string): boolean {
  return /^image\/(jpeg|png|webp|gif|bmp|avif|heic|heif)$/i.test(mime);
}

export interface PreparedImage {
  blob: Blob;
  mime: string;
  width?: number;
  height?: number;
  downscaled: boolean;
}

/**
 * Downscale an image to at most `maxEdge` px on the long edge and JPEG-encode it.
 * Uses createImageBitmap + canvas when available (browsers); in Node it returns the
 * original untouched.
 */
export async function prepareImage(blob: Blob, mime: string, maxEdge = MAX_IMAGE_EDGE): Promise<PreparedImage> {
  const g = globalThis as {
    createImageBitmap?: (b: Blob) => Promise<ImageBitmap>;
    OffscreenCanvas?: typeof OffscreenCanvas;
    document?: Document;
  };
  if (typeof g.createImageBitmap !== "function") return { blob, mime, downscaled: false };
  let bitmap: ImageBitmap;
  try {
    bitmap = await g.createImageBitmap(blob);
  } catch {
    return { blob, mime, downscaled: false };
  }
  const { width, height } = bitmap;
  const scale = Math.min(1, maxEdge / Math.max(width, height));
  const w = Math.max(1, Math.round(width * scale));
  const h = Math.max(1, Math.round(height * scale));
  try {
    if (scale === 1 && mime === "image/jpeg") return { blob, mime, width, height, downscaled: false };
    let out: Blob | null = null;
    if (g.OffscreenCanvas) {
      const canvas = new g.OffscreenCanvas(w, h);
      const ctx = canvas.getContext("2d");
      if (!ctx) return { blob, mime, width, height, downscaled: false };
      ctx.drawImage(bitmap, 0, 0, w, h);
      out = await canvas.convertToBlob({ type: "image/jpeg", quality: 0.85 });
    } else if (g.document) {
      const canvas = g.document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d");
      if (!ctx) return { blob, mime, width, height, downscaled: false };
      ctx.drawImage(bitmap, 0, 0, w, h);
      out = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/jpeg", 0.85));
    }
    if (!out) return { blob, mime, width, height, downscaled: false };
    return { blob: out, mime: "image/jpeg", width: w, height: h, downscaled: true };
  } finally {
    bitmap.close?.();
  }
}
