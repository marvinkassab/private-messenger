import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { authHeader, BASE, makeIdentity, registerUser, uniqueName } from "./helpers";

async function upload(id: Awaited<ReturnType<typeof registerUser>>, bytes: Uint8Array, headers: Record<string, string> = {}) {
  return SELF.fetch(`${BASE}/v1/attachments`, {
    method: "POST",
    headers: {
      Authorization: await authHeader(id, "POST", "/v1/attachments", bytes),
      "Content-Type": "application/octet-stream",
      ...headers,
    },
    body: bytes,
  });
}

describe("attachments", () => {
  it("uploads, downloads without auth, 404 for unknown ids", async () => {
    const alice = await registerUser("alice");
    const blob = new Uint8Array(70_000);
    for (let i = 0; i < blob.length; i += 65536) crypto.getRandomValues(blob.subarray(i, Math.min(i + 65536, blob.length)));
    const up = await upload(alice, blob);
    expect(up.status).toBe(201);
    const { id } = await up.json<any>();
    expect(id).toMatch(/^[0-9a-f]{64}$/);

    const down = await SELF.fetch(`${BASE}/v1/attachments/${id}`);
    expect(down.status).toBe(200);
    expect(down.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(new Uint8Array(await down.arrayBuffer())).toEqual(blob);

    const missing = await SELF.fetch(`${BASE}/v1/attachments/${"0".repeat(64)}`);
    expect(missing.status).toBe(404);
    const badId = await SELF.fetch(`${BASE}/v1/attachments/../etc`);
    expect(badId.status).toBe(404);
  });

  it("accepts a chunked upload without Content-Length", async () => {
    const alice = await registerUser("alice");
    const parts = [1000, 2000, 3000].map((n) => crypto.getRandomValues(new Uint8Array(n)));
    const whole = new Uint8Array(6000);
    parts.forEach((p, i) => whole.set(p, [0, 1000, 3000][i]));
    const stream = new ReadableStream<Uint8Array>({
      start(ctl) {
        for (const p of parts) ctl.enqueue(p);
        ctl.close();
      },
    });
    const res = await SELF.fetch(`${BASE}/v1/attachments`, {
      method: "POST",
      headers: { Authorization: await authHeader(alice, "POST", "/v1/attachments", whole), "Content-Type": "application/octet-stream" },
      body: stream,
    });
    expect(res.status).toBe(201);
    const { id } = await res.json<any>();
    const down = await SELF.fetch(`${BASE}/v1/attachments/${id}`);
    expect(new Uint8Array(await down.arrayBuffer())).toEqual(whole);
  });

  it("requires a valid signature and deletes the blob otherwise", async () => {
    const alice = await registerUser("alice");
    const impostor = await makeIdentity(alice.username);
    const blob = crypto.getRandomValues(new Uint8Array(100));
    const res = await upload(impostor, blob);
    expect(res.status).toBe(401);
    const unknown = await upload(await makeIdentity(uniqueName("ghost")), blob);
    expect(unknown.status).toBe(401);
    // signature over different bytes than uploaded
    const tampered = await SELF.fetch(`${BASE}/v1/attachments`, {
      method: "POST",
      headers: { Authorization: await authHeader(alice, "POST", "/v1/attachments", new Uint8Array([1, 2, 3])) },
      body: blob,
    });
    expect(tampered.status).toBe(401);
  });

  it("returns 413 above 25 MB", async () => {
    const alice = await registerUser("alice");
    const declared = await SELF.fetch(`${BASE}/v1/attachments`, {
      method: "POST",
      headers: {
        Authorization: await authHeader(alice, "POST", "/v1/attachments", new Uint8Array(1)),
        "Content-Length": String(25 * 1024 * 1024 + 1),
      },
      body: new Uint8Array(1),
    });
    expect(declared.status).toBe(413);

    // A chunked body that lies about nothing but is simply too big.
    const chunk = new Uint8Array(1024 * 1024);
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(ctl) {
        if (sent >= 26 * 1024 * 1024) return ctl.close();
        ctl.enqueue(chunk);
        sent += chunk.byteLength;
      },
    });
    const big = await SELF.fetch(`${BASE}/v1/attachments`, {
      method: "POST",
      headers: { Authorization: await authHeader(alice, "POST", "/v1/attachments", new Uint8Array(1)) },
      body: stream,
    });
    expect(big.status).toBe(413);
  });
});
