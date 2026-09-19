import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { b64Encode } from "../src/util";
import { api, authHeader, BASE, BOOTSTRAP, encodeBody, makeIdentity, makeSignedPreKey, registerBody, registerUser, uniqueName } from "./helpers";

describe("health and CORS", () => {
  it("GET /v1/health", async () => {
    const res = await SELF.fetch(`${BASE}/v1/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("answers CORS preflight for an allowed origin", async () => {
    const res = await SELF.fetch(`${BASE}/v1/register`, {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization, content-type",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("http://localhost:5173");
    expect(res.headers.get("Access-Control-Allow-Methods")).toBe("GET, POST, PUT, DELETE, OPTIONS");
    expect(res.headers.get("Access-Control-Allow-Headers")).toBe("Authorization, Unidentified-Access, Content-Type");
  });

  it("adds CORS headers to normal responses for allowed origins only", async () => {
    const ok = await SELF.fetch(`${BASE}/v1/health`, { headers: { Origin: "http://127.0.0.1:5173" } });
    expect(ok.headers.get("Access-Control-Allow-Origin")).toBe("http://127.0.0.1:5173");
    const bad = await SELF.fetch(`${BASE}/v1/health`, { headers: { Origin: "https://evil.example" } });
    expect(bad.headers.get("Access-Control-Allow-Origin")).toBeNull();
    const pre = await SELF.fetch(`${BASE}/v1/health`, { method: "OPTIONS", headers: { Origin: "https://evil.example" } });
    expect(pre.status).toBe(403);
  });

  it("returns the JSON error shape for unknown routes", async () => {
    const res = await SELF.fetch(`${BASE}/v1/nope`);
    expect(res.status).toBe(404);
    const body = await res.json<any>();
    expect(body.error).toBe("not_found");
    expect(typeof body.message).toBe("string");
  });
});

describe("POST /v1/register", () => {
  it("registers with the bootstrap invite", async () => {
    const id = await makeIdentity(uniqueName("reg"));
    const res = await api(id, "POST", "/v1/register", await registerBody(id, { invite: BOOTSTRAP }));
    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ username: id.username, deviceId: 1 });
  });

  it("rejects an unknown invite with 403", async () => {
    const id = await makeIdentity(uniqueName("reg"));
    const res = await api(id, "POST", "/v1/register", await registerBody(id, { invite: "does-not-exist" }));
    expect(res.status).toBe(403);
    expect((await res.json<any>()).error).toBe("invite_invalid");
  });

  it("mints an invite, uses it once, rejects reuse", async () => {
    const alice = await registerUser("alice");
    const mint = await api(alice, "POST", "/v1/invites");
    expect(mint.status).toBe(201);
    const { code, expiresAt } = await mint.json<any>();
    expect(typeof code).toBe("string");
    expect(expiresAt).toBeGreaterThan(Date.now() + 6 * 24 * 3600 * 1000);
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 7 * 24 * 3600 * 1000 + 1000);

    const bob = await makeIdentity(uniqueName("bob"));
    const ok = await api(bob, "POST", "/v1/register", await registerBody(bob, { invite: code }));
    expect(ok.status).toBe(201);

    const carol = await makeIdentity(uniqueName("carol"));
    const used = await api(carol, "POST", "/v1/register", await registerBody(carol, { invite: code }));
    expect(used.status).toBe(403);
    expect((await used.json<any>()).message).toContain("used");
  });

  it("returns 409 for a duplicate username", async () => {
    const id = await registerUser("dup");
    const again = await makeIdentity(id.username);
    const res = await api(again, "POST", "/v1/register", await registerBody(again));
    expect(res.status).toBe(409);
    expect((await res.json<any>()).error).toBe("username_taken");
  });

  it("returns 401 for a bad request signature", async () => {
    const id = await makeIdentity(uniqueName("badsig"));
    const other = await makeIdentity(id.username);
    const body = await registerBody(id);
    const bytes = encodeBody(body);
    const res = await SELF.fetch(`${BASE}/v1/register`, {
      method: "POST",
      headers: { Authorization: await authHeader(other, "POST", "/v1/register", bytes), "Content-Type": "application/json" },
      body: bytes,
    });
    expect(res.status).toBe(401);
  });

  it("returns 401 when the timestamp is outside the 300 s window", async () => {
    const id = await makeIdentity(uniqueName("oldts"));
    const body = await registerBody(id);
    const stale = await api(id, "POST", "/v1/register", body, { ts: Math.floor(Date.now() / 1000) - 600 });
    expect(stale.status).toBe(401);
    const future = await api(id, "POST", "/v1/register", body, { ts: Math.floor(Date.now() / 1000) + 600 });
    expect(future.status).toBe(401);
  });

  it("returns 400 when the signed prekey signature does not verify", async () => {
    const id = await makeIdentity(uniqueName("badspk"));
    const other = await makeIdentity("other");
    const body = await registerBody(id);
    body.signedPreKey = await makeSignedPreKey(other, 1);
    const res = await api(id, "POST", "/v1/register", body);
    expect(res.status).toBe(400);
    expect((await res.json<any>()).error).toBe("bad_signature");
  });

  it("validates the username", async () => {
    for (const bad of ["ab", "Upper", "has-dash", "a".repeat(33), "count"]) {
      const id = await makeIdentity(bad);
      const res = await api(id, "POST", "/v1/register", await registerBody(id));
      expect(res.status, bad).toBeGreaterThanOrEqual(400);
      expect(res.status, bad).toBeLessThan(402);
    }
  });

  it("rejects malformed keys", async () => {
    const id = await makeIdentity(uniqueName("badkeys"));
    const body = await registerBody(id);
    body.identityKey = b64Encode(new Uint8Array(32));
    const res = await api(id, "POST", "/v1/register", body);
    expect(res.status).toBe(400);
  });
});
