import { env } from "cloudflare:test";
import { afterEach, describe, expect, it } from "vitest";
import { createVapidJwt, sendWebPush, setPushTransport, type VapidConfig } from "../src/push";
import { b64urlDecode, utf8 } from "../src/util";
import { api, randomContent, registerUser, sendTo, sleep, connectWs } from "./helpers";

const cfg: VapidConfig = {
  publicKey: env.VAPID_PUBLIC_KEY!,
  privateKey: env.VAPID_PRIVATE_KEY!,
  subject: env.VAPID_SUBJECT!,
};

const PEM_PRIVATE = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg28TCKBOdPAgjONCT
VPKW/pYMsVAg3S8g5ifba0vv5JyhRANCAASU1oOuyBznDicWvkcM5bMV5SQRiTFu
bHGq29jvWDs3fzf8cU4PaZaA5HehSNzmEbdCik74cM6xxKEYGPnZRk7E
-----END PRIVATE KEY-----`;

async function verifyJwt(jwt: string, publicKeyB64url: string): Promise<{ header: any; claims: any; valid: boolean }> {
  const [h, c, s] = jwt.split(".");
  const pub = b64urlDecode(publicKeyB64url)!;
  const key = await crypto.subtle.importKey("raw", pub as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    b64urlDecode(s)! as BufferSource,
    utf8(`${h}.${c}`) as BufferSource,
  );
  const dec = (x: string) => JSON.parse(new TextDecoder().decode(b64urlDecode(x)!));
  return { header: dec(h), claims: dec(c), valid };
}

describe("VAPID / Web Push", () => {
  afterEach(() => setPushTransport(undefined));

  it("produces a well-formed ES256 JWT that verifies under the public key", async () => {
    const before = Math.floor(Date.now() / 1000);
    const jwt = await createVapidJwt(cfg, "https://push.example.org");
    expect(jwt.split(".")).toHaveLength(3);
    const { header, claims, valid } = await verifyJwt(jwt, cfg.publicKey);
    expect(header).toEqual({ typ: "JWT", alg: "ES256" });
    expect(claims.aud).toBe("https://push.example.org");
    expect(claims.sub).toBe("mailto:test@example.com");
    expect(claims.exp).toBeGreaterThanOrEqual(before + 12 * 3600 - 5);
    expect(claims.exp).toBeLessThanOrEqual(before + 12 * 3600 + 5);
    expect(valid).toBe(true);
  });

  it("accepts a PEM private key too", async () => {
    const jwt = await createVapidJwt({ ...cfg, privateKey: PEM_PRIVATE }, "https://push.example.org");
    expect((await verifyJwt(jwt, cfg.publicKey)).valid).toBe(true);
  });

  it("posts an empty push with VAPID, TTL and Urgency headers", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fake = async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(null, { status: 201 });
    };
    const sub = { endpoint: "https://push.example.org/send/abc", keys: { p256dh: "x", auth: "y" } };
    expect(await sendWebPush(sub, cfg, fake)).toBe("sent");
    expect(calls).toHaveLength(1);
    const { url, init } = calls[0];
    expect(url).toBe(sub.endpoint);
    expect(init.method).toBe("POST");
    expect(init.body).toBeUndefined();
    const h = init.headers as Record<string, string>;
    expect(h.TTL).toBe("86400");
    expect(h.Urgency).toBe("high");
    expect(h["Content-Length"]).toBe("0");
    const m = /^vapid t=([^,]+), k=(.+)$/.exec(h.Authorization);
    expect(m).not.toBeNull();
    expect(m![2]).toBe(cfg.publicKey);
    const { claims, valid } = await verifyJwt(m![1], cfg.publicKey);
    expect(valid).toBe(true);
    expect(claims.aud).toBe("https://push.example.org");

    const gone = async () => new Response(null, { status: 410 });
    expect(await sendWebPush(sub, cfg, gone)).toBe("gone");
  });

  it("the mailbox pushes when a message arrives with no live socket, debounced", async () => {
    const calls: string[] = [];
    setPushTransport(async (url) => {
      calls.push(url);
      return new Response(null, { status: 201 });
    });
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const endpoint = `https://push.example.org/send/${bob.username}`;
    const put = await api(bob, "PUT", "/v1/push", { endpoint, keys: { p256dh: "BAbc", auth: "xyz" } });
    expect(put.status).toBe(200);
    const badSub = await api(bob, "PUT", "/v1/push", { endpoint: "http://insecure.example", keys: { p256dh: "a", auth: "b" } });
    expect(badSub.status).toBe(400);

    expect((await sendTo(alice, bob.username, randomContent())).status).toBe(200);
    for (let i = 0; i < 50 && calls.length === 0; i++) await sleep(20);
    expect(calls).toEqual([endpoint]);

    // second message within 10 s: debounced
    expect((await sendTo(alice, bob.username, randomContent())).status).toBe(200);
    await sleep(100);
    expect(calls).toHaveLength(1);
  });

  it("does not push while a socket is live, and stops after DELETE /v1/push", async () => {
    const calls: string[] = [];
    setPushTransport(async (url) => {
      calls.push(url);
      return new Response(null, { status: 201 });
    });
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    await api(bob, "PUT", "/v1/push", { endpoint: "https://push.example.org/send/live", keys: { p256dh: "a", auth: "b" } });
    const { ws, frames } = await connectWs(bob);
    expect(await frames.next()).toEqual({ type: "queue-empty" });
    expect((await sendTo(alice, bob.username, randomContent())).status).toBe(200);
    expect((await frames.next()).type).toBe("envelope");
    await sleep(100);
    expect(calls).toHaveLength(0);
    ws.close(1000);
    await sleep(50);

    expect((await api(bob, "DELETE", "/v1/push")).status).toBe(200);
    expect((await sendTo(alice, bob.username, randomContent())).status).toBe(200);
    await sleep(100);
    expect(calls).toHaveLength(0);
  });
});
