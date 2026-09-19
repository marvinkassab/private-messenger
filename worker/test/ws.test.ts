import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { api, BASE, connectWs, makeIdentity, randomContent, registerUser, sendTo, sleep, uniqueName, wsUrl } from "./helpers";

describe("WebSocket /v1/ws", () => {
  it("rejects bad auth in the query", async () => {
    const bob = await registerUser("bob");
    const impostor = await makeIdentity(bob.username);
    const res = await SELF.fetch(await wsUrl(impostor), { headers: { Upgrade: "websocket" } });
    expect(res.status).toBe(401);
    const stale = await SELF.fetch(await wsUrl(bob, Math.floor(Date.now() / 1000) - 1000), { headers: { Upgrade: "websocket" } });
    expect(stale.status).toBe(401);
    const noUpgrade = await SELF.fetch(await wsUrl(bob));
    expect(noUpgrade.status).toBe(426);
    const unknown = await SELF.fetch(await wsUrl(await makeIdentity(uniqueName("ghost"))), { headers: { Upgrade: "websocket" } });
    expect(unknown.status).toBe(401);
  });

  it("streams the backlog, then queue-empty, then live envelopes; acks over the socket", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const c1 = randomContent();
    const c2 = randomContent();
    expect((await sendTo(alice, bob.username, c1)).status).toBe(200);
    expect((await sendTo(alice, bob.username, c2)).status).toBe(200);

    const { ws, frames } = await connectWs(bob);
    const f1 = await frames.next();
    expect(f1.type).toBe("envelope");
    expect(f1.envelope.content).toBe(c1);
    expect(f1.envelope.from).toEqual({ username: alice.username, deviceId: 1 });
    const f2 = await frames.next();
    expect(f2.envelope.content).toBe(c2);
    expect(f2.envelope.id > f1.envelope.id).toBe(true);
    const f3 = await frames.next();
    expect(f3).toEqual({ type: "queue-empty" });

    // ping/pong
    ws.send(JSON.stringify({ type: "ping" }));
    expect(await frames.next()).toEqual({ type: "pong" });
    ws.send('{"type": "ping"}');
    expect(await frames.next()).toEqual({ type: "pong" });

    // live push of a new envelope
    const c3 = randomContent();
    expect((await sendTo(alice, bob.username, c3, 1)).status).toBe(200);
    const live = await frames.next();
    expect(live.type).toBe("envelope");
    expect(live.envelope.content).toBe(c3);

    // ack over the socket: the queue drains -> queue-empty again
    ws.send(JSON.stringify({ type: "ack", id: f1.envelope.id }));
    ws.send(JSON.stringify({ type: "ack", id: f2.envelope.id }));
    await sleep(50);
    expect(frames.pending()).toBe(0);
    ws.send(JSON.stringify({ type: "ack", id: live.envelope.id }));
    expect(await frames.next()).toEqual({ type: "queue-empty" });

    const drained = await (await api(bob, "GET", "/v1/messages")).json<any>();
    expect(drained.envelopes).toEqual([]);

    // garbage frames are ignored
    ws.send("not json");
    ws.send(JSON.stringify({ type: "ack" }));
    ws.send(JSON.stringify({ type: "ping" }));
    expect(await frames.next()).toEqual({ type: "pong" });
    ws.close(1000, "done");
  });

  it("re-sends unacked envelopes on the next connect", async () => {
    const alice = await registerUser("alice");
    const bob = await registerUser("bob");
    const c1 = randomContent();
    expect((await sendTo(alice, bob.username, c1)).status).toBe(200);
    const first = await connectWs(bob);
    expect((await first.frames.next()).envelope.content).toBe(c1);
    expect(await first.frames.next()).toEqual({ type: "queue-empty" });
    first.ws.close(1000, "bye");
    await sleep(50);

    const second = await connectWs(bob);
    expect((await second.frames.next()).envelope.content).toBe(c1);
    expect(await second.frames.next()).toEqual({ type: "queue-empty" });
    second.ws.close(1000, "bye");
  });

  it("delivers unidentified sends over the socket without a from field", async () => {
    const bob = await registerUser("bob");
    const { ws, frames } = await connectWs(bob);
    expect(await frames.next()).toEqual({ type: "queue-empty" });
    const content = randomContent();
    const res = await SELF.fetch(`${BASE}/v1/messages/${bob.username}`, {
      method: "POST",
      headers: { "Unidentified-Access": bob.deliveryTokenB64, "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [{ destinationDeviceId: 1, type: 4, content }], timestamp: 9 }),
    });
    expect(res.status).toBe(200);
    const frame = await frames.next();
    expect(frame.envelope.content).toBe(content);
    expect(frame.envelope.from).toBeUndefined();
    ws.close(1000);
  });
});
