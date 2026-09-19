// Full-stack end-to-end test: real Worker (wrangler dev, local Durable
// Objects + R2), real client build, real Chromium. Three people register,
// talk, share a photo, form a group, reload, and compare safety numbers.
//
//   node e2e/run.mjs
//
// Needs the client's Playwright dev dependency (client/node_modules/playwright)
// and Chromium at /opt/pw-browsers/chromium or PLAYWRIGHT_CHROMIUM.

import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(ROOT, "client", "package.json"));
const { chromium } = require("playwright");

/* One origin, because that is what deploys: the Worker serves the app as well
   as the API. Testing them on two ports would exercise a topology nobody
   runs, and would hide any same-origin assumption the app makes. */
const WORKER_PORT = 8791;
const API = `http://127.0.0.1:${WORKER_PORT}`;
const APP = `${API}/`;
const BOOTSTRAP = "e2e-bootstrap-invite";
const SHOTS = path.join(ROOT, "e2e", "screenshots");
fs.mkdirSync(SHOTS, { recursive: true });

const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (ok, label) => { console.log((ok ? "PASS " : "FAIL ") + label); if (!ok) failures++; };

/* Long-running servers are started from their real binaries, not through npx,
   and in their own process group. Going through npx leaves the actual server
   alive when the wrapper is killed: a stale client server then keeps the port
   and the next run silently tests an old build, which is exactly what happened. */
function run(bin, args, cwd, env = {}) {
  const p = spawn(bin, args, {
    cwd,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1", ...env },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  p.stdout.on("data", (d) => { if (process.env.E2E_VERBOSE) process.stdout.write(`[${path.basename(bin)}] ${d}`); });
  p.stderr.on("data", (d) => { if (process.env.E2E_VERBOSE) process.stderr.write(`[${path.basename(bin)}] ${d}`); });
  procs.push(p);
  return p;
}

/** Kills a server and every process it spawned. */
function stop(p) {
  try { process.kill(-p.pid, "SIGTERM"); } catch { try { p.kill("SIGTERM"); } catch { /* already gone */ } }
}

/** Refuses to run against a port something else is already serving. */
async function requireFreePort(port, what) {
  let inUse = false;
  try {
    await fetch(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(1500) });
    inUse = true;
  } catch { /* nothing listening: good */ }
  if (inUse) {
    throw new Error(
      `port ${port} is already serving something: a previous run's ${what} is still alive. ` +
      `Kill it first, otherwise this test would quietly check a stale build.`,
    );
  }
}
async function waitFor(url, ms = 60000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    try { const r = await fetch(url); if (r.ok || r.status === 404) return; } catch {}
    await sleep(500);
  }
  throw new Error("timeout waiting for " + url);
}
function sh(cmd, args, cwd, env = {}) {
  return new Promise((res, rej) => {
    const p = spawn(cmd, args, { cwd, env: { ...process.env, ...env }, stdio: "inherit" });
    p.on("exit", (c) => (c === 0 ? res() : rej(new Error(`${cmd} ${args.join(" ")} exited ${c}`))));
  });
}

// ---- boot the stack
// A fresh Durable Object store per run, so the test is repeatable: local
// wrangler state otherwise persists between runs and the second one fails
// with "username is already registered".
const STATE = fs.mkdtempSync(path.join(os.tmpdir(), "pm-e2e-state-"));
fs.writeFileSync(path.join(ROOT, "worker", ".dev.vars"),
  `BOOTSTRAP_INVITE=${BOOTSTRAP}\nALLOWED_ORIGINS=${APP.replace(/\/$/, "")}\nVAPID_SUBJECT=mailto:e2e@example.com\n`);
await requireFreePort(WORKER_PORT, "worker");
// The Worker serves client/dist, so the app is built before it starts. No
// VITE_API_URL: the app should find the server at its own origin.
await sh(path.join(ROOT, "client", "node_modules", ".bin", "vite"), ["build"], path.join(ROOT, "client"));
console.log("client built");
run(path.join(ROOT, "worker", "node_modules", ".bin", "wrangler"),
    ["dev", "--local", "--port", String(WORKER_PORT), "--persist-to", STATE],
    path.join(ROOT, "worker"));
await waitFor(`${API}/v1/health`);
await waitFor(APP);
console.log("worker up, serving both the API and the app");

const exe = process.env.PLAYWRIGHT_CHROMIUM || (fs.existsSync("/opt/pw-browsers/chromium") ? "/opt/pw-browsers/chromium" : undefined);
const browser = await chromium.launch(exe ? { executablePath: exe } : {});
const pageErrors = [];

async function person(name, viewport = { width: 1200, height: 800 }) {
  const ctx = await browser.newContext({ viewport, permissions: [] });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => pageErrors.push(`${name}: ${e.message}`));
  page.on("console", (m) => { if (m.type() === "error") pageErrors.push(`${name}: ${m.text()}`); });
  return page;
}

// Selectors are the UI's data-test attributes; keep this list in sync with client/src/ui.
const S = await import("./selectors.mjs").then((m) => m.default);

try {
  const alice = await person("alice");
  await alice.goto(APP);
  await S.register(alice, { username: "alice", invite: BOOTSTRAP, name: "Alice" });
  check(await S.isSignedIn(alice, "alice"), "Alice registers with the bootstrap invite");

  const invite = await S.mintInvite(alice);
  check(/^[A-Za-z0-9_-]{8,}$/.test(invite.code), "Alice mints an invite code");

  const bob = await person("bob");
  await bob.goto(invite.link || APP);
  await S.register(bob, { username: "bob", invite: invite.code, name: "Bob" });
  check(await S.isSignedIn(bob, "bob"), "Bob registers with Alice's invite");

  const bob2 = await person("bob-dup");
  await bob2.goto(APP);
  const dupInvite = await S.mintInvite(alice);
  const err = await S.registerExpectError(bob2, { username: "bob", invite: dupInvite.code, name: "Bob again" });
  check(/taken|exists|already|registered|409/i.test(err), "duplicate username is refused (" + err + ")");

  await S.addContact(alice, "bob");
  await S.openChat(alice, "bob");
  await S.sendText(alice, "hello bob, first message is a prekey message");
  await S.openChat(bob, "alice");
  check(await S.seesText(bob, "hello bob, first message"), "Bob receives Alice's first message");
  await S.sendText(bob, "hi alice, this one rides the ratchet");
  check(await S.seesText(alice, "rides the ratchet"), "Alice receives Bob's reply");
  check(await S.ownMessageStatus(alice, "hello bob") !== "failed", "Alice's message is not marked failed");

  await S.sendImage(bob, path.join(ROOT, "e2e", "photo.png"));
  check(await S.seesImage(alice), "Alice receives Bob's photo (encrypted attachment via R2)");

  const snA = await S.safetyNumber(alice, "bob");
  const snB = await S.safetyNumber(bob, "alice");
  check(snA.length === 60 && snA === snB, "safety numbers match on both sides");

  const carol = await person("carol");
  const invite2 = await S.mintInvite(bob);
  await carol.goto(APP);
  await S.register(carol, { username: "carol", invite: invite2.code, name: "Carol" });
  await S.addContact(alice, "carol");
  await S.createGroup(alice, "Family", ["bob", "carol"]);
  await S.openChat(alice, "Family");
  await S.sendText(alice, "welcome to the family group");
  await S.openChat(bob, "Family");
  await S.openChat(carol, "Family");
  check(await S.seesText(bob, "welcome to the family group") && await S.seesText(carol, "welcome to the family group"), "group message fans out to Bob and Carol");
  await S.sendText(carol, "carol here");
  check(await S.seesText(alice, "carol here") && await S.seesText(bob, "carol here"), "Carol's group message reaches Alice and Bob");

  await alice.reload();
  await S.openChat(alice, "bob");
  check(await S.seesText(alice, "rides the ratchet"), "Alice's history survives a reload");
  // Bob was last looking at the group; send from his direct chat with Alice,
  // or this goes to the group and Alice never sees it in the chat she has open.
  await S.openChat(bob, "alice");
  await S.sendText(bob, "after your reload");
  check(await S.seesText(alice, "after your reload"), "the session survives a reload and new messages still arrive");

  await alice.screenshot({ path: path.join(SHOTS, "desktop.png") });
  const mob = await person("mobile", { width: 390, height: 780 });
  await mob.goto(invite.link || APP);
  const invite3 = await S.mintInvite(alice);
  await S.register(mob, { username: "dana", invite: invite3.code, name: "Dana" });
  await S.addContact(mob, "alice");
  await S.openChat(mob, "alice");
  await S.sendText(mob, "hi from a phone");
  await mob.screenshot({ path: path.join(SHOTS, "mobile.png") });
  await S.openChat(alice, "dana");
  check(await S.seesText(alice, "hi from a phone"), "message from the phone layout arrives");
} catch (e) {
  failures++;
  console.log("FAIL exception:", e.stack || e.message);
} finally {
  const errs = pageErrors.filter(
    (e) => !/favicon|sw\.js|service worker/i.test(e) && !/^bob-dup:/.test(e),
  );
  check(errs.length === 0, "no page errors" + (errs.length ? ": " + errs.slice(0, 5).join(" | ") : ""));
  await browser.close();
  for (const p of procs) stop(p);
  // Leaving this behind overrides ALLOWED_ORIGINS for the worker's own tests.
  fs.rmSync(path.join(ROOT, "worker", ".dev.vars"), { force: true });
  fs.rmSync(STATE, { recursive: true, force: true });
  console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL PASSED");
  process.exit(failures ? 1 : 0);
}
