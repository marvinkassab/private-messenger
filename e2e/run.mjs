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
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(path.join(ROOT, "client", "package.json"));
const { chromium } = require("playwright");

const WORKER_PORT = 8791;
const CLIENT_PORT = 4180;
const API = `http://127.0.0.1:${WORKER_PORT}`;
const APP = `http://127.0.0.1:${CLIENT_PORT}/`;
const BOOTSTRAP = "e2e-bootstrap-invite";
const SHOTS = path.join(ROOT, "e2e", "screenshots");
fs.mkdirSync(SHOTS, { recursive: true });

const procs = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (ok, label) => { console.log((ok ? "PASS " : "FAIL ") + label); if (!ok) failures++; };

function run(cmd, args, cwd, env = {}) {
  const p = spawn(cmd, args, { cwd, env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1", ...env }, stdio: ["ignore", "pipe", "pipe"] });
  p.stdout.on("data", (d) => { if (process.env.E2E_VERBOSE) process.stdout.write(`[${args[0]}] ${d}`); });
  p.stderr.on("data", (d) => { if (process.env.E2E_VERBOSE) process.stderr.write(`[${args[0]}] ${d}`); });
  procs.push(p);
  return p;
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
fs.writeFileSync(path.join(ROOT, "worker", ".dev.vars"),
  `BOOTSTRAP_INVITE=${BOOTSTRAP}\nALLOWED_ORIGINS=${APP.replace(/\/$/, "")}\nVAPID_SUBJECT=mailto:e2e@example.com\n`);
run("npx", ["wrangler", "dev", "--local", "--port", String(WORKER_PORT)], path.join(ROOT, "worker"));
await waitFor(`${API}/v1/health`);
console.log("worker up");
await sh("npx", ["vite", "build", "--outDir", "dist-e2e"], path.join(ROOT, "client"), { VITE_API_URL: API });
run("npx", ["vite", "preview", "--outDir", "dist-e2e", "--port", String(CLIENT_PORT), "--strictPort"], path.join(ROOT, "client"));
await waitFor(APP);
console.log("client up");

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
  const err = await S.registerExpectError(bob2, { username: "bob", invite: BOOTSTRAP, name: "Bob again" });
  check(/taken|exists|409/i.test(err), "duplicate username is refused (" + err + ")");

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
  await S.sendText(bob, "after your reload");
  check(await S.seesText(alice, "after your reload"), "session survives a reload");

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
  const errs = pageErrors.filter((e) => !/favicon|sw\.js|service worker/i.test(e));
  check(errs.length === 0, "no page errors" + (errs.length ? ": " + errs.slice(0, 5).join(" | ") : ""));
  await browser.close();
  for (const p of procs) p.kill("SIGTERM");
  // Leaving this behind overrides ALLOWED_ORIGINS for the worker's own tests.
  fs.rmSync(path.join(ROOT, "worker", ".dev.vars"), { force: true });
  console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL PASSED");
  process.exit(failures ? 1 : 0);
}
