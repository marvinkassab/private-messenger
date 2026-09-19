// UI smoke test: builds the client against the mock Messenger, serves the
// build with `vite preview`, and drives it in real Chromium. No worker, no
// core — this only proves the UI shell built in client/src/ui and
// client/src/mock works end to end in a browser.
//
//   npm run test:ui   (from client/)
//   node test/ui/smoke.mjs

import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const CLIENT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const PORT = 4173;
const URL = `http://127.0.0.1:${PORT}/`;
const SHOTS = path.join(CLIENT, "test", "ui", "screenshots");
fs.mkdirSync(SHOTS, { recursive: true });

let failures = 0;
const check = (ok, label) => { console.log((ok ? "PASS " : "FAIL ") + label); if (!ok) failures++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* New accounts are shown a one-time explanation that their keys live only on
   this device, with an offer to back up. It is modal, so anything clicking
   afterwards has to get past it. */
async function dismissBackupIntro(page) {
  try {
    await page.waitForSelector('[data-test="backup-intro-later"]', { timeout: 8000 });
    await page.click('[data-test="backup-intro-later"]');
    await page.waitForSelector("dialog[open]", { state: "detached", timeout: 5000 }).catch(() => {});
  } catch {
    /* not shown: an existing account, or already dismissed */
  }
}


async function waitFor(fn, { timeout = 8000, interval = 100, label = "condition" } = {}) {
  const t0 = Date.now();
  let last;
  while (Date.now() - t0 < timeout) {
    last = await fn();
    if (last) return last;
    await sleep(interval);
  }
  throw new Error(`Timed out waiting for: ${label}`);
}
async function waitForServer(url, timeout = 30000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeout) {
    try { const r = await fetch(url); if (r.ok) return; } catch { /* not up yet */ }
    await sleep(200);
  }
  throw new Error("timeout waiting for " + url);
}

function sh(cmd, args, cwd, env = {}) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { cwd, env: { ...process.env, ...env }, stdio: "inherit" });
    p.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`${cmd} ${args.join(" ")} exited ${code}`))));
  });
}

let previewProc = null;
async function stopPreview() {
  const p = previewProc;
  previewProc = null;
  if (!p || p.exitCode !== null || p.signalCode !== null) return;
  p.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => p.once("exit", resolve)),
    sleep(2000),
  ]);
  if (p.exitCode === null && p.signalCode === null) p.kill("SIGKILL");
}

const VITE_BIN = path.join(CLIENT, "node_modules", ".bin", "vite");

async function main() {
  console.log("Building client with VITE_MOCK=1…");
  await sh(VITE_BIN, ["build", "--outDir", "dist-mock"], CLIENT, { VITE_MOCK: "1" });

  console.log("Starting vite preview…");
  // Spawn the local vite binary directly (not via `npx`): npx forks its own
  // child process for it, so a SIGTERM to the npx process never reaches the
  // actual server and it is left running after the test exits.
  previewProc = spawn(VITE_BIN, ["preview", "--outDir", "dist-mock", "--port", String(PORT), "--strictPort"], {
    cwd: CLIENT, stdio: ["ignore", "pipe", "pipe"],
  });
  previewProc.stdout.on("data", (d) => { if (process.env.SMOKE_VERBOSE) process.stdout.write(`[preview] ${d}`); });
  previewProc.stderr.on("data", (d) => { if (process.env.SMOKE_VERBOSE) process.stderr.write(`[preview] ${d}`); });
  await waitForServer(URL);
  console.log("Preview up at " + URL);

  const exe = process.env.PLAYWRIGHT_CHROMIUM || (fs.existsSync("/opt/pw-browsers/chromium") ? "/opt/pw-browsers/chromium" : undefined);
  const browser = await chromium.launch(exe ? { executablePath: exe } : {});
  const pageErrors = [];

  const ctx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
  const page = await ctx.newPage();
  page.on("pageerror", (e) => pageErrors.push(e.message));
  page.on("console", (m) => { if (m.type() === "error") pageErrors.push(m.text()); });

  try {
    await page.goto(URL);

    // ---- register ----
    await page.waitForSelector('[data-test="register-form"]', { timeout: 10000 });
    await page.fill('[data-test="register-username"]', "marvin");
    await page.fill('[data-test="register-invite"]', "SMOKE-TEST-1234");
    await page.fill('[data-test="register-displayname"]', "Marvin Kassab");
    await page.click('[data-test="register-submit"]');
    await dismissBackupIntro(page);

    // ---- seeded chats ----
    await page.waitForSelector('[data-test="chat-item"][data-title="Alice Nguyen"]', { timeout: 10000 });
    const chatCount = await page.locator('[data-test="chat-item"]').count();
    check(chatCount >= 3, `sees seeded chats (${chatCount} found)`);

    // ---- open a chat and send a text ----
    await page.click('[data-test="chat-item"][data-title="Alice Nguyen"]');
    await page.waitForSelector('[data-test="composer-input"]', { timeout: 5000 });
    const outgoing = "hello from the smoke test " + Date.now();
    await page.fill('[data-test="composer-input"]', outgoing);
    await page.click('[data-test="send-btn"]');

    const sentBubble = await waitFor(
      async () => {
        const loc = page.locator(`[data-test="message"]:has-text("${outgoing}")`);
        return (await loc.count()) > 0 ? loc.first() : null;
      },
      { label: "sent message bubble to appear" },
    );
    check(!!sentBubble, "sent message appears in the chat");

    const readStatus = await waitFor(
      async () => {
        const status = await sentBubble.locator('[data-test="msg-status"]').getAttribute("data-status");
        return status === "read" ? status : null;
      },
      { timeout: 6000, label: "message to reach read status" },
    ).catch(() => null);
    check(readStatus === "read", "message goes delivered then read (status=" + readStatus + ")");

    const peerReplied = await waitFor(
      async () => (await page.locator('[data-test="message"][data-mine="false"]').count()) > 0,
      { timeout: 6000, label: "peer reply" },
    ).catch(() => false);
    check(!!peerReplied, "the peer replies");

    // ---- reactions ----
    await sentBubble.hover();
    await sentBubble.locator('[data-test="msg-actions"]').click();
    await page.waitForSelector('[data-test="msg-menu"]', { timeout: 3000 });
    await page.locator('[data-test="react-btn"][data-emoji="👍"]').click();
    const hasReaction = await waitFor(
      async () => (await sentBubble.locator('[data-test="reaction"][data-emoji="👍"]').count()) > 0,
      { timeout: 3000, label: "reaction to appear" },
    ).catch(() => false);
    check(!!hasReaction, "adding a reaction shows it on the message");

    // ---- details: safety number + QR ----
    await page.click('[data-test="details-btn"]');
    await page.waitForSelector('[data-test="safety-number"]', { timeout: 5000 });
    const groups = await page.locator('[data-test="safety-digits"] > div').count();
    const digitsText = (await page.locator('[data-test="safety-digits"]').innerText()).replace(/\s+/g, "");
    check(groups === 12 && /^\d{60}$/.test(digitsText), `safety number is 12 groups of 5 digits (${groups} groups, ${digitsText.length} digits)`);
    const qrHtml = await page.locator('[data-test="safety-qr"]').innerHTML();
    check(qrHtml.includes("<svg"), "safety number QR code renders");
    await page.keyboard.press("Escape");
    await page.waitForSelector('[data-test="details-dialog"]', { state: "detached", timeout: 3000 }).catch(() => {});

    // ---- create a group ----
    await page.click('[data-test="new-group-btn"]');
    await page.waitForSelector('[data-test="group-form"]', { timeout: 5000 });
    await page.fill('[data-test="group-name"]', "Smoke Test Group");
    const memberBoxes = page.locator('[data-test="group-member"] input[type="checkbox"]');
    if (await memberBoxes.count()) await memberBoxes.first().check();
    await page.click('[data-test="group-submit"]');
    const groupTitle = await waitFor(
      async () => {
        const t = await page.locator('[data-test="chat-title"]').innerText().catch(() => "");
        return t === "Smoke Test Group" ? t : null;
      },
      { timeout: 5000, label: "new group to open" },
    ).catch(() => null);
    check(groupTitle === "Smoke Test Group", "creating a group opens it (title: " + groupTitle + ")");

    // ---- settings: mint an invite ----
    await page.click('[data-test="settings-btn"]');
    await page.waitForSelector('[data-test="settings-dialog"]', { timeout: 5000 });
    await page.click('[data-test="invite-mint-btn"]');
    const inviteLink = await waitFor(
      async () => {
        const t = await page.locator('[data-test="invite-link"]').innerText().catch(() => "");
        return t.startsWith("http") ? t : null;
      },
      { timeout: 5000, label: "invite link to be minted" },
    ).catch(() => null);
    check(!!inviteLink, "minting an invite shows a link (" + inviteLink + ")");

    // ---- theme toggle ----
    const before = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
    await page.click('[data-test="theme-dark"]');
    const after = await waitFor(
      async () => {
        const t = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
        return t === "dark" ? t : null;
      },
      { timeout: 2000, label: "theme to switch to dark" },
    ).catch(() => null);
    check(after === "dark" && after !== before, `theme toggle switches the page theme (was ${before}, now ${after})`);
    await page.click('[data-test="settings-done-btn"]');

    // ---- screenshots ----
    await page.screenshot({ path: path.join(SHOTS, "desktop-1200x800.png") });

    const mobCtx = await browser.newContext({ viewport: { width: 390, height: 780 } });
    const mob = await mobCtx.newPage();
    mob.on("pageerror", (e) => pageErrors.push("mobile: " + e.message));
    mob.on("console", (m) => { if (m.type() === "error") pageErrors.push("mobile: " + m.text()); });
    await mob.goto(URL);
    await mob.waitForSelector('[data-test="register-form"]', { timeout: 10000 });
    await mob.fill('[data-test="register-username"]', "mobiletester");
    await mob.fill('[data-test="register-invite"]', "SMOKE-TEST-5678");
    await mob.fill('[data-test="register-displayname"]', "Mobile Tester");
    await mob.click('[data-test="register-submit"]');
    await dismissBackupIntro(mob);
    await mob.waitForSelector('[data-test="chat-item"][data-title="Bob Okafor"]', { timeout: 10000 });
    await mob.click('[data-test="chat-item"][data-title="Bob Okafor"]');
    await mob.waitForSelector('[data-test="composer-input"]', { timeout: 5000 });
    const backVisible = await mob.locator("#btn-back").isVisible();
    check(backVisible, "mobile layout shows a back button when a chat is open");
    await mob.screenshot({ path: path.join(SHOTS, "mobile-390x780.png") });
    await mobCtx.close();
  } catch (e) {
    failures++;
    console.log("FAIL exception:", e.stack || e.message);
  } finally {
    const realErrors = pageErrors.filter((e) => !/favicon|sw\.js|service worker/i.test(e));
    check(realErrors.length === 0, "no page errors" + (realErrors.length ? ": " + realErrors.slice(0, 5).join(" | ") : ""));
    await browser.close();
    await stopPreview();
  }

  console.log(failures ? `\n${failures} FAILURE(S)` : "\nALL PASSED");
  process.exit(failures ? 1 : 0);
}

main().catch(async (e) => {
  console.error(e);
  await stopPreview();
  process.exit(1);
});
