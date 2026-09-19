import { chromium } from "/home/user/private-messenger/client/node_modules/playwright/index.mjs";
import { spawn } from "node:child_process";
const sleep = ms => new Promise(r => setTimeout(r, ms));
const pv = spawn("/home/user/private-messenger/client/node_modules/.bin/vite",
  ["preview", "--outDir", "dist-mock", "--port", "4190", "--strictPort"],
  { cwd: "/home/user/private-messenger/client", stdio: "ignore", detached: true });
for (let i = 0; i < 40; i++) { await sleep(500); try { if ((await fetch("http://127.0.0.1:4190/")).ok) break; } catch {} }
const br = await chromium.launch({ executablePath: "/opt/pw-browsers/chromium" });
const ctx = await br.newContext({ viewport: { width: 1200, height: 800 }, acceptDownloads: true });
const p = await ctx.newPage();
const errs = []; p.on("pageerror", e => errs.push(e.message));
let fail = 0; const ok = (c, l) => { console.log((c ? "PASS " : "FAIL ") + l); if (!c) fail++; };
try {
  await p.goto("http://127.0.0.1:4190/");
  await p.waitForSelector('[data-test="register-form"]');
  await p.fill('[data-test="register-username"]', "marvin");
  await p.fill('[data-test="register-invite"]', "x");
  await p.fill('[data-test="register-displayname"]', "Marvin");
  await p.click('[data-test="register-submit"]');

  await p.waitForSelector('[data-test="backup-intro-later"]', { timeout: 15000 });
  const text = await p.textContent("dialog[open]");
  ok(/device is lost|cleared/i.test(text), "new users are told their keys live only on this device");
  ok(/no password reset|nothing to/i.test(text), "and that there is no account recovery");

  await p.click('[data-test="backup-intro-later"]');
  await p.waitForSelector('[data-test="backup-reminder"]', { timeout: 10000 });
  ok(true, "declining leaves a standing reminder in the chat list");

  // The reminder must actually produce a file.
  await p.click('[data-test="backup-reminder-action"]');
  await p.waitForSelector("dialog[open] input[type=password]", { timeout: 10000 });
  await p.fill("dialog[open] input[type=password]", "correct horse battery");
  const [download] = await Promise.all([
    p.waitForEvent("download", { timeout: 15000 }),
    p.click('dialog[open] button[type=submit], dialog[open] .btn.primary'),
  ]);
  const name = download.suggestedFilename();
  ok(/^private-messenger-backup-\d{4}-\d{2}-\d{2}\.json$/.test(name), "it downloads a dated backup file (" + name + ")");

  await sleep(800);
  ok(await p.$('[data-test="backup-reminder"]') === null, "the reminder disappears once a backup exists");

  await p.click('[data-test="settings-btn"]');
  await p.waitForSelector('[data-test="backup-status"]');
  const status = await p.textContent('[data-test="backup-status"]');
  ok(/last backup/i.test(status), "settings shows when the last backup was made (" + status.slice(0, 40) + ")");

  // And it survives a reload, so people are not nagged again.
  await p.reload();
  await p.waitForSelector('[data-test="me-card"]', { timeout: 15000 });
  await sleep(600);
  ok(await p.$('[data-test="backup-reminder"]') === null, "and stays gone after a reload");
} catch (e) { fail++; console.log("FAIL exception: " + e.message.slice(0, 200)); }
ok(errs.length === 0, "no page errors" + (errs.length ? ": " + errs[0].slice(0, 120) : ""));
await br.close(); try { process.kill(-pv.pid, "SIGTERM"); } catch {}
console.log(fail ? `\n${fail} FAILURE(S)` : "\nALL PASSED");
process.exit(fail ? 1 : 0);
