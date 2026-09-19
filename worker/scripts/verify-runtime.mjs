// Boots the Worker on the real workerd runtime and checks it answers.
//
// This exists because the test suite cannot catch this class of failure: the
// vitest pool runs the Worker with a Node compatibility shim, so a dependency
// that reads `__dirname` at import time passes every test and then refuses to
// start on Cloudflare. That happened once already. Run this before deploying.

import { spawn } from "node:child_process";

const PORT = Number(process.env.PORT || 8795);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const child = spawn("npx", ["wrangler", "dev", "--local", "--port", String(PORT)], {
  env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" },
  stdio: ["ignore", "pipe", "pipe"],
});
let log = "";
child.stdout.on("data", (d) => (log += d));
child.stderr.on("data", (d) => (log += d));

let ok = false;
for (let i = 0; i < 60 && !ok; i++) {
  await sleep(1000);
  try {
    const res = await fetch(`http://127.0.0.1:${PORT}/v1/health`);
    if (res.ok) {
      const body = await res.json();
      ok = body && body.ok === true;
    }
  } catch {
    /* not up yet */
  }
}

child.kill("SIGTERM");
await sleep(300);

if (ok) {
  console.log("PASS the Worker starts on the workerd runtime and /v1/health responds");
  process.exit(0);
}
console.error("FAIL the Worker did not start on the workerd runtime.\n");
const interesting = log
  .split("\n")
  .filter((l) => /error|ReferenceError|__dirname|failed to start/i.test(l))
  .slice(0, 10);
console.error(interesting.join("\n") || log.slice(-2000));
process.exit(1);
