// Renders the SVG icons to PNG. Apple's home-screen icon does not support
// SVG at all, and Android's install prompt wants a 192 and a 512 PNG, so an
// SVG-only manifest installs with a blank icon on a phone.
import { chromium } from "/home/user/private-messenger/client/node_modules/playwright/index.mjs";
import fs from "node:fs";
import path from "node:path";

const DIR = "/home/user/private-messenger/client/public/icons";
const jobs = [
  { svg: "icon.svg", out: "icon-192.png", size: 192 },
  { svg: "icon.svg", out: "icon-512.png", size: 512 },
  { svg: "icon.svg", out: "apple-touch-icon.png", size: 180, background: "#2a78d6" },
  { svg: "icon-maskable.svg", out: "icon-maskable-512.png", size: 512 },
];

const browser = await chromium.launch({ executablePath: "/opt/pw-browsers/chromium" });
for (const job of jobs) {
  const svg = fs.readFileSync(path.join(DIR, job.svg), "utf8");
  const page = await browser.newPage({
    viewport: { width: job.size, height: job.size },
    deviceScaleFactor: 1,
  });
  // Apple composites its icon onto an opaque background and rounds the
  // corners itself, so that one is drawn square and filled.
  await page.setContent(
    `<!doctype html><meta charset="utf-8">
     <style>html,body{margin:0;padding:0;width:${job.size}px;height:${job.size}px;
       background:${job.background ?? "transparent"};}
       svg{display:block;width:${job.size}px;height:${job.size}px}</style>${svg}`,
  );
  await page.screenshot({
    path: path.join(DIR, job.out),
    omitBackground: !job.background,
  });
  await page.close();
  const bytes = fs.statSync(path.join(DIR, job.out)).size;
  console.log(`${job.out}  ${job.size}x${job.size}  ${bytes} bytes`);
}
await browser.close();
