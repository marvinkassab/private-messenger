/* Entry point: picks the mock or real Messenger implementation, registers the
   service worker, and boots the UI. */

import type { Messenger } from "./types";
import { bootApp } from "./ui/app";
import "./ui/styles.css";

async function createMessengerInstance(): Promise<Messenger> {
  if (import.meta.env.VITE_MOCK === "1") {
    const { createMockMessenger } = await import("./mock/mockMessenger");
    return createMockMessenger();
  }
  const { createMessenger } = await import("./core/index");
  return createMessenger({
    baseUrl: import.meta.env.VITE_API_URL || "http://127.0.0.1:8787",
    appUrl: location.origin + location.pathname,
  });
}

async function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  try { await navigator.serviceWorker.register("/sw.js"); }
  catch { /* not fatal: the app still works without push notifications */ }
}

async function main() {
  await registerServiceWorker();
  const messenger = await createMessengerInstance();
  await bootApp(messenger);
}

main();
