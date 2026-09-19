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
  /* The Worker serves this page as well as the API, so by default the server
     is wherever the app was loaded from. That needs no configuration and
     makes every request same-origin. VITE_API_URL is only for the cases where
     they are apart: the dev server, or the app hosted somewhere else. */
  const sameOrigin = location.origin;
  const baseUrl = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? "http://127.0.0.1:8787" : sameOrigin);
  return createMessenger({
    baseUrl,
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
