/* Service worker: Web Push and notification clicks.
   Push payloads are intentionally empty (the server never sees plaintext),
   so the notification is generic. The app builds real previews itself while
   it is open, using the Notification API directly. */

self.addEventListener("install", () => { self.skipWaiting(); });
self.addEventListener("activate", (event) => { event.waitUntil(self.clients.claim()); });

self.addEventListener("push", (event) => {
  event.waitUntil((async () => {
    // If the app is open and visible it will show its own notification (or none).
    const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    if (clients.some((c) => c.visibilityState === "visible")) return;
    await self.registration.showNotification("New message", {
      body: "Open Private Messenger to read it.",
      icon: "/icons/icon.svg",
      badge: "/icons/icon-maskable.svg",
      tag: "pm-new-message",
      renotify: true,
      data: { url: self.registration.scope },
    });
  })());
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || self.registration.scope;
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const c of clients) {
      if ("focus" in c) { await c.focus(); return; }
    }
    if (self.clients.openWindow) await self.clients.openWindow(url);
  })());
});
