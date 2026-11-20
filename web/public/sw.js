// The service worker: lets the app open, and show what it last saw, when the node can't be reached.
//
// Network first, always: online, nothing changes. Each successful GET (the app's files, the API's
// answers) is kept; offline, the kept answer is served instead. Navigations fall back to the last app
// page, as every route is the same SPA. Streams (/api/stream) and live rooms (WebSockets) pass through:
// they only make sense live. Writes aren't cached; the doc page keeps unsent edits itself (web/src/Doc.tsx).

const CACHE = "bisonbase-offline"; // also in web/src/api.ts, which clears it on signing out
const SHELL = "/__app";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== location.origin || url.pathname === "/api/stream") return;
  e.respondWith(
    (async () => {
      const cache = await caches.open(CACHE);
      try {
        const res = await fetch(req);
        if (res.ok) {
          e.waitUntil(cache.put(req, res.clone()));
          if (req.mode === "navigate") e.waitUntil(cache.put(SHELL, res.clone()));
        }
        return res;
      } catch (err) {
        const hit = (await cache.match(req)) ?? (req.mode === "navigate" ? await cache.match(SHELL) : undefined);
        if (hit) return hit;
        throw err;
      }
    })(),
  );
});
