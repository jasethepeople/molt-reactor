const CACHE_NAME = "spotsignal-shell-v2";
const SHELL = [
  "/",
  "/app.js",
  "/styles.css",
  "/manifest.webmanifest",
  "/icon.svg",
  "/pow-worker.js",
  "/vendor/leaflet.js",
  "/vendor/leaflet.css"
];

self.addEventListener("install", event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin || url.pathname.startsWith("/api/")) return;
  if (!SHELL.includes(url.pathname)) return;
  event.respondWith(caches.match(request).then(cached => cached ?? fetch(request)));
});
