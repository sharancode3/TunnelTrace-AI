/**
 * TunnelTrace AI Conservative Security Service Worker (PWA Shell Only)
 *
 * CRITICAL SECURITY POLICY:
 * In accordance with Stage-9 non-negotiables, this service worker caches ONLY
 * the static application shell, versioned JS/CSS, and UI icon assets.
 *
 * ABSOLUTELY NEVER CACHE:
 * - /api/ requests (sensitive analysis, protocol observations, SAs, findings, threats)
 * - Raw PCAP or frame bytes
 * - Generated security reports (HTML or PDF)
 * - WebSocket data
 */

const CACHE_NAME = "tunneltrace-shell-v1";
const STATIC_ASSETS = [
  "/analyses",
  "/manifest.json",
  "/globals.css",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch(() => {
        // Pre-caching failure should not block install in development
      });
    })
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // STRICT PRIVACY BYPASS: Never intercept or store API calls, report downloads, or WebSockets
  if (
    url.pathname.startsWith("/api/") ||
    url.pathname.includes("/reports/") ||
    url.pathname.includes("/captures/") ||
    url.pathname.includes("/ws/") ||
    event.request.method !== "GET"
  ) {
    return; // Pass through directly to network
  }

  // Network-first for HTML pages, cache-first for static immutable assets
  if (
    url.pathname.startsWith("/_next/static/") ||
    url.pathname.endsWith(".css") ||
    url.pathname.endsWith(".js") ||
    url.pathname.endsWith(".png") ||
    url.pathname.endsWith(".svg")
  ) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        return fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseToCache);
            });
          }
          return networkResponse;
        });
      })
    );
    return;
  }

  // For navigational shell pages, try network first, then cached shell
  event.respondWith(
    fetch(event.request).catch(() => {
      return caches.match(event.request).then((cached) => {
        if (cached) return cached;
        return caches.match("/analyses");
      });
    })
  );
});
