/* Service worker for Boardchestrator PWA.
 *
 * Strategy:
 *   - App shell and static assets (CSS, vendor JS, icons, manifest): cache-first
 *   - Documents (HTML pages): network-first with cache fallback
 *   - /api/*, /events/*, /mcp/*: never cached (passthrough)
 *   - Offline: show fallback notice
 */

var CACHE_NAME = 'boardchestrator-v1';

// Paths that must never be cached.
var NEVER_CACHE_PREFIXES = ['/api/', '/events', '/mcp'];

// App shell assets served from the static handler (content-hashed).
// Cache any path under /static/ except the excluded prefixes above.
function isStaticAsset(url) {
	return url.startsWith('/static/');
}

function shouldNeverCache(url) {
	for (var i = 0; i < NEVER_CACHE_PREFIXES.length; i++) {
		if (url.startsWith(NEVER_CACHE_PREFIXES[i])) {
			return true;
		}
	}
	return false;
}

// Install: pre-cache app shell assets.
self.addEventListener('install', function (event) {
	self.skipWaiting();
});

// Activate: clean up old caches.
self.addEventListener('activate', function (event) {
	event.waitUntil(
		caches.keys().then(function (names) {
			return Promise.all(
				names.filter(function (n) { return n !== CACHE_NAME; })
					.map(function (n) { return caches.delete(n); })
			);
		}).then(function () { return self.clients.claim(); })
	);
});

// Fetch: route by path type.
self.addEventListener('fetch', function (event) {
	var url = event.request.url;
	var path = new URL(url, location.href).pathname;

	// Never cache API, SSE, or MCP paths.
	if (shouldNeverCache(path)) {
		return;
	}

	// Static assets: cache-first.
	if (isStaticAsset(path)) {
		event.respondWith(cacheFirst(event.request));
		return;
	}

	// HTML documents: network-first with offline fallback.
	if (event.request.destination === 'document') {
		event.respondWith(networkFirst(event.request));
		return;
	}
});

// Cache-first: serve from cache, fall back to network then cache.
function cacheFirst(request) {
	return caches.open(CACHE_NAME).then(function (cache) {
		return cache.match(request).then(function (cached) {
			if (cached) return cached;
			return fetch(request).then(function (response) {
				if (response.ok) {
					cache.put(request, response.clone());
				}
				return response;
			}).catch(function () {
				return offlineResponse();
			});
		});
	});
}

// Network-first: try network, fall back to cache, then offline notice.
function networkFirst(request) {
	return caches.open(CACHE_NAME).then(function (cache) {
		return fetch(request).then(function (response) {
			if (response.ok) {
				cache.put(request, response.clone());
			}
			return response;
		}).catch(function () {
			return cache.match(request).then(function (cached) {
				return cached || offlineResponse();
			});
		});
	});
}

// Offline fallback HTML page.
function offlineResponse() {
	return new Response(
		'<!DOCTYPE html><html lang="en-AU"><head><meta charset="utf-8"><title>Offline</title>' +
		'<style>body{font-family:sans-serif;background:#1a1a1a;color:#e0e0e0;' +
		'display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}' +
		'.offline-box{max-width:320px;padding:2rem}.offline-box h1{font-size:1.5rem;margin-bottom:.5rem}' +
		'.offline-box p{color:#aaa}</style></head><body><div class="offline-box">' +
		'<h1>You are offline</h1><p>Reconnecting...</p></div></body></html>',
		{ status: 503, statusText: 'Service Unavailable',
		  headers: { 'Content-Type': 'text/html; charset=utf-8' } }
	);
}
