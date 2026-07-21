package web

import (
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

func handleRoot(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Home", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if auth.IsAuthenticated(r.Context()) {
		http.Redirect(w, r, "/app", http.StatusSeeOther)
		return
	}
	// Unauthenticated users see the landing page
	if err := views.LandingPage(s).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// shellData assembles the layout inputs for a request. The nonce and CSRF
// token are sourced from the request context, populated by the CSP and session
// middleware (WU-005).
func shellData(r *http.Request, title, active string) views.Shell {
	return views.Shell{
		Title: title,
		Nonce: auth.Nonce(r.Context()),
		CSRF:  auth.CSRFFrom(r.Context()),
		Assets: views.ShellAssets{
			AppCSS: AssetURL("app.css"),
			HTMX:   AssetURL("vendor/htmx.min.js"),
			Alpine: AssetURL("vendor/alpine-csp.min.js"),
			AppJS:  AssetURL("app.js"),
			// Served at the stable root path (not content-hashed) so the
			// worker's scope is the whole origin, not just /static/. A
			// hashed URL would also orphan the previous worker each build.
			SW: "/sw.js",
		},
		Active: active,
	}
}

func handleAppShell(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Home", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.Home(s).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// serveEmbedded copies an embedded static file to the response, reporting a
// 500 on read failure. Used for the small set of assets served at fixed root
// paths (manifest, service worker) rather than the content-hashed /static tree.
func serveEmbedded(w http.ResponseWriter, name string) {
	f, err := staticFS.Open(name)
	if err != nil {
		http.Error(w, "not found", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	if _, err := io.Copy(w, f); err != nil {
		// Client went away mid-stream; nothing useful to do but stop.
		return
	}
}

// handleManifest serves the PWA manifest with the correct MIME type.
// Browsers require application/manifest+json for installation.
func handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/manifest+json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	// manifest.json is served unhashed at /manifest.json — the conventional
	// path browsers expect for the manifest link.
	serveEmbedded(w, "static/manifest.json")
}

// handleServiceWorker serves the service worker at the stable root path
// /sw.js. Serving from the origin root (rather than a hashed /static/ URL)
// gives the worker default scope of "/", so it can intercept navigations to
// every page, not just assets under /static/. Service-Worker-Allowed is set
// defensively for callers that register with an explicit wider scope.
func handleServiceWorker(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	// Revalidate every load so a new worker ships promptly; the browser's
	// own byte-comparison update check does the rest.
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Service-Worker-Allowed", "/")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	serveEmbedded(w, "static/sw.js")
}

// Routes mounts the browser-facing routes: embedded static assets and the
// app shell.
func Routes(r chi.Router) {
	r.Handle("/static/*", StaticHandler())
	r.Get("/manifest.json", handleManifest)
	r.Get("/sw.js", handleServiceWorker)
	r.Get("/", handleRoot)
	r.Get("/app", handleAppShell)
}
