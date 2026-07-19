package web

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// Routes mounts the browser-facing routes: embedded static assets and the
// app shell.
func Routes(r chi.Router) {
	r.Handle("/static/*", StaticHandler())
	r.Get("/app", handleAppShell)
}

// shellData assembles the layout inputs for a request. The nonce comes from
// requestNonce until WU-005's CSP middleware provides the real one.
func shellData(r *http.Request, title, active string) views.Shell {
	return views.Shell{
		Title: title,
		Nonce: requestNonce(r),
		Assets: views.ShellAssets{
			AppCSS: AssetURL("app.css"),
			HTMX:   AssetURL("vendor/htmx.min.js"),
			Alpine: AssetURL("vendor/alpine-csp.min.js"),
			AppJS:  AssetURL("app.js"),
		},
		Active: active,
	}
}

// requestNonce returns the CSP nonce for the request. Placeholder until
// WU-005: generates a fresh random value per request with the same shape the
// CSP middleware will use (128-bit, base64), but no CSP header references it
// yet. WU-005 replaces the body of this function with a context lookup.
func requestNonce(_ *http.Request) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Unreachable: crypto/rand.Read is documented never to fail on
		// Go ≥1.24. The branch exists only to satisfy errcheck honestly.
		panic("web: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

func handleAppShell(w http.ResponseWriter, r *http.Request) {
	s := shellData(r, "Home", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.Home(s).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}
