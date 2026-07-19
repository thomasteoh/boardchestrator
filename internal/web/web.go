package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// Routes mounts the browser-facing routes: embedded static assets and the
// app shell.
func Routes(r chi.Router) {
	r.Handle("/static/*", StaticHandler())
	r.Get("/app", handleAppShell)
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
