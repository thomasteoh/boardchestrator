package auth

import (
	"html"
	"net/http"
)

// ContinueTo sends the browser on to dest at the end of a form submission.
//
// Every page carries CSP form-action 'self', and browsers apply form-action
// to each redirect of a form's navigation (GET forms too). A 303 from a form
// handler to an identity provider (end-session, SLO, authorize) is therefore
// blocked by the browser, and so is a 303 to a same-origin route that then
// redirects to the provider. Found with a real browser in WU-614; HTTP-level
// tests could not see it.
//
// ContinueTo answers 200 with a small page whose meta refresh starts a new
// navigation, which form-action does not govern, plus a link for browsers
// that ignore meta refresh. dest must come from configuration or a
// validated same-origin path, never from the request as is.
func ContinueTo(w http.ResponseWriter, dest string) {
	esc := html.EscapeString(dest)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html><html lang="en-AU"><head><meta charset="utf-8">` +
		`<meta http-equiv="refresh" content="0;url=` + esc + `">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<link rel="icon" type="image/svg+xml" href="/favicon.svg"><title>Continuing · Boardchestrator</title></head><body>` +
		`<p>Continuing&hellip; <a href="` + esc + `" data-bc-continue>Continue</a></p>` +
		`</body></html>`))
}
