package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/a-h/templ"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// Organisation SSO enforcement in the web layer (WU-607, SPEC §7.4). Dispatch
// enforces it for actions; OrgSSOGate enforces it for the pages and partials
// that read org data directly.

// sessionActor is the user actor for a web session, carrying the session's
// sign-in provider for SSO enforcement.
func sessionActor(r *http.Request, sess auth.Session) action.Actor {
	return action.Actor{Type: action.ActorUser, ID: sess.UserID, IP: auth.ClientIP(r), AuthProviderID: sess.ProviderID,
		SessionID: action.SessionPublicID(sess.TokenHash)}
}

// requestActor is the session actor, or the anonymous "placeholder" user the
// older pages dispatch as (it is a member of nothing, so it is refused).
func requestActor(r *http.Request) action.Actor {
	if sess, ok := auth.SessionFrom(r.Context()); ok && sess.UserID != "" {
		return sessionActor(r, sess)
	}
	return action.Actor{Type: action.ActorUser, ID: "placeholder", IP: auth.ClientIP(r)}
}

// orgSSOError checks the session user against orgID's SSO requirement.
func orgSSOError(ctx context.Context, sess auth.Session, orgID string) error {
	if disp == nil || disp.DB() == nil {
		return nil
	}
	return action.CheckOrgSSO(ctx, sqlc.New(disp.DB()), orgID, sess.UserID, sess.ProviderID)
}

// pathOrg returns the org a request path is scoped to: /app/org/{id}/...
// directly, or /app/project/{id}/... and /api/project/{id}/... through the
// project. "" when the path is not org-scoped (or the project is unknown).
func pathOrg(ctx context.Context, path string) string {
	seg := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch {
	case len(seg) >= 3 && seg[0] == "app" && seg[1] == "org":
		id, err := url.PathUnescape(seg[2])
		if err != nil {
			return ""
		}
		return id
	case len(seg) >= 3 && (seg[0] == "app" || seg[0] == "api") && seg[1] == "project":
		if disp == nil || disp.DB() == nil {
			return ""
		}
		id, err := url.PathUnescape(seg[2])
		if err != nil {
			return ""
		}
		org, err := sqlc.New(disp.DB()).FindProjectOrg(ctx, id)
		if err != nil {
			return ""
		}
		return org
	}
	return ""
}

// OrgSSOGate refuses session users who are not signed in through an org's
// identity provider every org-scoped page and partial of an organisation
// that requires single sign-on. API-key requests are not gated (SPEC §7.4).
// Mount it after the session middleware.
func OrgSSOGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := auth.SessionFrom(r.Context())
		if !ok || sess.UserID == "" {
			next.ServeHTTP(w, r)
			return
		}
		if _, isKey := auth.APIKeyActorFrom(r.Context()); isKey {
			next.ServeHTTP(w, r)
			return
		}
		orgID := pathOrg(r.Context(), r.URL.Path)
		if orgID == "" {
			next.ServeHTTP(w, r)
			return
		}
		err := orgSSOError(r.Context(), sess, orgID)
		var sso action.ErrSSORequired
		switch {
		case errors.As(err, &sso):
			RenderSSORequired(w, r, sso)
		case err != nil:
			ref := idpRef()
			slog.Error("org sso gate", "ref", ref, "err", err)
			renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

// ssoRequiredURL is the sign-in link for e: the org's first enabled
// provider, returning to the current page (GET) or the org's home.
func ssoRequiredURL(r *http.Request, e action.ErrSSORequired) (href, name string) {
	if len(e.Providers) == 0 {
		return "", ""
	}
	id := e.Providers[0]
	name = id
	if src := identityCfg().providers; src != nil {
		if ps, err := src.Providers(r.Context()); err == nil {
			for _, p := range ps {
				if p.ID == id {
					name = p.DisplayName
				}
			}
		}
	}
	back := "/app/org/" + url.PathEscape(e.OrgID) + "/settings"
	if r.Method == http.MethodGet {
		back = r.URL.RequestURI()
	}
	q := url.Values{}
	if rt := auth.SafeReturnTo(back); rt != auth.DefaultReturnTo {
		q.Set("return_to", rt)
	}
	href = "/auth/" + url.PathEscape(id)
	if len(q) > 0 {
		href += "?" + q.Encode()
	}
	return href, name
}

// RenderSSORequired is the "This organisation requires single sign-on"
// page (403) with a button to sign in through the org's provider.
func RenderSSORequired(w http.ResponseWriter, r *http.Request, e action.ErrSSORequired) {
	s := shellData(r, "Single sign-on required", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	href, name := ssoRequiredURL(r, e)
	const title = "This organisation requires single sign-on"
	var c templ.Component
	if href == "" {
		c = views.ErrorPage(s, http.StatusForbidden, title,
			"This organisation only allows access through its own identity provider, and none is available right now. Contact your organisation owner.")
	} else {
		// href is /auth/<escaped id> plus a SafeReturnTo-validated return_to.
		c = views.ErrorPageWithLink(s, http.StatusForbidden, title,
			"This organisation only allows access through its own identity provider. Sign in with "+name+" to continue.",
			templ.SafeURL(href), "Sign in with "+name)
	}
	if err := c.Render(r.Context(), w); err != nil {
		slog.Error("render sso required", "err", err)
	}
}

// writeSSORequiredPlain answers an API-style (JSON/HTMX) request refused by
// enforcement: 403 with fixed copy; HTMX follows HX-Redirect to the sign-in URL.
func writeSSORequiredPlain(w http.ResponseWriter, r *http.Request, e action.ErrSSORequired) {
	href, _ := ssoRequiredURL(r, e)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if href != "" {
		w.Header().Set("HX-Redirect", href)
	}
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("This organisation requires single sign-on. Sign in through its identity provider.\n"))
}

// ssoFilter drops items from organisations whose SSO requirement the
// session does not meet (cross-org reads such as search). A lookup failure
// drops the item too.
func ssoFilter[T any](ctx context.Context, sess auth.Session, items []T, orgOf func(T) string) []T {
	verdict := map[string]bool{}
	out := items[:0]
	for _, it := range items {
		org := orgOf(it)
		ok, seen := verdict[org]
		if !seen {
			ok = orgSSOError(ctx, sess, org) == nil
			verdict[org] = ok
		}
		if ok {
			out = append(out, it)
		}
	}
	return out
}
