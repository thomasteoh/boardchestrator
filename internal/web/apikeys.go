package web

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// API keys (WU-109; lifecycle WU-613, SPEC §7.10): the caller's own keys for
// an org at /app/org/{orgID}/apikeys, and every key bound to the org for its
// owners at /app/org/{orgID}/settings/api-keys. Everything is dispatched as
// the session user.

var apiKeyNotices = map[string]string{
	"revoked": "API key revoked. It no longer works.",
}

var apiKeyErrors = map[string]string{
	"name":      "Give the key a name of up to 100 characters.",
	"expiry":    "Choose an expiry from the list.",
	"scope":     "Enter the scope as action names separated by commas.",
	"not_found": "That API key isn't on this organisation or is already revoked.",
	"duplicate": "You already have a key with that name in this organisation.",
}

func apiKeyErrorCode(err error) string {
	switch {
	case errors.Is(err, action.ErrAPIKeyName):
		return "name"
	case errors.Is(err, action.ErrAPIKeyExpiry):
		return "expiry"
	case errors.Is(err, action.ErrAPIKeyScope):
		return "scope"
	case errors.Is(err, action.ErrAPIKeyNotFound):
		return "not_found"
	case err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed"):
		return "duplicate"
	}
	return ""
}

// apiKeyActor is the session user; anonymous GETs go to /login and back.
func apiKeyActor(w http.ResponseWriter, r *http.Request, back string) (action.Actor, bool) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		if r.Method == http.MethodGet {
			// back is a fixed /app/org/<escaped id>/... path.
			http.Redirect(w, r, auth.LoginURLFor(back), http.StatusSeeOther) //nolint:gosec // G710: fixed path, return_to validated by auth.SafeReturnTo
		} else {
			renderStatusPage(w, r, http.StatusForbidden, "Forbidden", "You must be signed in.")
		}
		return action.Actor{}, false
	}
	if disp == nil {
		http.Error(w, "dispatcher not configured", http.StatusInternalServerError)
		return action.Actor{}, false
	}
	return sessionActor(r, sess), true
}

// apiKeyDenied renders a dispatch refusal that is not the action's own.
func apiKeyDenied(w http.ResponseWriter, r *http.Request, err error) bool {
	var sso action.ErrSSORequired
	if errors.As(err, &sso) {
		RenderSSORequired(w, r, sso)
		return true
	}
	if errors.Is(err, action.ErrForbidden) || errors.Is(err, action.ErrScope) {
		renderStatusPage(w, r, http.StatusForbidden, "Forbidden",
			"You need permission to manage API keys for this organisation.")
		return true
	}
	return false
}

func apiKeyRows(keys []action.APIKeyView, withOwner bool) []views.APIKeyRow {
	rows := make([]views.APIKeyRow, 0, len(keys))
	for _, k := range keys {
		row := views.APIKeyRow{
			ID: k.ID, Name: k.Name, Prefix: k.Prefix, Scope: k.Scope, Status: k.Status,
			CreatedAt: displayDate(k.CreatedAt), LastUsed: displayDate(k.LastUsedAt), Expires: displayDate(k.ExpiresAt),
		}
		if withOwner {
			row.Owner = k.OwnerName
			if k.OwnerEmail != "" {
				if row.Owner == "" {
					row.Owner = k.OwnerEmail
				} else {
					row.Owner += " (" + k.OwnerEmail + ")"
				}
			}
			if row.Owner == "" {
				row.Owner = k.UserID
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// handleAPIKeys renders the caller's API keys page for an org.
func handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := apiKeyActor(w, r, views.APIKeysURL(url.PathEscape(orgID)))
	if !ok {
		return
	}
	renderAPIKeys(w, r, actor, orgID, nil)
}

func renderAPIKeys(w http.ResponseWriter, r *http.Request, actor action.Actor, orgID string, created *action.APIKeyCreated) {
	out, err := orgDispatch(r, actor, orgID, "apikey.list", struct{}{})
	if err != nil {
		if apiKeyDenied(w, r, err) {
			return
		}
		ref := idpRef()
		slog.Error("api keys: list", "ref", ref, "err", err)
		renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	keys, _ := out.([]action.APIKeyView)
	d := views.APIKeysData{
		OrgID:  url.PathEscape(orgID),
		Notice: apiKeyNotices[r.URL.Query().Get("notice")],
		Error:  apiKeyErrors[r.URL.Query().Get("error")],
		Keys:   apiKeyRows(keys, false),
	}
	if created != nil {
		d.NewKey, d.NewKeyName = created.Secret, created.Name
	}
	if _, err := orgDispatch(r, actor, orgID, action.ActionAPIKeyOrgList, struct{}{}); err == nil {
		d.CanManageOrg = true
	}
	s := shellData(r, "API keys", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := views.APIKeysPage(s, d).Render(r.Context(), w); err != nil {
		slog.Error("render api keys", "err", err)
	}
}

func apiKeysRedirect(w http.ResponseWriter, r *http.Request, base, kind, code string) {
	// base is a fixed /app/org/<escaped id>/... path plus a fixed code.
	http.Redirect(w, r, base+"?"+kind+"="+code, http.StatusSeeOther) //nolint:gosec // G710: same-origin fixed path
}

// handleAPIKeyCreate creates a key and renders the page with its secret
// shown once (no redirect: the secret must not travel in a URL).
func handleAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	base := views.APIKeysURL(url.PathEscape(orgID))
	actor, ok := apiKeyActor(w, r, base)
	if !ok {
		return
	}
	out, err := orgDispatch(r, actor, orgID, "apikey.create", map[string]string{
		"name": r.PostFormValue("name"), "scope": r.PostFormValue("scope"),
		"expires_in_days": r.PostFormValue("expires_in_days"),
	})
	if err != nil {
		if apiKeyDenied(w, r, err) {
			return
		}
		if code := apiKeyErrorCode(err); code != "" {
			apiKeysRedirect(w, r, base, "error", code)
			return
		}
		ref := idpRef()
		slog.Error("api keys: create", "ref", ref, "err", err)
		renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	created, ok := out.(action.APIKeyCreated)
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	renderAPIKeys(w, r, actor, orgID, &created)
}

// handleAPIKeyRevoke revokes one of the caller's keys.
func handleAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	apiKeyRevoke(w, r, "apikey.revoke", views.APIKeysURL)
}

// handleOrgAPIKeyRevoke revokes any key bound to the org (org owners).
func handleOrgAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	apiKeyRevoke(w, r, action.ActionAPIKeyOrgRevoke, views.OrgAPIKeysURL)
}

func apiKeyRevoke(w http.ResponseWriter, r *http.Request, name string, page func(string) string) {
	orgID := chi.URLParam(r, "orgID")
	base := page(url.PathEscape(orgID))
	actor, ok := apiKeyActor(w, r, base)
	if !ok {
		return
	}
	_, err := orgDispatch(r, actor, orgID, name, map[string]string{"id": chi.URLParam(r, "id")})
	switch {
	case err == nil:
		apiKeysRedirect(w, r, base, "notice", "revoked")
	case apiKeyDenied(w, r, err):
	case apiKeyErrorCode(err) != "":
		apiKeysRedirect(w, r, base, "error", apiKeyErrorCode(err))
	default:
		ref := idpRef()
		slog.Error("api keys: revoke", "ref", ref, "err", err)
		renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
	}
}

// handleOrgAPIKeys renders every key bound to the org (org owners).
func handleOrgAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := apiKeyActor(w, r, views.OrgAPIKeysURL(url.PathEscape(orgID)))
	if !ok {
		return
	}
	out, err := orgDispatch(r, actor, orgID, action.ActionAPIKeyOrgList, struct{}{})
	if err != nil {
		if apiKeyDenied(w, r, err) {
			return
		}
		ref := idpRef()
		slog.Error("api keys: org list", "ref", ref, "err", err)
		renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	keys, _ := out.([]action.APIKeyView)
	d := views.OrgAPIKeysData{
		OrgID:  url.PathEscape(orgID),
		Notice: apiKeyNotices[r.URL.Query().Get("notice")],
		Error:  apiKeyErrors[r.URL.Query().Get("error")],
		Keys:   apiKeyRows(keys, true),
	}
	crumbs := []views.Breadcrumb{
		{Label: orgID, Href: "/app/org/" + url.PathEscape(orgID) + "/settings"},
		{Label: "API keys", Href: ""},
	}
	s := shellData(r, "API keys in this organisation", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := views.OrgAPIKeysPage(s, d, crumbs).Render(r.Context(), w); err != nil {
		slog.Error("render org api keys", "err", err)
	}
}
