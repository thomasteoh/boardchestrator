package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// Org settings -> Single sign-on -> SCIM provisioning (WU-611, SPEC §7.8):
// SCIM tokens via scim.token.list|create|revoke, dispatched as the session
// user, and the base URL to give the identity provider.

// SCIMBasePath is the SCIM base path (internal/auth/scim.Prefix).
const SCIMBasePath = "/scim/v2"

func init() {
	ssoNotices["scim_revoked"] = "SCIM token revoked. Your identity provider can no longer use it."
	for k, v := range map[string]string{
		"scim_name":      "Give the token a name of up to 100 characters.",
		"scim_expiry":    "Choose an expiry from the list.",
		"scim_limit":     "This organisation has reached its limit of 20 active SCIM tokens. Revoke one first.",
		"scim_not_found": "That SCIM token isn't on this organisation or is already revoked.",
	} {
		ssoErrors[k] = v
	}
}

func scimErrorCode(err error) string {
	for _, c := range []struct {
		code string
		err  error
	}{
		{"scim_name", action.ErrSCIMTokenName}, {"scim_expiry", action.ErrSCIMTokenExpiry},
		{"scim_limit", action.ErrSCIMTokenLimit}, {"scim_not_found", action.ErrSCIMTokenNotFound},
		{"platform_org", action.ErrPlatformOrgSSO},
	} {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return ""
}

// scimSection builds the SCIM section from scim.token.list.
func scimSection(r *http.Request, actor action.Actor, orgID string, newToken *action.SCIMTokenCreated) (templ.Component, error) {
	out, err := orgDispatch(r, actor, orgID, action.ActionSCIMTokenList, struct{}{})
	if err != nil {
		return nil, err
	}
	tokens, _ := out.([]action.SCIMTokenView)
	d := views.OrgSCIMData{
		OrgID: url.PathEscape(orgID), CSRF: shellData(r, "", "").CSRF,
		BaseURL: strings.TrimRight(identityCfg().baseURL, "/") + SCIMBasePath,
	}
	for _, t := range tokens {
		d.Tokens = append(d.Tokens, views.OrgSCIMTokenRow{
			ID: t.ID, Name: t.Name, Prefix: t.Prefix, Status: t.Status, Created: displayDate(t.CreatedAt),
			Expires: displayDate(t.ExpiresAt), LastUsed: displayDate(t.LastUsedAt), RevokeOpen: t.Status != "revoked",
		})
	}
	if newToken != nil {
		d.NewToken, d.NewTokenName = newToken.Token, newToken.Name
	}
	return views.OrgSCIMSection(d), nil
}

// handleOrgSCIMCreate creates a token and renders the page with it shown
// once (no redirect: the token must not travel in a URL).
func handleOrgSCIMCreate(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	days, err := strconv.Atoi(r.PostFormValue("expires_in_days"))
	if err != nil {
		orgSSORedirect(w, r, orgID, "error", "scim_expiry")
		return
	}
	out, err := orgDispatch(r, actor, orgID, action.ActionSCIMTokenCreate, map[string]any{
		"name": r.PostFormValue("name"), "expires_in_days": days,
	})
	if err != nil {
		if !errors.Is(err, action.ErrForbidden) && !errors.Is(err, action.ErrScope) {
			if code := scimErrorCode(err); code != "" {
				orgSSORedirect(w, r, orgID, "error", code)
				return
			}
		}
		orgSSOOutcome(w, r, orgID, err, "")
		return
	}
	created, ok := out.(action.SCIMTokenCreated)
	if !ok {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	renderOrgSSO(w, r, actor, orgID, &created)
}

// handleOrgSCIMRevoke revokes a token.
func handleOrgSCIMRevoke(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	_, err := orgDispatch(r, actor, orgID, action.ActionSCIMTokenRevoke, map[string]string{"id": chi.URLParam(r, "id")})
	if err != nil && !errors.Is(err, action.ErrForbidden) && !errors.Is(err, action.ErrScope) {
		if code := scimErrorCode(err); code != "" {
			orgSSORedirect(w, r, orgID, "error", code)
			return
		}
	}
	orgSSOOutcome(w, r, orgID, err, "scim_revoked")
}
