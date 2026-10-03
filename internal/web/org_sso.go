package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// Organisation SSO (WU-606, SPEC §7.4): Org settings → Single sign-on and
// home-realm discovery on /login.

// SSODiscoverURL is home-realm discovery. It is a GET (SPEC §7.2/§7.4 as
// amended in WU-606): it changes nothing, so it needs no CSRF exemption, and
// a hit redirects to /auth/{id}?login_hint=<email>, so the address is in a
// URL either way. The request log records paths only, never query strings.
const SSODiscoverURL = "/auth/sso/discover"

// maxEmailLen bounds the address discovery accepts (RFC 5321 path limit).
const maxEmailLen = 254

var ssoNotices = map[string]string{
	"added":    "Domain added. Publish the TXT record below, then select Verify.",
	"verified": "Domain verified.",
	"removed":  "Domain removed.",
}

var ssoErrors = map[string]string{
	"invalid":          "That isn't a valid domain name. Enter just the domain, like example.com.",
	"ip":               "Enter a domain name, not an IP address.",
	"public_suffix":    "That's a public suffix (like com or co.uk), not a domain an organisation can own.",
	"exists":           "That domain has already been added.",
	"taken":            "That domain has been verified by another organisation.",
	"limit":            "This organisation has reached its limit of 50 domains. Remove one first.",
	"already_verified": "That domain is already verified.",
	"record_missing":   "We couldn't find the TXT record with this domain's value. Check the record name and value, allow time for DNS to update, then try again.",
	"lookup":           "The DNS lookup failed or timed out. Try again in a few minutes.",
	"not_found":        "That domain isn't on this organisation.",
}

// domainErrorCode maps an org.domain.* error to an ssoErrors code ("" =
// unexpected).
func domainErrorCode(err error) string {
	for code, e := range map[string]error{
		"invalid": action.ErrDomainInvalid, "ip": action.ErrDomainIP,
		"public_suffix": action.ErrDomainPublicSuffix, "exists": action.ErrDomainExists,
		"taken": action.ErrDomainTaken, "limit": action.ErrDomainLimit,
		"already_verified": action.ErrDomainAlreadyChecked, "record_missing": action.ErrDomainRecordMissing,
		"lookup": action.ErrDomainLookup, "not_found": sql.ErrNoRows,
	} {
		if errors.Is(err, e) {
			return code
		}
	}
	return ""
}

// renderStatusPage writes an error page with the given status.
func renderStatusPage(w http.ResponseWriter, r *http.Request, status int, title, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	RenderErrorPage(w, r, status, title, msg)
}

// ssoActor is the session user for the SSO pages; anonymous GETs go to
// /login and come back.
func ssoActor(w http.ResponseWriter, r *http.Request, orgID string) (action.Actor, bool) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		if r.Method == http.MethodGet {
			// The target is /login with a SafeReturnTo-validated return_to.
			http.Redirect(w, r, auth.LoginURLFor(views.OrgSSOURL(url.PathEscape(orgID))), http.StatusSeeOther) //nolint:gosec // G710: fixed path, return_to validated by auth.SafeReturnTo
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

// ssoDenied renders the refusal for a dispatch error that is not the
// action's own: no permission or not a member of the org.
func ssoDenied(w http.ResponseWriter, r *http.Request, err error) bool {
	var sso action.ErrSSORequired
	if errors.As(err, &sso) {
		RenderSSORequired(w, r, sso)
		return true
	}
	if errors.Is(err, action.ErrForbidden) || errors.Is(err, action.ErrScope) {
		renderStatusPage(w, r, http.StatusForbidden, "Forbidden",
			"You need permission to manage single sign-on for this organisation.")
		return true
	}
	return false
}

func handleOrgSSO(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	out, err := disp.Dispatch(r.Context(), actor, "org.domain.list", json.RawMessage(`{}`), action.Opts{Org: orgID})
	if err != nil {
		if ssoDenied(w, r, err) {
			return
		}
		ref := idpRef()
		slog.Error("org sso: list domains", "ref", ref, "err", err)
		renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	var list struct {
		Domains []action.OrgDomainView `json:"domains"`
	}
	b, err := json.Marshal(out)
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	d := views.OrgSSOData{
		OrgID:  orgID,
		Notice: ssoNotices[r.URL.Query().Get("notice")],
		Error:  ssoErrors[r.URL.Query().Get("error")],
	}
	if org, err := sqlc.New(disp.DB()).FindOrgByID(r.Context(), orgID); err == nil {
		d.OrgName = org.Name
	}
	for _, dm := range list.Domains {
		d.Domains = append(d.Domains, views.OrgDomainRow{
			ID: dm.ID, Domain: dm.Domain, Status: dm.Status, VerifiedAt: displayDate(dm.VerifiedAt),
			RecordName: dm.RecordName, RecordValue: dm.RecordValue,
		})
	}
	if err := orgSSOSections(r, actor, orgID, &d); err != nil {
		if ssoDenied(w, r, err) {
			return
		}
		ref := idpRef()
		slog.Error("org sso: providers", "ref", ref, "err", err)
		renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	label := d.OrgName
	if label == "" {
		label = orgID
	}
	crumbs := []views.Breadcrumb{
		{Label: label, Href: "/app/org/" + orgID + "/settings"},
		{Label: "Single sign-on", Href: ""},
	}
	s := shellData(r, "Single sign-on", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := views.OrgSSOPage(s, d, crumbs).Render(r.Context(), w); err != nil {
		slog.Error("render org sso", "err", err)
	}
}

// handleOrgDomainPost serves the add/verify/remove form posts: it
// dispatches the action and lands back on the page with a fixed code.
func handleOrgDomainPost(name, notice string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "orgID")
		actor, ok := ssoActor(w, r, orgID)
		if !ok {
			return
		}
		in := map[string]string{"id": chi.URLParam(r, "id")}
		if name == "org.domain.add" {
			in = map[string]string{"domain": r.PostFormValue("domain")}
		}
		raw, err := json.Marshal(in)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		_, err = disp.Dispatch(r.Context(), actor, name, raw, action.Opts{Org: orgID})
		page := views.OrgSSOURL(url.PathEscape(orgID))
		dest := page + "?notice=" + notice
		if err != nil {
			if ssoDenied(w, r, err) {
				return
			}
			code := domainErrorCode(err)
			if code == "" {
				ref := idpRef()
				slog.Error("org sso: "+name, "ref", ref, "err", err)
				renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
				return
			}
			if code == "lookup" {
				slog.Warn("org sso: domain lookup", "org", orgID, "err", err)
			}
			dest = page + "?error=" + code
		}
		// dest is the fixed /app/org/<escaped id>/settings/sso path plus a
		// fixed code: always same-origin.
		http.Redirect(w, r, dest, http.StatusSeeOther) //nolint:gosec // G710: same-origin fixed path, see above
	}
}

// --- Home-realm discovery (SPEC §7.4) ---------------------------------------

// ssoProviderFor returns the sign-in provider for email's verified domain:
// the first (in display order) enabled provider owned by the org that
// verified it, or "" when there is none. Callers must not reveal which part
// was missing.
func ssoProviderFor(ctx context.Context, email string) string {
	src := identityCfg().providers
	if disp == nil || disp.DB() == nil || src == nil || len(email) > maxEmailLen {
		return ""
	}
	orgID, err := action.VerifiedOrgForEmail(ctx, sqlc.New(disp.DB()), email)
	if err != nil {
		slog.Error("sso discover: domain lookup", "err", err)
		return ""
	}
	if orgID == "" {
		return ""
	}
	ps, err := src.Providers(ctx)
	if err != nil {
		slog.Error("sso discover: list providers", "err", err)
		return ""
	}
	for _, p := range ps {
		if p.OrgID == orgID {
			return p.ID
		}
	}
	return ""
}

// handleSSODiscover is GET /auth/sso/discover?email=: a verified domain
// with an enabled org provider redirects to /auth/{id}?login_hint=<email>
// (with return_to and invite carried over); anything else re-renders /login
// with the same neutral message.
func handleSSODiscover(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	email := strings.TrimSpace(q.Get("email"))
	if id := ssoProviderFor(r.Context(), email); id != "" {
		hq := url.Values{"login_hint": {email}}
		if rt := auth.SafeReturnTo(q.Get("return_to")); rt != auth.DefaultReturnTo {
			hq.Set("return_to", rt)
		}
		if inv := q.Get("invite"); inv != "" && len(inv) <= 128 {
			hq.Set("invite", inv)
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, "/auth/"+url.PathEscape(id)+"?"+hq.Encode(), http.StatusSeeOther)
		return
	}
	if len(email) > maxEmailLen {
		email = ""
	}
	renderLogin(w, r, loginExtras{ssoEmail: email, ssoNotFound: true})
}

// loginSSOForm is the /login SSO slot: shown when any enabled org-owned
// provider exists, or to carry the "not found" message.
func loginSSOForm(ps []string, x loginExtras, returnTo, invite string) templ.Component {
	if len(ps) == 0 && !x.ssoNotFound {
		return nil
	}
	rt := ""
	if returnTo != auth.DefaultReturnTo {
		rt = returnTo
	}
	return views.LoginSSOForm(x.ssoEmail, rt, invite, x.ssoNotFound)
}
