package web

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// Settings → Sign-in methods (WU-604, SPEC §7.3, PRD §4 "Account linking").
// Linking starts at POST /settings/sign-in-methods/link/{providerID}, which
// the auth handler serves because it owns the flow cookie; it comes back
// here with ?notice= or ?error=.

// signInNotices and signInErrors map the fixed codes in ?notice= / ?error=
// to copy. Unknown codes show nothing, so nothing from the URL is echoed.
var signInNotices = map[string]string{ //nolint:gosec // G101: notice copy, no credentials
	"linked":          "Sign-in method linked. You can now sign in with it.",
	"already_linked":  "That sign-in method was already linked to your account.",
	"unlinked":        "Sign-in method removed.",
	"passkey_added":   "Passkey added. You can now sign in with it.",
	"passkey_renamed": "Passkey renamed.",
	"passkey_removed": "Passkey removed.",
}

var signInErrors = map[string]string{
	auth.RefuseLinkSession:    "Your session changed before linking finished. Sign in again and retry.",
	auth.RefuseIdentityInUse:  "That sign-in is already linked to a different account. Accounts can't be merged.",
	auth.RefuseProviderLinked: "You already have a sign-in method from that provider. Unlink it first to link a different account.",
	auth.RefuseUserDeleted:    "This account has been deleted.",
	"last_method":             "You can't remove your only sign-in method. Link another first.",
	"not_found":               "That sign-in method isn't linked to your account.",
	"passkey_name":            "Give the passkey a name of up to 64 characters.",
	"passkey_not_found":       "That passkey isn't registered to your account.",
}

// signInUser is the session user, or a redirect to /login (GET) / 403.
func signInUser(w http.ResponseWriter, r *http.Request) (action.Actor, bool) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		if r.Method == http.MethodGet {
			http.Redirect(w, r, auth.LoginURLFor(auth.SignInMethodsURL), http.StatusSeeOther)
		} else {
			RenderErrorPage(w, r, http.StatusForbidden, "Forbidden", "You must be signed in.")
		}
		return action.Actor{}, false
	}
	if disp == nil {
		http.Error(w, "dispatcher not configured", http.StatusInternalServerError)
		return action.Actor{}, false
	}
	return sessionActor(r, sess), true
}

func handleSignInMethods(w http.ResponseWriter, r *http.Request) {
	actor, ok := signInUser(w, r)
	if !ok {
		return
	}
	out, err := disp.Dispatch(r.Context(), actor, "identity.list", json.RawMessage(`{}`), action.Opts{})
	if err != nil {
		ref := idpRef()
		slog.Error("sign-in methods: list", "ref", ref, "err", err)
		RenderErrorPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	var list struct {
		Identities []action.IdentityView `json:"identities"`
	}
	b, err := json.Marshal(out)
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	presets := map[string]string{}
	var platform []views.LinkableProvider
	if src := identityCfg().providers; src != nil {
		ps, err := src.Providers(r.Context())
		if err != nil {
			slog.Error("sign-in methods: list providers", "err", err)
		}
		for _, p := range ps {
			presets[p.ID] = p.Preset
			if p.OrgID == "" {
				platform = append(platform, views.LinkableProvider{ID: p.ID, Name: p.DisplayName, Preset: p.Preset})
			}
		}
	}
	pks, pkOn, err := listPasskeys(r, actor)
	if err != nil {
		ref := idpRef()
		slog.Error("sign-in methods: passkeys", "ref", ref, "err", err)
		RenderErrorPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	// The same count action.SignInMethodCount uses: passkeys count only
	// while the platform has them on.
	methods := len(list.Identities)
	if pkOn {
		methods += len(pks)
	}
	d := views.SignInMethodsData{
		CanUnlink: methods > 1,
		Notice:    signInNotices[r.URL.Query().Get("notice")],
		Error:     signInErrors[r.URL.Query().Get("error")],
	}
	if pkOn || len(pks) > 0 {
		sec := views.PasskeysSectionData{CSRF: auth.CSRFFrom(r.Context()), CanDelete: methods > 1, Enabled: pkOn}
		for _, p := range pks {
			sec.Rows = append(sec.Rows, views.PasskeyRow{
				ID: p.ID, Name: p.Name, Synced: p.Synced,
				Created: displayDate(p.CreatedAt), LastUsed: displayDate(p.LastUsedAt),
			})
		}
		d.Passkeys = views.PasskeysSection(sec)
	}
	linked := map[string]bool{}
	for _, id := range list.Identities {
		linked[id.Provider] = true
		d.Methods = append(d.Methods, views.SignInMethod{
			ID: id.ID, Provider: id.Provider, Name: id.DisplayName, Preset: presets[id.Provider],
			Email: id.Email, LastUsed: displayDate(id.LastLoginAt), Linked: displayDate(id.CreatedAt),
		})
	}
	for _, p := range platform {
		if !linked[p.ID] {
			d.Available = append(d.Available, p)
		}
	}
	s := shellData(r, "Sign-in methods", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := views.SignInMethodsPage(s, d).Render(r.Context(), w); err != nil {
		slog.Error("render sign-in methods", "err", err)
	}
}

// handleSignInMethodUnlink is POST /settings/sign-in-methods/unlink/{id}.
func handleSignInMethodUnlink(w http.ResponseWriter, r *http.Request) {
	actor, ok := signInUser(w, r)
	if !ok {
		return
	}
	raw, err := json.Marshal(map[string]string{"id": chi.URLParam(r, "id")})
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	out, err := disp.Dispatch(r.Context(), actor, "identity.unlink", raw, action.Opts{})
	dest := auth.SignInMethodsURL + "?notice=unlinked"
	switch {
	case err == nil:
		// The unlink revoked the sessions signed in through that identity;
		// when this is one of them the browser is signed out (WU-613).
		if m, ok := out.(map[string]any); ok && actor.AuthProviderID != "" && m["provider"] == actor.AuthProviderID {
			auth.ClearSessionCookie(w)
			http.Redirect(w, r, auth.LoginURL+"?signed_out=1", http.StatusSeeOther)
			return
		}
	case errors.Is(err, action.ErrLastSignInMethod):
		dest = auth.SignInMethodsURL + "?error=last_method"
	case errors.Is(err, sql.ErrNoRows):
		dest = auth.SignInMethodsURL + "?error=not_found"
	default:
		ref := idpRef()
		slog.Error("sign-in methods: unlink", "ref", ref, "err", err)
		RenderErrorPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// displayDate renders a stored UTC timestamp as a date ("" when unknown).
func displayDate(ts string) string {
	if ts == "" {
		return ""
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", ts)
	if err != nil {
		return ""
	}
	return t.Format("2 Jan 2006")
}

// listPasskeys is the session user's passkeys and whether passkeys are on.
func listPasskeys(r *http.Request, actor action.Actor) ([]action.PasskeyView, bool, error) {
	out, err := disp.Dispatch(r.Context(), actor, "passkey.list", json.RawMessage(`{}`), action.Opts{})
	if err != nil {
		return nil, false, err
	}
	var list struct {
		Passkeys []action.PasskeyView `json:"passkeys"`
	}
	b, err := json.Marshal(out)
	if err == nil {
		err = json.Unmarshal(b, &list)
	}
	return list.Passkeys, passkeysOn(r.Context()), err
}

// handlePasskeyRename is POST /settings/passkeys/{id}/rename.
func handlePasskeyRename(w http.ResponseWriter, r *http.Request) {
	passkeyAction(w, r, "passkey.rename", map[string]string{
		"id": chi.URLParam(r, "id"), "name": r.PostFormValue("name"),
	}, "passkey_renamed")
}

// handlePasskeyDelete is POST /settings/passkeys/{id}/delete.
func handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	passkeyAction(w, r, "passkey.delete", map[string]string{"id": chi.URLParam(r, "id")}, "passkey_removed")
}

func passkeyAction(w http.ResponseWriter, r *http.Request, name string, in map[string]string, notice string) {
	actor, ok := signInUser(w, r)
	if !ok {
		return
	}
	raw, err := json.Marshal(in)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	_, err = disp.Dispatch(r.Context(), actor, name, raw, action.Opts{})
	dest := auth.SignInMethodsURL + "?notice=" + notice
	switch {
	case err == nil:
	case errors.Is(err, action.ErrLastSignInMethod):
		dest = auth.SignInMethodsURL + "?error=last_method"
	case errors.Is(err, action.ErrPasskeyName):
		dest = auth.SignInMethodsURL + "?error=passkey_name"
	case errors.Is(err, sql.ErrNoRows):
		dest = auth.SignInMethodsURL + "?error=passkey_not_found"
	default:
		ref := idpRef()
		slog.Error("sign-in methods: "+name, "ref", ref, "err", err)
		RenderErrorPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
		return
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}
