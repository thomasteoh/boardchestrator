package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// Org settings -> Single sign-on: the organisation's own identity providers
// and SSO enforcement (WU-607, SPEC §7.4). Every change dispatches an
// org.idp.* / org.sso.* action as the session user with the org id.

func init() {
	for k, v := range map[string]string{
		"idp_created":  "Identity provider added.",
		"idp_updated":  "Changes saved.",
		"idp_enabled":  "Identity provider enabled.",
		"idp_disabled": "Identity provider disabled.",
		"idp_deleted":  "Identity provider deleted.",
		"enforced":     "Single sign-on is now required for this organisation.",
		"unenforced":   "Single sign-on is no longer required.",
	} {
		ssoNotices[k] = v
	}
	for k, v := range map[string]string{
		"lockout":       "To require single sign-on, first sign in through one of this organisation's enabled identity providers, so you can't lock yourself out.",
		"no_provider":   "Add and enable an identity provider before requiring single sign-on.",
		"last_provider": "That's the last enabled identity provider and single sign-on is required. Stop requiring single sign-on first.",
		"in_use":        "People sign in with that identity provider, so it can't be deleted. Disable it instead.",
		"idp_not_found": "That identity provider isn't on this organisation.",
	} {
		ssoErrors[k] = v
	}
}

func orgDispatch(r *http.Request, actor action.Actor, orgID, name string, in any) (any, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	return disp.Dispatch(r.Context(), actor, name, raw, action.Opts{Org: orgID})
}

// orgSSORedirect lands back on the SSO page with a fixed code.
func orgSSORedirect(w http.ResponseWriter, r *http.Request, orgID, kind, code string) {
	// Fixed /app/org/<escaped id>/settings/sso path plus a fixed code.
	http.Redirect(w, r, views.OrgSSOURL(url.PathEscape(orgID))+"?"+kind+"="+code, http.StatusSeeOther) //nolint:gosec // G710: same-origin fixed path, see above
}

// orgSSOSections builds the Identity provider, Enforcement and Provisioning
// sections.
func orgSSOSections(r *http.Request, actor action.Actor, orgID string, d *views.OrgSSOData) error {
	out, err := orgDispatch(r, actor, orgID, idp.ActionOrgList, struct{}{})
	if err != nil {
		return err
	}
	provs, _ := out.([]idp.ProviderView)
	base := identityCfg().baseURL
	csrf := shellData(r, "", "").CSRF
	sec := views.OrgIdPSectionData{OrgID: url.PathEscape(orgID), CSRF: csrf}
	enabled := map[string]string{}
	for _, p := range provs {
		pr, _ := idp.LookupPreset(p.Preset)
		sec.Rows = append(sec.Rows, views.IdPRow{
			ID: p.ID, Name: p.DisplayName, Preset: p.Preset, PresetName: pr.DisplayName, Kind: p.Kind,
			Enabled: p.Enabled, Identities: p.IdentityCount, CallbackURL: idp.CallbackURL(base, p.ID),
		})
		if p.Enabled {
			enabled[p.ID] = p.DisplayName
		}
	}
	sec.Presets = orgPresets()
	d.Provider = views.OrgIdPSection(sec)

	sOut, err := orgDispatch(r, actor, orgID, "org.sso.get", struct{}{})
	if err != nil {
		return err
	}
	st, _ := sOut.(action.OrgSSOView)
	en := views.OrgEnforcementData{OrgID: url.PathEscape(orgID), CSRF: csrf, Enforced: st.EnforceSSO}
	_, signedInViaOrg := enabled[actor.AuthProviderID]
	switch {
	case len(enabled) == 0:
		en.Hint = ssoErrors["no_provider"]
	case actor.AuthProviderID == "" || !signedInViaOrg:
		en.Hint = ssoErrors["lockout"]
	default:
		en.CanEnable = true
	}
	d.Enforcement = views.OrgEnforcementSection(en)

	pd, err := provisioningSection(r, actor, orgID, csrf, st, provs)
	if err != nil {
		return err
	}
	d.Provisioning = views.OrgProvisioningSection(pd)
	return nil
}

// orgPresets are the presets an organisation can use: OpenID Connect only
// (GitHub OAuth is not an organisation IdP; SAML arrives in WU-610).
func orgPresets() []views.IdPPresetOption {
	var out []views.IdPPresetOption
	for _, id := range idp.PresetIDs {
		pr, ok := idp.LookupPreset(id)
		if !ok || pr.Kind != idp.KindOIDC {
			continue
		}
		out = append(out, views.IdPPresetOption{ID: pr.ID, Name: pr.DisplayName, Kind: pr.Kind})
	}
	return out
}

func orgIdPForm(r *http.Request, orgID string, p idp.Preset, fv formValues, editing bool) views.IdPForm {
	f := buildIdPForm(p, fv, editing)
	f.Base = views.OrgIdPBase(url.PathEscape(orgID))
	f.OrgOwned = true
	if prefix, err := idp.OrgProviderPrefix(r.Context(), sqlc.New(disp.DB()), orgID); err == nil {
		f.IDPrefix = prefix
		if !editing {
			f.CallbackURL = idp.CallbackURL(identityCfg().baseURL, prefix+"your-id")
			f.BackChannelURL = auth.BackChannelLogoutURL(identityCfg().baseURL, prefix+"your-id")
		}
	}
	return f
}

func renderOrgIdPForm(w http.ResponseWriter, r *http.Request, orgID string, status int, f views.IdPForm) {
	title := "Add identity provider"
	if f.Editing {
		title = "Edit identity provider"
	}
	label := orgID
	if org, err := sqlc.New(disp.DB()).FindOrgByID(r.Context(), orgID); err == nil {
		label = org.Name
	}
	crumbs := []views.Breadcrumb{
		{Label: label, Href: "/app/org/" + orgID + "/settings"},
		{Label: "Single sign-on", Href: views.OrgSSOURL(orgID)},
		{Label: title, Href: ""},
	}
	s := shellData(r, title, "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := views.OrgIdPFormPage(s, url.PathEscape(orgID), f, crumbs).Render(r.Context(), w); err != nil {
		slog.Error("render org identity provider form", "err", err)
	}
}

func handleOrgIdPNew(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	if _, err := orgDispatch(r, actor, orgID, idp.ActionOrgList, struct{}{}); err != nil {
		if !ssoDenied(w, r, err) {
			renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", idpUserMessage(err))
		}
		return
	}
	p, ok := idp.LookupPreset(r.URL.Query().Get("preset"))
	if !ok || r.URL.Query().Get("preset") == "" || p.Kind != idp.KindOIDC {
		http.Redirect(w, r, views.OrgSSOURL(url.PathEscape(orgID)), http.StatusSeeOther) //nolint:gosec // G710: same-origin fixed path
		return
	}
	fv := formValues{trust: p.TrustEmail, enabled: true, idpLogout: p.SupportsLogout}
	if prefix, err := idp.OrgProviderPrefix(r.Context(), sqlc.New(disp.DB()), orgID); err == nil {
		fv.id = prefix
	}
	f := orgIdPForm(r, orgID, p, fv, false)
	renderOrgIdPForm(w, r, orgID, http.StatusOK, f)
}

func handleOrgIdPEdit(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	out, err := orgDispatch(r, actor, orgID, idp.ActionOrgGet, map[string]string{"id": chi.URLParam(r, "id")})
	switch {
	case err != nil && ssoDenied(w, r, err):
		return
	case errors.Is(err, action.ErrInvalidInput):
		renderStatusPage(w, r, http.StatusNotFound, "Page not found", "There's no identity provider with that ID on this organisation.")
		return
	case err != nil:
		renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", idpUserMessage(err))
		return
	}
	v, _ := out.(idp.ProviderView)
	p, _ := idp.LookupPreset(v.Preset)
	f := orgIdPForm(r, orgID, p, formValues{
		id: v.ID, displayName: v.DisplayName, params: v.Params, clientID: v.ClientID,
		scopes: v.Scopes, claims: v.ClaimMap, trust: v.TrustEmail, idpLogout: v.IdPLogout,
		tenants: strings.Join(v.AllowedTenants, "\n"), position: strconv.FormatInt(v.Position, 10), enabled: v.Enabled,
	}, true)
	f.SecretSet = v.SecretSet
	f.Kind = v.Kind
	renderOrgIdPForm(w, r, orgID, http.StatusOK, f)
}

func handleOrgIdPCreate(w http.ResponseWriter, r *http.Request) { orgIdPSave(w, r, "") }

func handleOrgIdPUpdate(w http.ResponseWriter, r *http.Request) {
	orgIdPSave(w, r, chi.URLParam(r, "id"))
}

func orgIdPSave(w http.ResponseWriter, r *http.Request, editID string) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	editing := editID != ""
	fv := readFormValues(r, editID)
	fv.signup = false // never offered for organisation providers
	p, ok := idp.LookupPreset(fv.preset)
	if !ok || fv.preset == "" {
		orgSSORedirect(w, r, orgID, "error", "idp_not_found")
		return
	}
	in, perr := fv.input(editing)
	in.AllowSignup = nil
	name := idp.ActionOrgCreate
	if editing {
		name = idp.ActionOrgUpdate
	}
	var err error
	if perr == nil {
		_, err = orgDispatch(r, actor, orgID, name, in)
	}
	if err != nil && ssoDenied(w, r, err) {
		return
	}
	if perr != nil || err != nil {
		f := orgIdPForm(r, orgID, p, fv, editing)
		if perr != nil {
			f.Error = capitalise(perr.Error()) + "."
		} else {
			f.Error = idpUserMessage(err)
		}
		if editing {
			if out, gerr := orgDispatch(r, actor, orgID, idp.ActionOrgGet, map[string]string{"id": editID}); gerr == nil {
				v, _ := out.(idp.ProviderView)
				f.SecretSet = v.SecretSet
			}
		}
		renderOrgIdPForm(w, r, orgID, http.StatusUnprocessableEntity, f)
		return
	}
	notice := "idp_created"
	if editing {
		notice = "idp_updated"
	}
	orgSSORedirect(w, r, orgID, "notice", notice)
}

// orgSSOErrorCode maps an org.idp.* / org.sso.update refusal to a fixed
// ssoErrors code ("" = unexpected).
func orgSSOErrorCode(err error) string {
	switch {
	case errors.Is(err, action.ErrSSOLockout):
		return "lockout"
	case errors.Is(err, action.ErrSSONoProvider):
		return "no_provider"
	case errors.Is(err, idp.ErrLastEnforcedProvider):
		return "last_provider"
	case errors.Is(err, action.ErrInvalidInput) && strings.Contains(err.Error(), "disable the provider instead"):
		return "in_use"
	case errors.Is(err, action.ErrInvalidInput):
		return "idp_not_found"
	}
	return ""
}

// handleOrgIdPVerb serves the enable / disable / delete buttons.
func handleOrgIdPVerb(verb string) http.HandlerFunc {
	name := map[string]string{"enable": idp.ActionOrgEnable, "disable": idp.ActionOrgDisable, "delete": idp.ActionOrgDelete}[verb]
	notice := map[string]string{"enable": "idp_enabled", "disable": "idp_disabled", "delete": "idp_deleted"}[verb]
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := chi.URLParam(r, "orgID")
		actor, ok := ssoActor(w, r, orgID)
		if !ok {
			return
		}
		_, err := orgDispatch(r, actor, orgID, name, map[string]string{"id": chi.URLParam(r, "id")})
		orgSSOOutcome(w, r, orgID, err, notice)
	}
}

func orgSSOOutcome(w http.ResponseWriter, r *http.Request, orgID string, err error, notice string) {
	if err == nil {
		orgSSORedirect(w, r, orgID, "notice", notice)
		return
	}
	if ssoDenied(w, r, err) {
		return
	}
	if code := orgSSOErrorCode(err); code != "" {
		orgSSORedirect(w, r, orgID, "error", code)
		return
	}
	ref := idpRef()
	slog.Error("org sso", "ref", ref, "err", err)
	renderStatusPage(w, r, http.StatusInternalServerError, "Something went wrong", "Reference: "+ref)
}

// handleOrgSSOEnforce turns "Require single sign-on" on or off.
func handleOrgSSOEnforce(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	on := r.PostFormValue("enforce_sso") == "1"
	_, err := orgDispatch(r, actor, orgID, "org.sso.update", map[string]bool{"enforce_sso": on})
	notice := "unenforced"
	if on {
		notice = "enforced"
	}
	orgSSOOutcome(w, r, orgID, err, notice)
}

// handleOrgIdPDiscover is the org form's "Test discovery" HTMX endpoint.
func handleOrgIdPDiscover(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	actor, ok := ssoActor(w, r, orgID)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	fv := readFormValues(r, "")
	out, err := orgDispatch(r, actor, orgID, idp.ActionOrgDiscover, idp.DiscoverInput{Preset: fv.preset, Params: fv.params})
	if errors.Is(err, action.ErrForbidden) || errors.Is(err, action.ErrScope) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	renderDiscover(w, r, out, err)
}

// renderDiscover writes the "Test discovery" fragment for an idp.discover /
// org.idp.discover result.
func renderDiscover(w http.ResponseWriter, r *http.Request, out any, err error) {
	var d views.IdPDiscoverData
	if err != nil {
		d.Error = idpUserMessage(err)
	} else {
		res, _ := out.(idp.DiscoverResult)
		d = views.IdPDiscoverData{OK: res.OK, Issuer: res.Issuer, Ref: res.Ref}
		for _, e := range [][2]string{
			{"Authorisation endpoint", res.AuthorizationEndpoint},
			{"Token endpoint", res.TokenEndpoint},
			{"User info endpoint", res.UserinfoEndpoint},
			{"Signing keys (JWKS)", res.JWKSURI},
			{"Sign-out endpoint", res.EndSessionEndpoint},
		} {
			if e[1] != "" {
				d.Endpoints = append(d.Endpoints, e)
			}
		}
		if res.BackchannelLogout {
			d.Endpoints = append(d.Endpoints, [2]string{"Back-channel sign-out", "Supported"})
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := views.IdPDiscoverResult(d).Render(r.Context(), w); err != nil {
		slog.Error("render discovery result", "err", err)
	}
}
