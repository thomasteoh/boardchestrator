package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/a-h/templ"
	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/idp"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/web/views"
)

// LoginProviderSource lists the enabled sign-in providers in display order
// (the idp.Registry).
type LoginProviderSource interface {
	Providers(ctx context.Context) ([]idp.ProviderInfo, error)
}

type identityConfig struct {
	baseURL   string
	providers LoginProviderSource
}

var identity atomic.Pointer[identityConfig]

// SetIdentity wires the /login page to the provider registry and gives the
// admin pages the public base URL for callback URLs.
func SetIdentity(baseURL string, providers LoginProviderSource) {
	identity.Store(&identityConfig{baseURL: strings.TrimRight(baseURL, "/"), providers: providers})
}

func identityCfg() identityConfig {
	if c := identity.Load(); c != nil {
		return *c
	}
	return identityConfig{}
}

// refRe matches the reference codes the sign-in failure page shows.
var refRe = regexp.MustCompile(`^[A-Z0-9]{4,16}$`)

// handleLogin serves GET /login (SPEC §7.2).
func handleLogin(w http.ResponseWriter, r *http.Request) {
	renderLogin(w, r, loginExtras{})
}

// loginExtras is state the /login page shows only when re-rendered by home-
// realm discovery (WU-606).
type loginExtras struct {
	ssoEmail    string
	ssoNotFound bool
}

// renderLogin renders the sign-in page for r's query (return_to, invite,
// error, signed_out).
func renderLogin(w http.ResponseWriter, r *http.Request, x loginExtras) {
	q := r.URL.Query()
	returnTo := auth.SafeReturnTo(q.Get("return_to"))
	inviteToken := q.Get("invite")
	if inviteToken != "" {
		// The invite's own page is where a signed-in person accepts it, so
		// that is where every sign-in through this page returns.
		returnTo = inviteAcceptURL(inviteToken)
	}
	if auth.IsAuthenticated(r.Context()) {
		// returnTo passed auth.SafeReturnTo: a same-origin path or /app.
		http.Redirect(w, r, returnTo, http.StatusSeeOther) //nolint:gosec // G710: validated by auth.SafeReturnTo, see above
		return
	}
	d := views.LoginPageData{SignedOut: q.Get("signed_out") == "1"}
	if inviteToken != "" {
		if org, ok := pendingInviteOrg(r.Context(), inviteToken); ok {
			d.InviteOrg = org
		} else {
			d.InviteInvalid = true
			inviteToken = "" // grants nothing; don't carry it
		}
	}
	if q.Has("error") {
		d.Failed = true
		if ref := q.Get("error"); refRe.MatchString(ref) {
			d.ErrorRef = ref
		}
	}
	var orgProviders []string
	if src := identityCfg().providers; src != nil {
		ps, err := src.Providers(r.Context())
		if err != nil {
			slog.Error("login: list providers", "err", err)
		}
		for _, p := range ps {
			if p.OrgID != "" {
				orgProviders = append(orgProviders, p.ID)
				continue // org-owned providers are reached through SSO discovery
			}
			hq := url.Values{}
			if returnTo != auth.DefaultReturnTo {
				hq.Set("return_to", returnTo)
			}
			if inviteToken != "" {
				hq.Set("invite", inviteToken)
			}
			href := "/auth/" + url.PathEscape(p.ID)
			if len(hq) > 0 {
				href += "?" + hq.Encode()
			}
			d.Providers = append(d.Providers, views.LoginProvider{
				ID: p.ID, Name: p.DisplayName, Preset: p.Preset, Href: templ.SafeURL(href),
			})
		}
	}
	if c := loginSSOForm(orgProviders, x, returnTo, inviteToken); c != nil {
		d.SSO = c
	}
	s := shellData(r, "Sign in", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := views.LoginPage(s, d).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// RenderSetupPage is the "Claim this instance" page that auth.Handler.Setup
// shows after a valid bootstrap token (SPEC §7.3 step 5): every enabled
// platform provider, each starting a bootstrap flow (?bootstrap=1; the setup
// cookie carries the proof).
func RenderSetupPage(w http.ResponseWriter, r *http.Request) {
	var ps []views.LoginProvider
	if src := identityCfg().providers; src != nil {
		all, err := src.Providers(r.Context())
		if err != nil {
			slog.Error("setup: list providers", "err", err)
		}
		for _, p := range all {
			if p.OrgID != "" {
				continue
			}
			ps = append(ps, views.LoginProvider{
				ID: p.ID, Name: p.DisplayName, Preset: p.Preset,
				Href: templ.SafeURL("/auth/" + url.PathEscape(p.ID) + "?bootstrap=1"),
			})
		}
	}
	s := shellData(r, "Claim this instance", "")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := views.SetupPage(s, ps).Render(r.Context(), w); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// inviteAcceptURL is the invite landing page for token.
func inviteAcceptURL(token string) string {
	return "/invite/accept?token=" + url.QueryEscape(token)
}

// pendingInviteOrg reports the organisation name of the pending, unexpired
// invite token names. Anything else (unknown, used, expired, no database)
// is just "not usable"; the page never says which.
func pendingInviteOrg(ctx context.Context, token string) (string, bool) {
	if disp == nil || disp.DB() == nil || len(token) > 128 {
		return "", false
	}
	q := sqlc.New(disp.DB())
	inv, err := action.PendingInvite(ctx, q, token, time.Now())
	if err != nil {
		if !errors.Is(err, action.ErrInviteInvalid) {
			slog.Error("login: look up invite", "err", err)
		}
		return "", false
	}
	org, err := q.FindOrgByID(ctx, inv.OrgID)
	if err != nil {
		slog.Error("login: invite org", "err", err)
		return "", false
	}
	return org.Name, true
}

// RenderLoginFailedPage renders the generic sign-in failure page (WU-601)
// with a way back to /login that keeps the reference code visible.
func RenderLoginFailedPage(w http.ResponseWriter, r *http.Request, status int, message, ref string) {
	s := shellData(r, "Sign-in failed", "")
	back := auth.LoginURL
	if refRe.MatchString(ref) {
		back += "?error=" + ref
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := views.ErrorPageWithLink(s, status, "Sign-in failed", message+" Reference: "+ref,
		templ.SafeURL(back), "Back to sign in").Render(r.Context(), w); err != nil {
		slog.Error("render sign-in failure page", "err", err)
	}
}

// --- Platform Admin → Identity providers -----------------------------------

// idpAdmin resolves the session actor for the admin pages. Without a session
// a GET goes to /login and returns here afterwards.
func idpAdmin(w http.ResponseWriter, r *http.Request) (action.Actor, bool) {
	sess, ok := auth.SessionFrom(r.Context())
	if !ok || sess.UserID == "" {
		if r.Method == http.MethodGet {
			// Always /login; the request path only travels as a query value
			// that SafeReturnTo validates.
			http.Redirect(w, r, auth.LoginURLFor(r.URL.RequestURI()), http.StatusSeeOther) //nolint:gosec // G710: fixed /login target, see above
		} else {
			idpForbidden(w, r)
		}
		return action.Actor{}, false
	}
	if disp == nil {
		http.Error(w, "dispatcher not configured", http.StatusInternalServerError)
		return action.Actor{}, false
	}
	return sessionActor(r, sess), true
}

func idpDispatch(r *http.Request, actor action.Actor, name string, in any) (any, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	// Platform scope: never pass an org id (see idp.platformOnly).
	return disp.Dispatch(r.Context(), actor, name, raw, action.Opts{})
}

func idpForbidden(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusForbidden)
	RenderErrorPage(w, r, http.StatusForbidden, "Forbidden",
		"Only platform administrators can manage identity providers.")
}

// idpUserMessage turns a dispatch error into copy for the page: our own
// validation messages are shown; anything else is logged under a reference.
func idpUserMessage(err error) string {
	if errors.Is(err, action.ErrInvalidInput) {
		msg := err.Error()
		if i := strings.Index(msg, action.ErrInvalidInput.Error()+": "); i >= 0 {
			msg = msg[i+len(action.ErrInvalidInput.Error())+2:]
		}
		return capitalise(msg) + "."
	}
	ref := idpRef()
	slog.Error("identity providers admin", "ref", ref, "err", err)
	return "Something went wrong. Reference: " + ref
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func idpRef() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "UNKNOWN"
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// idpNotices are the fixed confirmations after a change.
var idpNotices = map[string]string{
	"created":  "Provider added.",
	"updated":  "Changes saved.",
	"enabled":  "Provider enabled. It now appears on the sign-in page.",
	"disabled": "Provider disabled. It no longer appears on the sign-in page.",
	"deleted":  "Provider deleted.",
}

func handleIdPList(w http.ResponseWriter, r *http.Request) {
	actor, ok := idpAdmin(w, r)
	if !ok {
		return
	}
	notice := ""
	if n, ok := idpNotices[r.URL.Query().Get("notice")]; ok {
		notice = n
	}
	renderIdPList(w, r, actor, http.StatusOK, notice, "")
}

func renderIdPList(w http.ResponseWriter, r *http.Request, actor action.Actor, status int, notice, errMsg string) {
	out, err := idpDispatch(r, actor, idp.ActionList, struct{}{})
	if errors.Is(err, action.ErrForbidden) {
		idpForbidden(w, r)
		return
	}
	if err != nil {
		errMsg = idpUserMessage(err)
		status = http.StatusInternalServerError
	}
	provs, _ := out.([]idp.ProviderView)
	d := idpListData(provs)
	d.Notice, d.Error = notice, errMsg
	s := shellData(r, "Identity providers", "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := views.IdPListPage(s, d).Render(r.Context(), w); err != nil {
		slog.Error("render identity providers", "err", err)
	}
}

func idpListData(ps []idp.ProviderView) views.IdPListData {
	base := identityCfg().baseURL
	var d views.IdPListData
	for _, p := range ps {
		pr, _ := idp.LookupPreset(p.Preset)
		name := pr.DisplayName
		if name == "" {
			name = p.Preset
		}
		d.Rows = append(d.Rows, views.IdPRow{
			ID: p.ID, Name: p.DisplayName, Preset: p.Preset, PresetName: name, Kind: p.Kind,
			Enabled: p.Enabled, EnvManaged: p.ManagedBy == "env", Identities: p.IdentityCount,
			CallbackURL: idp.CallbackURL(base, p.ID),
		})
	}
	for _, id := range idp.PresetIDs {
		pr, ok := idp.LookupPreset(id)
		if !ok {
			continue
		}
		d.Presets = append(d.Presets, views.IdPPresetOption{ID: pr.ID, Name: pr.DisplayName, Kind: pr.Kind})
	}
	return d
}

func handleIdPNew(w http.ResponseWriter, r *http.Request) {
	actor, ok := idpAdmin(w, r)
	if !ok {
		return
	}
	// Permission gate: the form is only for people who could submit it.
	if _, err := idpDispatch(r, actor, idp.ActionList, struct{}{}); errors.Is(err, action.ErrForbidden) {
		idpForbidden(w, r)
		return
	}
	p, ok := idp.LookupPreset(r.URL.Query().Get("preset"))
	if !ok || r.URL.Query().Get("preset") == "" {
		http.Redirect(w, r, views.IdPAdminBase, http.StatusSeeOther)
		return
	}
	f := buildIdPForm(p, formValues{trust: p.TrustEmail, enabled: true, idpLogout: p.SupportsLogout}, false)
	renderIdPForm(w, r, http.StatusOK, f)
}

func handleIdPEdit(w http.ResponseWriter, r *http.Request) {
	actor, ok := idpAdmin(w, r)
	if !ok {
		return
	}
	out, err := idpDispatch(r, actor, idp.ActionGet, map[string]string{"id": chi.URLParam(r, "id")})
	switch {
	case errors.Is(err, action.ErrForbidden):
		idpForbidden(w, r)
		return
	case errors.Is(err, action.ErrInvalidInput):
		w.WriteHeader(http.StatusNotFound)
		RenderErrorPage(w, r, http.StatusNotFound, "Page not found", "There's no identity provider with that ID.")
		return
	case err != nil:
		renderIdPList(w, r, actor, http.StatusInternalServerError, "", idpUserMessage(err))
		return
	}
	v, _ := out.(idp.ProviderView)
	p, _ := idp.LookupPreset(v.Preset)
	tenants := strings.Join(v.AllowedTenants, "\n")
	f := buildIdPForm(p, formValues{
		id: v.ID, displayName: v.DisplayName, params: v.Params, clientID: v.ClientID,
		scopes: v.Scopes, claims: v.ClaimMap, trust: v.TrustEmail, signup: v.AllowSignup,
		idpLogout: v.IdPLogout, tenants: tenants, position: strconv.FormatInt(v.Position, 10), enabled: v.Enabled,
		metadataURL: v.MetadataURL, metadataXML: v.MetadataXML,
	}, true)
	f.SPCertPEM = v.SPCert
	f.SecretSet = v.SecretSet
	f.ReadOnly = v.ManagedBy == "env"
	f.Kind = v.Kind
	renderIdPForm(w, r, http.StatusOK, f)
}

func handleIdPCreate(w http.ResponseWriter, r *http.Request) {
	idpSave(w, r, "")
}

func handleIdPUpdate(w http.ResponseWriter, r *http.Request) {
	idpSave(w, r, chi.URLParam(r, "id"))
}

// idpSave handles the create (editID == "") and update forms.
func idpSave(w http.ResponseWriter, r *http.Request, editID string) {
	actor, ok := idpAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	editing := editID != ""
	fv := readFormValues(r, editID)
	p, ok := idp.LookupPreset(fv.preset)
	if !ok || fv.preset == "" {
		http.Redirect(w, r, views.IdPAdminBase, http.StatusSeeOther)
		return
	}
	in, perr := fv.input(editing)
	name := idp.ActionCreate
	if editing {
		name = idp.ActionUpdate
	}
	var err error
	if perr == nil {
		_, err = idpDispatch(r, actor, name, in)
	}
	if errors.Is(err, action.ErrForbidden) {
		idpForbidden(w, r)
		return
	}
	if perr != nil || err != nil {
		f := buildIdPForm(p, fv, editing)
		if perr != nil {
			f.Error = capitalise(perr.Error()) + "."
		} else {
			f.Error = idpUserMessage(err)
		}
		if editing {
			if out, gerr := idpDispatch(r, actor, idp.ActionGet, map[string]string{"id": editID}); gerr == nil {
				v, _ := out.(idp.ProviderView)
				f.SecretSet = v.SecretSet
				f.SPCertPEM = v.SPCert
				f.ReadOnly = v.ManagedBy == "env"
			}
		}
		renderIdPForm(w, r, http.StatusUnprocessableEntity, f)
		return
	}
	notice := "created"
	if editing {
		notice = "updated"
	}
	http.Redirect(w, r, views.IdPAdminBase+"?notice="+notice, http.StatusSeeOther)
}

// handleIdPVerb serves the enable / disable / delete buttons.
func handleIdPVerb(verb string) http.HandlerFunc {
	name := map[string]string{"enable": idp.ActionEnable, "disable": idp.ActionDisable, "delete": idp.ActionDelete}[verb]
	notice := map[string]string{"enable": "enabled", "disable": "disabled", "delete": "deleted"}[verb]
	return func(w http.ResponseWriter, r *http.Request) {
		actor, ok := idpAdmin(w, r)
		if !ok {
			return
		}
		_, err := idpDispatch(r, actor, name, map[string]string{"id": chi.URLParam(r, "id")})
		switch {
		case errors.Is(err, action.ErrForbidden):
			idpForbidden(w, r)
		case err != nil:
			renderIdPList(w, r, actor, http.StatusUnprocessableEntity, "", idpUserMessage(err))
		default:
			http.Redirect(w, r, views.IdPAdminBase+"?notice="+notice, http.StatusSeeOther)
		}
	}
}

// handleIdPDiscover is the "Test discovery" HTMX endpoint: it runs
// idp.discover for the preset and parameters currently in the form.
func handleIdPDiscover(w http.ResponseWriter, r *http.Request) {
	actor, ok := idpAdmin(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form body", http.StatusBadRequest)
		return
	}
	fv := readFormValues(r, "")
	out, err := idpDispatch(r, actor, idp.ActionDiscover, idp.DiscoverInput{Preset: fv.preset, Params: fv.params})
	if errors.Is(err, action.ErrForbidden) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	renderDiscover(w, r, out, err)
}

// formValues is the admin form as submitted (or as loaded for editing).
type formValues struct {
	id, preset, displayName, clientID, secret, scopes, tenants, position string
	metadataURL, metadataXML                                             string
	params, claims                                                       map[string]string
	trust, signup, enabled, idpLogout                                    bool
}

func readFormValues(r *http.Request, editID string) formValues {
	f := r.PostForm
	fv := formValues{
		id: strings.TrimSpace(f.Get("id")), preset: f.Get("preset"),
		displayName: f.Get("display_name"), clientID: f.Get("client_id"),
		secret: f.Get("client_secret"), scopes: f.Get("scopes"),
		tenants: f.Get("allowed_tenants"), position: strings.TrimSpace(f.Get("position")),
		params: map[string]string{}, claims: map[string]string{},
		trust: f.Get("trust_email") == "1", signup: f.Get("allow_signup") == "1",
		enabled: f.Get("enabled") == "1", idpLogout: f.Get("idp_logout") == "1",
		metadataURL: strings.TrimSpace(f.Get("metadata_url")), metadataXML: strings.TrimSpace(f.Get("metadata_xml")),
	}
	if editID != "" {
		fv.id = editID
	}
	for k, vs := range f {
		if len(vs) == 0 || strings.TrimSpace(vs[0]) == "" {
			continue
		}
		if name, ok := strings.CutPrefix(k, "param_"); ok {
			fv.params[name] = strings.TrimSpace(vs[0])
		}
		if name, ok := strings.CutPrefix(k, "claim_"); ok {
			fv.claims[name] = strings.TrimSpace(vs[0])
		}
	}
	return fv
}

// errFormPosition is the one form error checked before dispatch.
var errFormPosition = errors.New("position must be a whole number")

func (fv formValues) input(editing bool) (idp.ProviderInput, error) {
	trust, signup, logout := fv.trust, fv.signup, fv.idpLogout
	in := idp.ProviderInput{
		ID: fv.id, Preset: fv.preset, DisplayName: fv.displayName, Params: fv.params,
		ClientID: fv.clientID, ClientSecret: fv.secret, Scopes: fv.scopes, ClaimMap: fv.claims,
		TrustEmail: &trust, AllowSignup: &signup, IdPLogout: &logout,
		MetadataURL: fv.metadataURL, MetadataXML: fv.metadataXML,
	}
	in.AllowedTenants = strings.FieldsFunc(fv.tenants, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t'
	})
	if fv.position != "" {
		pos, err := strconv.ParseInt(fv.position, 10, 64)
		if err != nil || pos < 0 {
			return in, errFormPosition
		}
		in.Position = &pos
	}
	if !editing {
		enabled := fv.enabled
		in.Enabled = &enabled
	}
	return in, nil
}

var claimLabels = [][2]string{
	{"email", "Email"}, {"email_verified", "Email verified"}, {"name", "Name"},
	{"picture", "Picture"}, {"groups", "Groups"},
}

func buildIdPForm(p idp.Preset, fv formValues, editing bool) views.IdPForm {
	base := identityCfg().baseURL
	f := views.IdPForm{
		Editing: editing, ID: fv.id, Preset: p.ID, PresetName: p.DisplayName, Kind: p.Kind,
		DocsURL: p.DocsURL, DisplayName: fv.displayName, ClientID: fv.clientID,
		Scopes: fv.scopes, DefaultScopes: strings.Join(p.Scopes, " "),
		TrustEmail: fv.trust, AllowSignup: fv.signup, AllowedTenants: fv.tenants,
		Position: fv.position, Enabled: fv.enabled, ShowTenants: p.ID == "microsoft",
		IdPLogout: fv.idpLogout,
	}
	if f.DisplayName == "" && editing {
		f.DisplayName = p.DisplayName
	}
	cbID := fv.id
	if !editing {
		cbID = "your-id"
	}
	f.CallbackURL = idp.CallbackURL(base, cbID)
	f.PostLogoutURL = auth.PostLogoutRedirectURL(base)
	f.BackChannelURL = auth.BackChannelLogoutURL(base, cbID)
	if p.Kind == idp.KindSAML {
		setSAMLForm(&f, p, fv, base, cbID)
		return f
	}
	for _, pp := range p.Params {
		f.Params = append(f.Params, views.IdPParamField{
			Name: pp.Name, Label: pp.Label, Help: pp.Help, Value: fv.params[pp.Name],
			Default: pp.Default, Required: pp.Default == "",
		})
	}
	defaults := map[string]string{
		"email": p.Claims.Email, "email_verified": p.Claims.EmailVerified, "name": p.Claims.Name,
		"picture": p.Claims.Picture, "groups": p.Claims.Groups,
	}
	for _, c := range claimLabels {
		f.Claims = append(f.Claims, views.IdPClaimField{Key: c[0], Label: c[1], Value: fv.claims[c[0]], Default: defaults[c[0]]})
	}
	return f
}

func renderIdPForm(w http.ResponseWriter, r *http.Request, status int, f views.IdPForm) {
	title := "Add identity provider"
	if f.Editing {
		title = "Edit identity provider"
	}
	s := shellData(r, title, "/settings")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := views.IdPFormPage(s, f).Render(r.Context(), w); err != nil {
		slog.Error("render identity provider form", "err", err)
	}
}

// samlAttrLabels are the SAML attribute overrides on the form, with the
// defaults shown as placeholders.
var samlAttrLabels = [][3]string{
	{"subject", "Subject", "persistent NameID"},
	{"email", "Email", "emailaddress claim, mail or email"},
	{"name", "Name", "displayName or name claim (else given name + surname)"},
	{"groups", "Groups", "groups claim, groups or memberOf"},
}

// setSAMLForm fills the SAML parts of the provider form: SP details to give
// the IdP, metadata source and attribute overrides.
func setSAMLForm(f *views.IdPForm, p idp.Preset, fv formValues, base, id string) {
	f.MetadataURL, f.MetadataXML, f.MetadataHelp = fv.metadataURL, fv.metadataXML, p.MetadataHelp
	f.SAMLEntityID = auth.SAMLEntityID(base, id)
	f.SAMLACSURL = auth.SAMLACSURL(base, id)
	f.SAMLSLOURL = auth.SAMLSLOURL(base, id)
	f.SAMLCertURL = auth.SAMLCertificateURL(base, id)
	f.Claims = nil
	for _, c := range samlAttrLabels {
		f.Claims = append(f.Claims, views.IdPClaimField{Key: c[0], Label: c[1], Value: fv.claims[c[0]], Default: c[2]})
	}
}
