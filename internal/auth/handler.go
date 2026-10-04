package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth/passkey"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// LoginFailedHandler renders the generic sign-in failure page. The server
// overrides it with the templ error page; the default is plain text. message
// is fixed copy chosen by this package and ref is the log reference code;
// neither ever contains upstream or internal error text.
var LoginFailedHandler = func(w http.ResponseWriter, _ *http.Request, status int, message, ref string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "Sign-in failed. %s Reference: %s\n", message, ref)
}

// User-facing copy for login failures, by refusal reason. Everything not
// listed gets msgGeneric.
const msgGeneric = "Something went wrong signing you in. Please try again."

var refusalCopy = map[string]string{
	RefuseUserDeleted:     "This account has been deleted.",
	RefuseNotBootstrap:    "This instance hasn't been set up yet, and your email isn't on its administrator list.",
	RefuseNoAccount:       "There's no account for this email. Ask an organisation admin for an invite.",
	RefuseEmailUnverified: "Your identity provider didn't confirm your email address.",
	"logout":              "Something went wrong signing you out. Please try again.",
}

// LoginURL is the sign-in page (SPEC §7.2); SignedOutURL is where a local
// logout lands (SPEC §7.6); SignInMethodsURL is Settings -> Sign-in methods,
// where an explicit link starts and ends (WU-604).
const (
	LoginURL         = "/login"
	SignedOutURL     = "/login?signed_out=1"
	SignInMethodsURL = "/settings/sign-in-methods"
)

// maxInviteTokenLen bounds the invite token a flow will carry.
const maxInviteTokenLen = 128

// LoginURLFor is the sign-in page URL that returns to returnTo afterwards
// (validated by SafeReturnTo; the default destination is omitted).
func LoginURLFor(returnTo string) string {
	rt := SafeReturnTo(returnTo)
	if rt == DefaultReturnTo {
		return LoginURL
	}
	return LoginURL + "?return_to=" + url.QueryEscape(rt)
}

// Handler serves the login routes (SPEC §7.2): GET /auth/{providerID},
// GET /auth/{providerID}/callback, POST /auth/logout and the OIDC
// back-channel logout endpoint (logout.go).
type Handler struct {
	Providers ConnectorSource
	Flows     *FlowSealer
	Sessions  *SessionStore
	Resolver  *Resolver
	BaseURL   string
	// Replay remembers back-channel logout token ids (jti) and SAML
	// LogoutRequest ids.
	Replay *ReplayCache
	// RequestID returns the request id for log correlation (server wires
	// server.RequestID); nil logs without one.
	RequestID func(context.Context) string
	// Passkeys is the WebAuthn relying party (WU-612); nil when BC_BASE_URL's
	// host cannot be an RP ID, which turns passkeys off.
	Passkeys *passkey.RP
}

// HandlerConfig is everything NewHandler needs.
type HandlerConfig struct {
	DB          *sql.DB
	Sessions    *SessionStore
	SecretKey   string // raw BC_SECRET_KEY (flow cookie key derivation)
	EncKey      []byte // 32-byte key for _enc columns
	BaseURL     string
	AdminEmails []string
	// BootstrapToken is BC_BOOTSTRAP_TOKEN ("" = generated, see Bootstrap).
	BootstrapToken string
	// Providers resolves provider ids (production: the idp.Registry). When
	// nil, Connectors is used as a fixed set.
	Providers  ConnectorSource
	Connectors []Connector
	RequestID  func(context.Context) string
	// Events receives login-time events (membership.synced, WU-608).
	Events action.EventSink
}

// NewHandler builds the login handler.
func NewHandler(cfg HandlerConfig) (*Handler, error) {
	flows, err := NewFlowSealer(cfg.SecretKey)
	if err != nil {
		return nil, err
	}
	src := cfg.Providers
	if src == nil {
		src = NewStaticConnectors(cfg.Connectors...)
	}
	h := &Handler{
		Providers: src,
		Flows:     flows,
		Sessions:  cfg.Sessions,
		Resolver: &Resolver{
			DB:          cfg.DB,
			Sessions:    cfg.Sessions,
			AdminEmails: cfg.AdminEmails,
			SecretKey:   cfg.EncKey,
			Events:      cfg.Events,
			Bootstrap: &Bootstrap{
				DB: cfg.DB, EnvToken: cfg.BootstrapToken, AdminEmails: cfg.AdminEmails,
			},
		},
		BaseURL:   strings.TrimRight(cfg.BaseURL, "/"),
		Replay:    NewReplayCache(0),
		RequestID: cfg.RequestID,
	}
	if rp, err := passkey.New(cfg.BaseURL); err != nil {
		slog.Warn("auth: passkeys are unavailable on this instance", "err", err)
	} else {
		h.Passkeys = rp
	}
	return h, nil
}

// Routes mounts the login routes on r.
func (h *Handler) Routes(r chi.Router) {
	r.Get(SetupURL, h.Setup)
	r.Post("/auth/logout", h.Logout)
	r.Post(BackChannelLogoutPattern, h.BackChannelLogout)
	r.Post(SignInMethodsURL+"/link/{providerID}", h.BeginLink)
	r.Post(SAMLACSPattern, h.SAMLACS)
	r.Get(SAMLSLOPattern, h.SAMLSLO)
	r.Post(SAMLSLOPattern, h.SAMLSLO)
	r.Get(SAMLMetadataPattern, h.SAMLMetadata)
	r.Get(SAMLCertificatePattern, h.SAMLCertificate)
	r.Get(SAMLLinkPattern, h.SAMLLinkFinish)
	h.passkeyRoutes(r)
	r.Get("/auth/{providerID}", h.Begin)
	r.Get("/auth/{providerID}/callback", h.Callback)
}

// Begin starts a login: mints a flow, seals it into the flow cookie, and
// redirects to the provider.
func (h *Handler) Begin(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "providerID")
	c, ok := h.connector(w, r, id)
	if !ok {
		return
	}
	flow, err := h.Flows.NewFlow(id, IntentLogin)
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, id, "flow_create", err)
		return
	}
	if hint := r.URL.Query().Get("login_hint"); len(hint) <= 254 {
		flow.LoginHint = hint
	}
	flow.ReturnTo = SafeReturnTo(r.URL.Query().Get("return_to"))
	// An invite link's token rides the flow; resolution validates it.
	if inv := r.URL.Query().Get("invite"); len(inv) <= maxInviteTokenLen {
		flow.InviteToken = inv
	}
	// A claim-page button (?bootstrap=1) with a setup cookie whose token
	// still claims the platform makes this a bootstrap flow. Anything less
	// is an ordinary login; resolution re-checks the token either way.
	if r.URL.Query().Get("bootstrap") == "1" {
		if hash := h.Flows.setupHash(r); hash != "" {
			if ok, err := h.Resolver.Bootstrap.Valid(r.Context(), hash); err == nil && ok {
				flow.Intent, flow.Bootstrap, flow.BootstrapHash = IntentBootstrap, true, hash
			}
		}
	}
	h.redirectToProvider(w, r, c, id, flow)
}

// BeginLink is POST /settings/sign-in-methods/link/{providerID} (SPEC §7.3
// step 2): a signed-in user starts linking another sign-in method. The flow
// is bound to the current session's hash, which the callback requires the
// browser to still present. CSRF-protected by the global middleware.
func (h *Handler) BeginLink(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFrom(r.Context())
	if !ok || sess.TokenHash == "" {
		http.Redirect(w, r, LoginURLFor(SignInMethodsURL), http.StatusSeeOther)
		return
	}
	id := chi.URLParam(r, "providerID")
	c, ok := h.connector(w, r, id)
	if !ok {
		return
	}
	flow, err := h.Flows.NewFlow(id, IntentLink)
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, id, "flow_create", err)
		return
	}
	flow.LinkSessionHash = sess.TokenHash
	flow.ReturnTo = SignInMethodsURL
	h.toProvider(w, r, c, id, flow, true)
}

// redirectToProvider seals flow into the flow cookie and sends the browser
// to the provider.
func (h *Handler) redirectToProvider(w http.ResponseWriter, r *http.Request, c Connector, id string, flow *Flow) {
	h.toProvider(w, r, c, id, flow, false)
}

// toProvider seals flow into the flow cookie and sends the browser to the
// provider: by 303, or, for a form submission (fromForm), through the
// continue page, because CSP form-action 'self' blocks a form's redirect to
// another origin (ContinueTo).
func (h *Handler) toProvider(w http.ResponseWriter, r *http.Request, c Connector, id string, flow *Flow, fromForm bool) {
	dest, err := c.Begin(r.Context(), flow)
	if err != nil {
		h.fail(w, r, http.StatusBadGateway, id, "begin", err)
		return
	}
	if err := h.Flows.SetCookie(w, flow); err != nil {
		h.fail(w, r, http.StatusInternalServerError, id, "flow_seal", err)
		return
	}
	if fromForm {
		ContinueTo(w, dest)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// gosec G710 sees login_hint (request input) reach dest. It is only a
	// URL-encoded query value; the scheme and host come from operator config
	// or the provider's discovery document, so this is not an open redirect.
	http.Redirect(w, r, dest, http.StatusSeeOther) //nolint:gosec // G710: host fixed by provider config, see above
}

// connector resolves id, answering 404 for an unknown or disabled provider
// and the generic failure page for one that is misconfigured.
func (h *Handler) connector(w http.ResponseWriter, r *http.Request, id string) (Connector, bool) {
	c, err := h.Providers.Connector(r.Context(), id)
	switch {
	case err == nil:
		return c, true
	case errors.Is(err, ErrUnknownProvider):
		http.NotFound(w, r)
	default:
		h.fail(w, r, http.StatusBadGateway, id, "provider", err)
	}
	return nil, false
}

// Callback completes a login. The flow cookie is cleared on every outcome.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ClearFlowCookie(w)
	w.Header().Set("Cache-Control", "no-store")
	id := chi.URLParam(r, "providerID")
	c, ok := h.connector(w, r, id)
	if !ok {
		return
	}
	if _, saml := c.(SAMLConnector); saml {
		// SAML responses arrive only at the ACS (POST binding).
		http.NotFound(w, r)
		return
	}
	flow, err := h.Flows.FromRequest(r)
	if err != nil {
		h.fail(w, r, http.StatusBadRequest, id, "flow_cookie", err)
		return
	}
	if err := flow.Matches(id, r.URL.Query().Get("state")); err != nil {
		h.fail(w, r, http.StatusBadRequest, id, "state", err)
		return
	}
	a, err := c.Complete(r.Context(), r, flow)
	if err != nil {
		h.fail(w, r, http.StatusForbidden, id, "assertion", err)
		return
	}
	a.ProviderID = id
	h.completeLogin(w, r, c, id, flow, a)
}

// completeLogin resolves a verified assertion (SPEC §7.3) and finishes the
// flow: a new session and a redirect for a login, or the Sign-in methods
// page for a link. Shared by the OIDC/GitHub callback and the SAML ACS.
func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request, c Connector, id string, flow *Flow, a *Assertion) {
	presented := ""
	if ck, err := r.Cookie(CookieName); err == nil {
		presented = ck.Value
	}
	res, err := h.Resolver.Resolve(r.Context(), LoginRequest{
		Assertion:        a,
		Policy:           c.Policy(),
		AuthMethod:       c.AuthMethod(),
		PresentedSession: presented,
		IP:               ClientIP(r),
		UA:               r.UserAgent(),
		Intent:           flow.Intent,
		LinkSessionHash:  flow.LinkSessionHash,
		InviteToken:      flow.InviteToken,
		BootstrapHash:    bootstrapHash(flow),
	})
	if flow.Intent == IntentLink {
		h.finishLink(w, r, id, res, err)
		return
	}
	if err != nil {
		var ref *RefusedError
		if errors.As(err, &ref) {
			h.fail(w, r, http.StatusForbidden, id, ref.Reason, err)
			return
		}
		h.fail(w, r, http.StatusInternalServerError, id, "resolve", err)
		return
	}
	if flow.Bootstrap {
		clearSetupCookie(w)
	}
	setSessionCookie(w, res.RawToken, res.Session.ExpiresAt)
	dest := SafeReturnTo(flow.ReturnTo)
	if res.InviteOrgID != "" {
		// The invite was accepted with the sign-up; its landing page (the
		// usual return_to for invite flows) has nothing left to do.
		dest = DefaultReturnTo
	}
	// Re-validated: the cookie is sealed, but the check is cheap and keeps
	// the redirect target provably same-origin.
	http.Redirect(w, r, h.BaseURL+dest, http.StatusSeeOther) //nolint:gosec // G710: BaseURL + a SafeReturnTo path, see above
}

// finishLink ends a link flow back on the Sign-in methods page. The session
// cookie is left alone: linking issues no new session. A refusal travels as
// its fixed reason code (the page maps known codes to copy); anything else
// gets the generic failure page.
func (h *Handler) finishLink(w http.ResponseWriter, r *http.Request, id string, res *LoginResult, err error) {
	if err != nil {
		var ref *RefusedError
		if !errors.As(err, &ref) {
			h.fail(w, r, http.StatusInternalServerError, id, "link", err)
			return
		}
		slog.Warn("auth: link refused", "provider", id, "reason", ref.Reason)
		http.Redirect(w, r, h.BaseURL+SignInMethodsURL+"?error="+url.QueryEscape(ref.Reason), http.StatusSeeOther)
		return
	}
	notice := "linked"
	if res.AlreadyLinked {
		notice = "already_linked"
	}
	http.Redirect(w, r, h.BaseURL+SignInMethodsURL+"?notice="+notice, http.StatusSeeOther)
}

// fail logs err with a fresh reference code and renders the generic failure
// page. err is never written to the client.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, status int, provider, reason string, err error) {
	ref := newRef()
	reqID := ""
	if h.RequestID != nil {
		reqID = h.RequestID(r.Context())
	}
	slog.Warn("auth: login failed",
		"ref", ref, "req_id", reqID, "provider", provider, "reason", reason, "status", status, "err", err)
	if reason != "logout" {
		// auth.login_failed (SPEC §7.3 step 6): the fixed reason code and the
		// reference only; never err, tokens, codes or claims.
		h.audit(r, "anonymous", "", "auth.login_failed", provider, map[string]string{
			"reason": reason, "provider": provider, "ref": ref,
		})
	}
	msg, ok := refusalCopy[reason]
	if !ok {
		msg = msgGeneric
	}
	LoginFailedHandler(w, r, status, msg, ref)
}

// maxAuditUA bounds the user agent kept in an audit row.
const maxAuditUA = 256

func truncateUA(ua string) string {
	if len(ua) > maxAuditUA {
		return ua[:maxAuditUA]
	}
	return ua
}

// audit writes an authentication audit row outside any transaction, best
// effort: a failed write is logged and the response carries on. The client
// IP and user agent are added here.
func (h *Handler) audit(r *http.Request, actorType, actorID, act, subject string, detail map[string]string) {
	if h.Resolver == nil || h.Resolver.DB == nil {
		return
	}
	detail["ua"] = truncateUA(r.UserAgent())
	now := h.Sessions.now().UTC().Format(timeFormat)
	if err := writeAuditAs(r.Context(), sqlc.New(h.Resolver.DB), actorType, actorID, act, subject,
		ClientIP(r), now, detail); err != nil {
		slog.Error("auth: audit", "action", act, "err", err)
	}
}

// newRef returns a short reference code users can quote to an admin.
func newRef() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// newID returns a random hex id (16 bytes).
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("auth: crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// bootstrapHash is the token hash a bootstrap flow proved ("" otherwise).
func bootstrapHash(f *Flow) string {
	if !f.Bootstrap {
		return ""
	}
	return f.BootstrapHash
}
