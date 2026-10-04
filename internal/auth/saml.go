package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// SAML 2.0 service-provider routes (SPEC §7.2, §7.7). The ACS and the SLO
// POST are on the CSRF exemption list (csrf_exempt.go): the identity
// provider posts to them cross-site, and they authenticate by signed XML,
// never by the session cookie.
const (
	SAMLACSPattern         = "/auth/saml/{providerID}/acs"
	SAMLSLOPattern         = "/auth/saml/{providerID}/slo"
	SAMLMetadataPattern    = "/auth/saml/{providerID}/metadata"
	SAMLCertificatePattern = "/auth/saml/{providerID}/certificate"
	// SAMLLinkPattern finishes an explicit link through a SAML provider: the
	// ACS cannot see the (SameSite=Lax) session cookie on the IdP's cross-site
	// POST, so it seals the verified identity into a short-lived cookie and
	// redirects here, a top-level GET that does carry the session.
	SAMLLinkPattern = "/auth/saml/{providerID}/link"

	// samlLinkCookie carries a verified SAML identity from the ACS to
	// SAMLLinkPattern; samlLinkTTL bounds that hop.
	samlLinkCookie = "__Host-bc_saml_link"
	samlLinkTTL    = 2 * time.Minute
	// maxSAMLBody bounds a POST to the ACS or SLO endpoint.
	maxSAMLBody = 1 << 20
)

// SAMLEntityID is a provider's SP entity id, which is also its metadata URL.
func SAMLEntityID(baseURL, providerID string) string {
	return trimSlash(baseURL) + "/auth/saml/" + providerID + "/metadata"
}

// SAMLACSURL is a provider's assertion consumer service URL (HTTP-POST).
func SAMLACSURL(baseURL, providerID string) string {
	return trimSlash(baseURL) + "/auth/saml/" + providerID + "/acs"
}

// SAMLSLOURL is a provider's single logout URL (HTTP-Redirect and POST).
func SAMLSLOURL(baseURL, providerID string) string {
	return trimSlash(baseURL) + "/auth/saml/" + providerID + "/slo"
}

// SAMLCertificateURL serves a provider's SP certificate (PEM).
func SAMLCertificateURL(baseURL, providerID string) string {
	return trimSlash(baseURL) + "/auth/saml/" + providerID + "/certificate"
}

// SAMLConnector is a SAML 2.0 provider. Begin sends an AuthnRequest and
// records its ID in the flow (Flow.SAMLRequestID); Complete verifies the
// POSTed SAMLResponse at the ACS. Callback refuses SAML connectors.
type SAMLConnector interface {
	Connector
	// SPMetadata is the SP metadata document (entity id, ACS, SLO, cert).
	SPMetadata() ([]byte, error)
	// SPCertificatePEM is the SP certificate; never the key.
	SPCertificatePEM() []byte
	// ParseSLO verifies a LogoutRequest or LogoutResponse received at the SLO
	// endpoint (either binding): signature, issuer, destination and time.
	ParseSLO(ctx context.Context, r *http.Request) (*SAMLLogoutMessage, error)
	// LogoutResponseURL is the IdP URL carrying a signed LogoutResponse
	// answering req (HTTP-Redirect binding).
	LogoutResponseURL(ctx context.Context, req *SAMLLogoutMessage) (string, error)
}

// SAMLLogoutMessage is a verified SLO message. For a LogoutRequest NameID
// is set and SessionIndexes may be; for a LogoutResponse Response is true.
type SAMLLogoutMessage struct {
	Response       bool
	ID             string
	NameID         string
	SessionIndexes []string
	RelayState     string
	// Expires is when the message stops being acceptable; its id is
	// remembered until then.
	Expires time.Time
}

// samlConnector resolves id to an enabled SAML provider, answering 404 for
// anything else.
func (h *Handler) samlConnector(w http.ResponseWriter, r *http.Request, id string) (SAMLConnector, bool) {
	c, ok := h.connector(w, r, id)
	if !ok {
		return nil, false
	}
	sc, ok := c.(SAMLConnector)
	if !ok {
		http.NotFound(w, r)
		return nil, false
	}
	return sc, true
}

// SAMLACS is POST /auth/saml/{providerID}/acs: the identity provider's
// HTTP-POST binding response to an SP-initiated AuthnRequest. The flow
// cookie (SameSite=None) must carry the request id the response answers and
// a RelayState equal to its state; unsolicited (IdP-initiated) responses are
// refused. The flow cookie is cleared on every outcome.
func (h *Handler) SAMLACS(w http.ResponseWriter, r *http.Request) {
	clearFlowCookie(w, http.SameSiteNoneMode)
	w.Header().Set("Cache-Control", "no-store")
	id := chi.URLParam(r, "providerID")
	c, ok := h.samlConnector(w, r, id)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSAMLBody)
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, http.StatusBadRequest, id, "form", err)
		return
	}
	flow, err := h.Flows.FromRequest(r)
	if err != nil {
		h.fail(w, r, http.StatusBadRequest, id, "flow_cookie", err)
		return
	}
	if flow.SAMLRequestID == "" {
		h.fail(w, r, http.StatusBadRequest, id, "state", errors.New("auth: flow has no SAML request id"))
		return
	}
	if err := flow.Matches(id, r.PostForm.Get("RelayState")); err != nil {
		h.fail(w, r, http.StatusBadRequest, id, "state", err)
		return
	}
	a, err := c.Complete(r.Context(), r, flow)
	if err != nil {
		h.fail(w, r, http.StatusForbidden, id, "assertion", err)
		return
	}
	a.ProviderID = id
	if flow.Intent == IntentLink {
		h.samlLinkBounce(w, r, c, id, flow, a)
		return
	}
	h.completeLogin(w, r, c, id, flow, a)
}

// pendingSAMLLink is the verified identity an ACS hands to SAMLLinkFinish.
type pendingSAMLLink struct {
	ProviderID      string `json:"p"`
	Subject         string `json:"s"`
	Email           string `json:"e,omitempty"`
	Name            string `json:"n,omitempty"`
	LinkSessionHash string `json:"ls"`
	Exp             int64  `json:"exp"`
}

func (h *Handler) samlLinkBounce(w http.ResponseWriter, r *http.Request, c Connector, id string, flow *Flow, a *Assertion) {
	v, err := h.Flows.sealAs(samlLinkCookie, pendingSAMLLink{
		ProviderID: id, Subject: a.Subject, Email: a.Email, Name: a.Name,
		LinkSessionHash: flow.LinkSessionHash, Exp: h.Flows.now().Add(samlLinkTTL).Unix(),
	})
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, id, "flow_seal", err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: samlLinkCookie, Value: v, Path: "/", MaxAge: int(samlLinkTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	// The id named an enabled provider (registry lookup) and ids are
	// [a-z0-9-]; the host is BaseURL.
	http.Redirect(w, r, h.BaseURL+"/auth/saml/"+c.ID()+"/link", http.StatusSeeOther) //nolint:gosec // G710: same-origin path, see above
}

// SAMLLinkFinish is GET /auth/saml/{providerID}/link: the second half of a
// SAML link flow, run with the browser's session cookie (WU-604 rules: the
// session must be the one that started the link).
func (h *Handler) SAMLLinkFinish(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, &http.Cookie{
		Name: samlLinkCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	id := chi.URLParam(r, "providerID")
	c, ok := h.samlConnector(w, r, id)
	if !ok {
		return
	}
	ck, err := r.Cookie(samlLinkCookie)
	if err != nil || ck.Value == "" {
		h.fail(w, r, http.StatusBadRequest, id, "flow_cookie", ErrFlowMissing)
		return
	}
	var p pendingSAMLLink
	if err := h.Flows.openAs(samlLinkCookie, ck.Value, &p); err != nil {
		h.fail(w, r, http.StatusBadRequest, id, "flow_cookie", err)
		return
	}
	if h.Flows.now().Unix() >= p.Exp || p.ProviderID != id || p.Subject == "" {
		h.fail(w, r, http.StatusBadRequest, id, "flow_cookie", ErrFlowExpired)
		return
	}
	presented := ""
	if sc, err := r.Cookie(CookieName); err == nil {
		presented = sc.Value
	}
	res, err := h.Resolver.Resolve(r.Context(), LoginRequest{
		Assertion: &Assertion{
			ProviderID: id, Subject: p.Subject, Email: p.Email, Name: p.Name,
		},
		Policy:           c.Policy(),
		AuthMethod:       c.AuthMethod(),
		PresentedSession: presented,
		IP:               ClientIP(r),
		UA:               r.UserAgent(),
		Intent:           IntentLink,
		LinkSessionHash:  p.LinkSessionHash,
	})
	h.finishLink(w, r, id, res, err)
}

// SAMLMetadata is GET /auth/saml/{providerID}/metadata: the public SP
// metadata of an enabled SAML provider.
func (h *Handler) SAMLMetadata(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "providerID")
	c, ok := h.samlConnector(w, r, id)
	if !ok {
		return
	}
	md, err := c.SPMetadata()
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, id, "metadata", err)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "no-cache")
	// XML we generate from the provider's configuration (entity id, URLs,
	// certificate), served as metadata, not HTML.
	_, _ = w.Write(md) //nolint:gosec // G705: generated SAML metadata, not HTML, see above
}

// SAMLCertificate is GET /auth/saml/{providerID}/certificate: the SP
// certificate as a PEM download (it is public; the key never leaves the
// database unencrypted).
func (h *Handler) SAMLCertificate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "providerID")
	c, ok := h.samlConnector(w, r, id)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+c.ID()+`-sp.crt"`)
	// A PEM certificate from the provider row, served as a download.
	_, _ = w.Write(c.SPCertificatePEM()) //nolint:gosec // G705: PEM attachment, not HTML, see above
}

// SAMLSLO is /auth/saml/{providerID}/slo (GET for HTTP-Redirect, POST for
// HTTP-POST). A LogoutResponse ends an SP-initiated logout: the local
// session is already gone, so whatever its validity the browser lands on
// the signed-out page (an invalid one is logged). A LogoutRequest is the
// IdP signing the user out: once verified and unreplayed, every session of
// that NameID (and SessionIndex, when given) through this provider is
// revoked and the browser goes back to the IdP with a signed
// LogoutResponse. Never reads the session cookie for authentication.
func (h *Handler) SAMLSLO(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := chi.URLParam(r, "providerID")
	c, ok := h.samlConnector(w, r, id)
	if !ok {
		return
	}
	bad := func(reason string, err error) {
		reqID := ""
		if h.RequestID != nil {
			reqID = h.RequestID(r.Context())
		}
		slog.Warn("auth: SAML logout refused", "req_id", reqID, "provider", id, "reason", reason, "err", err)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Invalid logout request.\n"))
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxSAMLBody)
	if err := r.ParseForm(); err != nil {
		bad("form", err)
		return
	}
	if r.Form.Get("SAMLResponse") != "" {
		if _, err := c.ParseSLO(r.Context(), r); err != nil {
			slog.Warn("auth: SAML logout response not valid; signed out locally", "provider", id, "err", err)
		}
		http.Redirect(w, r, SignedOutURL, http.StatusSeeOther)
		return
	}
	msg, err := c.ParseSLO(r.Context(), r)
	if err != nil {
		bad("message", err)
		return
	}
	if msg.Response || msg.NameID == "" || msg.ID == "" {
		bad("message", errors.New("not a logout request"))
		return
	}
	if !h.Replay.Use("saml-slo\x00"+id+"\x00"+msg.ID, msg.Expires) {
		bad("replay", nil)
		return
	}
	q := sqlc.New(h.Resolver.DB)
	var n int64
	matched := "name_id"
	if len(msg.SessionIndexes) > 0 {
		matched = "session_index"
		n, err = q.DeleteSessionsBySubjectSIDs(r.Context(), sqlc.DeleteSessionsBySubjectSIDsParams{
			ProviderID: id, IdpSubject: msg.NameID, Sids: msg.SessionIndexes,
		})
	} else {
		n, err = q.DeleteSessionsByIdPSubject(r.Context(), sqlc.DeleteSessionsByIdPSubjectParams{ProviderID: id, IdpSubject: msg.NameID})
	}
	if err != nil {
		bad("revoke", err)
		return
	}
	h.auditOrg(r, c.Policy().OrgID, "service", "idp:"+id, "auth.saml_logout", id, map[string]string{
		"provider": id, "matched": matched, "revoked": strconv.FormatInt(n, 10),
	})
	dest, err := c.LogoutResponseURL(r.Context(), msg)
	if err != nil {
		// The sessions are revoked; only the answer to the IdP failed.
		slog.Warn("auth: SAML logout response could not be built", "provider", id, "err", err)
		clearSessionCookie(w)
		http.Redirect(w, r, SignedOutURL, http.StatusSeeOther)
		return
	}
	clearSessionCookie(w)
	// gosec G710: dest is the IdP's SLO endpoint from its metadata (admin
	// configured); nothing in the request chooses the host.
	http.Redirect(w, r, dest, http.StatusSeeOther) //nolint:gosec // G710: host from IdP metadata, see above
}
