package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// Logout routes and constants (SPEC §7.6).
const (
	// BackChannelLogoutPattern is the OIDC back-channel logout route. It is
	// on the CSRF exemption list (csrf_exempt.go).
	BackChannelLogoutPattern = "/auth/oidc/{providerID}/backchannel-logout"
	// BackChannelLogoutEvent is the events member a logout token must carry
	// (OIDC Back-Channel Logout 1.0 §2.4).
	BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
	// LogoutTokenSkew is how far a logout token's iat may be from now, either
	// way. A token's jti is remembered for this long past its iat, which is
	// as long as the token could be accepted.
	LogoutTokenSkew = 5 * time.Minute
	// maxLogoutBody bounds the back-channel request body.
	maxLogoutBody = 64 << 10
)

// BackChannelLogoutURL is the back-channel logout URI admins register with
// a provider.
func BackChannelLogoutURL(baseURL, providerID string) string {
	return trimSlash(baseURL) + "/auth/oidc/" + providerID + "/backchannel-logout"
}

// PostLogoutRedirectURL is the post_logout_redirect_uri sent with
// RP-initiated logout; admins register it with the provider.
func PostLogoutRedirectURL(baseURL string) string {
	return trimSlash(baseURL) + SignedOutURL
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// EndSessionRequest is what RP-initiated logout sends to the provider.
type EndSessionRequest struct {
	IDTokenHint           string
	PostLogoutRedirectURI string
	State                 string
}

// RPLogoutConnector is implemented by connectors that can end the session at
// the identity provider (OIDC RP-Initiated Logout). EndSessionURL returns ""
// with a nil error when the provider has no end-session endpoint or the
// admin turned IdP sign-out off.
type RPLogoutConnector interface {
	EndSessionURL(ctx context.Context, req EndSessionRequest) (string, error)
}

// LogoutToken is a verified back-channel logout token. At least one of SID
// and Subject is set; JTI is always set.
type LogoutToken struct {
	Subject  string
	SID      string
	JTI      string
	IssuedAt time.Time
}

// BackChannelLogoutConnector is implemented by connectors that accept OIDC
// back-channel logout tokens. VerifyLogoutToken checks everything about the
// token itself (signature, iss, aud, iat, exp, events, sid/sub, no nonce,
// jti present); replay is the handler's job.
type BackChannelLogoutConnector interface {
	VerifyLogoutToken(ctx context.Context, raw string) (*LogoutToken, error)
}

// Logout revokes the current session and clears its cookie. When the
// session signed in through a provider that supports RP-initiated logout
// (and the admin left "sign out of the identity provider too" on), the
// browser continues to the provider's end-session endpoint with the ID token
// as id_token_hint; otherwise, or if anything about that fails, it lands on
// the signed-out page. It sits behind the global CSRF middleware.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	dest := SignedOutURL
	if ck, err := r.Cookie(CookieName); err == nil && ck.Value != "" {
		th := hashToken(ck.Value)
		var info sqlc.GetSessionLogoutInfoRow
		if h.Resolver != nil && h.Resolver.DB != nil {
			info, err = sqlc.New(h.Resolver.DB).GetSessionLogoutInfo(r.Context(), th)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				slog.Warn("auth: logout: session provenance", "err", err)
			}
		}
		if err := h.Sessions.Revoke(r.Context(), ck.Value); err != nil {
			clearSessionCookie(w)
			h.fail(w, r, http.StatusInternalServerError, "", "logout", err)
			return
		}
		// Audit, and consider IdP logout, only for a real sign-out: the
		// session middleware resolved this cookie to a live session.
		if sess, ok := SessionFrom(r.Context()); ok && sess.UserID != "" && sess.TokenHash == th {
			idpURL := h.endSessionURL(r.Context(), info.ProviderID, info.IDTokenEnc)
			detail := map[string]string{"provider": sess.ProviderID, "method": sess.AuthMethod}
			if idpURL != "" {
				detail["idp_logout"] = "1"
				dest = idpURL
			}
			h.audit(r, "user", sess.UserID, "auth.logout", sess.ProviderID, detail)
		}
	}
	clearSessionCookie(w)
	w.Header().Set("Cache-Control", "no-store")
	// gosec G710: dest is either the fixed signed-out path or the end-session
	// endpoint from the provider's own discovery document (operator or org
	// owner configured); nothing in the request chooses the host.
	http.Redirect(w, r, dest, http.StatusSeeOther) //nolint:gosec // G710: host from provider config, see above
}

// endSessionURL is the provider's end-session URL for a session, or "" to
// fall back to local logout (no provider, provider gone or disabled, IdP
// sign-out unsupported or off, ID token missing or undecryptable).
func (h *Handler) endSessionURL(ctx context.Context, providerID, idTokenEnc string) string {
	if providerID == "" || idTokenEnc == "" || h.Providers == nil {
		return ""
	}
	c, err := h.Providers.Connector(ctx, providerID)
	if err != nil {
		return ""
	}
	rp, ok := c.(RPLogoutConnector)
	if !ok {
		return ""
	}
	var key []byte
	if h.Resolver != nil {
		key = h.Resolver.SecretKey
	}
	hint, err := tenant.Decrypt(key, idTokenEnc)
	if err != nil {
		slog.Warn("auth: logout: id token cannot be decrypted; signing out locally only", "provider", providerID)
		return ""
	}
	u, err := rp.EndSessionURL(ctx, EndSessionRequest{
		IDTokenHint:           hint,
		PostLogoutRedirectURI: PostLogoutRedirectURL(h.BaseURL),
		State:                 newID(),
	})
	if err != nil {
		slog.Warn("auth: logout: end-session endpoint unavailable; signing out locally only", "provider", providerID, "err", err)
		return ""
	}
	return u
}

// BackChannelLogout is POST /auth/oidc/{providerID}/backchannel-logout (OIDC
// Back-Channel Logout 1.0). The identity provider posts a signed
// logout_token; a valid, unreplayed token revokes the sessions it names.
// CSRF-exempt and never reads the session cookie: the token is the only
// authentication. Responses carry no detail.
func (h *Handler) BackChannelLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := chi.URLParam(r, "providerID")
	bad := func(reason string, err error) {
		reqID := ""
		if h.RequestID != nil {
			reqID = h.RequestID(r.Context())
		}
		slog.Warn("auth: back-channel logout refused", "req_id", reqID, "provider", id, "reason", reason, "err", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}` + "\n"))
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBody)
	if err := r.ParseForm(); err != nil {
		bad("form", err)
		return
	}
	raw := r.PostForm.Get("logout_token")
	if raw == "" {
		bad("no_token", nil)
		return
	}
	c, err := h.Providers.Connector(r.Context(), id)
	if err != nil {
		bad("provider", err)
		return
	}
	bc, ok := c.(BackChannelLogoutConnector)
	if !ok {
		bad("unsupported", nil)
		return
	}
	lt, err := bc.VerifyLogoutToken(r.Context(), raw)
	if err != nil {
		bad("token", err)
		return
	}
	if !h.Replay.Use(id+"\x00"+lt.JTI, lt.IssuedAt.Add(LogoutTokenSkew)) {
		bad("replay", nil)
		return
	}

	q := sqlc.New(h.Resolver.DB)
	var n int64
	matched := "sid"
	switch {
	case lt.SID != "" && lt.Subject != "":
		n, err = q.DeleteSessionsByIdPSIDSubject(r.Context(), sqlc.DeleteSessionsByIdPSIDSubjectParams{
			ProviderID: id, IdpSid: lt.SID, IdpSubject: lt.Subject,
		})
	case lt.SID != "":
		n, err = q.DeleteSessionsByIdPSID(r.Context(), sqlc.DeleteSessionsByIdPSIDParams{ProviderID: id, IdpSid: lt.SID})
	default:
		matched = "sub"
		n, err = q.DeleteSessionsByIdPSubject(r.Context(), sqlc.DeleteSessionsByIdPSubjectParams{ProviderID: id, IdpSubject: lt.Subject})
	}
	if err != nil {
		bad("revoke", err)
		return
	}
	h.auditOrg(r, c.Policy().OrgID, "service", "idp:"+id, "auth.backchannel_logout", id, map[string]string{
		"provider": id, "matched": matched, "revoked": strconv.FormatInt(n, 10),
	})
	w.WriteHeader(http.StatusOK)
}

// auditOrg is audit for an event that belongs to an org's audit log when
// orgID is set (an org-owned provider) and to the platform log otherwise.
func (h *Handler) auditOrg(r *http.Request, orgID, actorType, actorID, act, subject string, detail map[string]string) {
	if orgID == "" {
		h.audit(r, actorType, actorID, act, subject, detail)
		return
	}
	if h.Resolver == nil || h.Resolver.DB == nil {
		return
	}
	detail["ua"] = truncateUA(r.UserAgent())
	dj, err := json.Marshal(detail)
	if err == nil {
		err = sqlc.New(h.Resolver.DB).CreateAuditLog(r.Context(), sqlc.CreateAuditLogParams{
			ID: newID(), OrgID: sql.NullString{String: orgID, Valid: true}, ActorType: actorType, ActorID: actorID,
			Action: act, Subject: subject, DetailJson: string(dj), Ip: ClientIP(r),
			CreatedAt: h.Sessions.now().UTC().Format(timeFormat),
		})
	}
	if err != nil {
		slog.Error("auth: audit", "action", act, "err", fmt.Errorf("org %s: %w", orgID, err))
	}
}
