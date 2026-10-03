package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth/passkey"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Passkey routes (WU-612, SPEC §7.9). The begin endpoints only mint a
// challenge and seal the ceremony into the flow cookie: they change nothing
// on the server, so the anonymous ones are GETs (like GET /auth/{id}) and
// need no CSRF token. The anonymous finish endpoints are POSTs exempt from
// CSRF (SPEC §7.11): they are bound to the flow cookie's single-use
// challenge, which is SameSite=Lax, HttpOnly and sealed, so a cross-site
// request can neither read nor supply it. Adding a passkey while signed in
// is CSRF-protected like every other session POST.
const (
	PasskeyLoginBeginURL   = "/auth/passkey/login/begin"
	PasskeyLoginFinishURL  = "/auth/passkey/login/finish"
	PasskeySignupBeginURL  = "/auth/passkey/signup/begin"
	PasskeySignupFinishURL = "/auth/passkey/signup/finish"
	PasskeyAddBeginURL     = "/settings/passkeys/begin"
	PasskeyAddFinishURL    = "/settings/passkeys/finish"
)

// maxPasskeyBody bounds a posted WebAuthn response.
const maxPasskeyBody = 64 << 10

// maxSignupNameLen bounds the display name typed at passkey sign-up.
const maxSignupNameLen = 100

// passkeyCopy is the fixed copy for each passkey refusal. Anything not
// listed gets msgGeneric.
var passkeyCopy = map[string]string{
	RefusePasskeysOff:     "Passkeys are turned off on this instance. Use another way to sign in.",
	"passkeys_unavailable": "Passkeys aren't available on this instance. Use another way to sign in.",
	RefusePasskeyUnknown:  "That passkey isn't registered here. Sign in another way, or ask an organisation admin for an invite.",
	RefusePasskeyVerify:   "We couldn't verify that passkey. Please try again.",
	RefusePasskeyReplayed: "We couldn't verify that passkey. Please try again.",
	RefusePasskeyClone:    "This passkey can't be used because it looks like a copy. Sign in another way and remove it from your sign-in methods.",
	RefusePasskeyExists:   "That passkey is already registered.",
	RefusePasskeyLimit:    "You've reached the limit of 20 passkeys. Remove one before adding another.",
	RefuseInviteInvalid:   "This invite link is invalid, has expired or has already been used. Ask an organisation admin for a new one.",
	RefuseSetupInvalid:    "This setup link is no longer valid. The instance may already have been claimed.",
	RefuseAccountExists:   "An account already uses this email address. Sign in with it, then open the invite again.",
	RefuseUserDeleted:     "This account has been deleted.",
	RefuseNotBootstrap:    "This instance hasn't been set up yet.",
	RefuseLinkSession:     "Your session changed while adding the passkey. Please try again.",
	"flow_cookie":         "That took too long, or it was started in another tab. Please try again.",
	"name":                "Enter your name (up to 100 characters).",
	"email":               "Enter a valid email address.",
	"signed_out":          "Your session has ended. Sign in again to add a passkey.",
}

// PasskeysAvailable reports whether this instance can run passkey ceremonies
// at all: BC_BASE_URL's host must be usable as a WebAuthn RP ID.
func (h *Handler) PasskeysAvailable() bool { return h.Passkeys != nil }

// PasskeysOn reports whether passkeys are available and the platform setting
// passkeys_enabled is on.
func (h *Handler) PasskeysOn(ctx context.Context) bool {
	if h.Passkeys == nil || h.Resolver == nil || h.Resolver.DB == nil {
		return false
	}
	on, err := action.PasskeysEnabled(ctx, sqlc.New(h.Resolver.DB))
	if err != nil {
		slog.Error("auth: passkeys setting", "err", err)
		return false
	}
	return on
}

// passkeyRoutes mounts the passkey endpoints.
func (h *Handler) passkeyRoutes(r interface {
	Get(string, http.HandlerFunc)
	Post(string, http.HandlerFunc)
}) {
	r.Get(PasskeyLoginBeginURL, h.PasskeyLoginBegin)
	r.Post(PasskeyLoginFinishURL, h.PasskeyLoginFinish)
	r.Get(PasskeySignupBeginURL, h.PasskeySignupBegin)
	r.Post(PasskeySignupFinishURL, h.PasskeySignupFinish)
	r.Post(PasskeyAddBeginURL, h.PasskeyAddBegin)
	r.Post(PasskeyAddFinishURL, h.PasskeyAddFinish)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// passkeyFail logs err under a fresh reference code and answers JSON with the
// reason's fixed copy. Sign-in and sign-up failures (signIn) are audited as
// auth.login_failed like every other login failure; err is never sent.
func (h *Handler) passkeyFail(w http.ResponseWriter, r *http.Request, status int, reason string, signIn bool, err error) {
	ref := newRef()
	reqID := ""
	if h.RequestID != nil {
		reqID = h.RequestID(r.Context())
	}
	slog.Warn("auth: passkey ceremony failed",
		"ref", ref, "req_id", reqID, "reason", reason, "status", status, "err", err)
	if signIn {
		h.audit(r, "anonymous", "", "auth.login_failed", PasskeyProviderID, map[string]string{
			"reason": reason, "provider": PasskeyProviderID, "ref": ref,
		})
	}
	msg, ok := passkeyCopy[reason]
	if !ok {
		msg = msgGeneric
	}
	writeJSON(w, status, map[string]string{"error": msg, "ref": ref})
}

// passkeyGate answers for a disabled or unavailable feature and reports
// whether the request may go on.
func (h *Handler) passkeyGate(w http.ResponseWriter, r *http.Request, signIn bool) bool {
	if h.Passkeys == nil {
		h.passkeyFail(w, r, http.StatusNotFound, "passkeys_unavailable", signIn, errors.New("no relying party"))
		return false
	}
	if !h.PasskeysOn(r.Context()) {
		h.passkeyFail(w, r, http.StatusNotFound, RefusePasskeysOff, signIn, errors.New("passkeys_enabled is off"))
		return false
	}
	return true
}

// beginCeremony seals the ceremony into a fresh flow cookie and answers the
// options for the browser.
func (h *Handler) beginCeremony(w http.ResponseWriter, r *http.Request, flow *Flow, options, session []byte, signIn bool) {
	flow.WebAuthn = session
	if err := h.Flows.SetCookie(w, flow); err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "flow_seal", signIn, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(options)
}

// passkeyFlow opens the flow cookie for a finish endpoint, which must carry
// a ceremony of intent. The cookie is cleared whatever happens next.
func (h *Handler) passkeyFlow(w http.ResponseWriter, r *http.Request, intent string) (*Flow, error) {
	ClearFlowCookie(w)
	flow, err := h.Flows.FromRequest(r)
	if err != nil {
		return nil, err
	}
	if flow.ProviderID != PasskeyProviderID || flow.Intent != intent || len(flow.WebAuthn) == 0 {
		return nil, ErrFlowMismatch
	}
	return flow, nil
}

func readPasskeyBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPasskeyBody))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return body, nil
}

// useChallenge spends the ceremony's challenge: a verified response is
// accepted once, so a captured response replayed with a copy of the flow
// cookie is refused even when the authenticator keeps no counter.
func (h *Handler) useChallenge(flow *Flow) bool {
	ch, err := passkey.Challenge(flow.WebAuthn)
	if err != nil {
		return false
	}
	return h.Replay.Use("passkey:"+ch, time.Unix(flow.Exp, 0))
}

func (h *Handler) presentedSession(r *http.Request) string {
	if ck, err := r.Cookie(CookieName); err == nil {
		return ck.Value
	}
	return ""
}

// PasskeyLoginBegin is GET /auth/passkey/login/begin: options for a
// usernameless sign-in (?return_to= as for providers).
func (h *Handler) PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyGate(w, r, true) {
		return
	}
	flow, err := h.Flows.NewFlow(PasskeyProviderID, IntentPasskeyLogin)
	if err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "flow_create", true, err)
		return
	}
	flow.ReturnTo = SafeReturnTo(r.URL.Query().Get("return_to"))
	options, session, err := h.Passkeys.BeginLogin()
	if err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "begin", true, err)
		return
	}
	h.beginCeremony(w, r, flow, options, session, true)
}

// PasskeyLoginFinish is POST /auth/passkey/login/finish (CSRF-exempt, bound
// to the flow cookie): verify the assertion and sign the user in.
func (h *Handler) PasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	flow, err := h.passkeyFlow(w, r, IntentPasskeyLogin)
	if !h.passkeyGate(w, r, true) {
		return
	}
	if err != nil {
		h.passkeyFail(w, r, http.StatusBadRequest, "flow_cookie", true, err)
		return
	}
	body, err := readPasskeyBody(w, r)
	if err != nil {
		h.passkeyFail(w, r, http.StatusBadRequest, RefusePasskeyVerify, true, err)
		return
	}
	var row sqlc.FindWebAuthnCredentialForLoginRow
	lookup := func(rawID, _ []byte) (passkey.User, error) {
		got, err := sqlc.New(h.Resolver.DB).FindWebAuthnCredentialForLogin(r.Context(), rawID)
		if errors.Is(err, sql.ErrNoRows) {
			return passkey.User{}, passkey.ErrUnknownCredential
		}
		if err != nil {
			return passkey.User{}, err
		}
		row = got
		return passkey.User{
			Handle: got.WebauthnHandle, Name: got.Email, DisplayName: got.Name,
			Credentials: []passkey.Credential{credentialFromRow(got)},
		}, nil
	}
	res, err := h.Passkeys.FinishLogin(flow.WebAuthn, body, lookup)
	switch {
	case errors.Is(err, passkey.ErrUnknownCredential):
		h.passkeyFail(w, r, http.StatusForbidden, RefusePasskeyUnknown, true, err)
		return
	case err != nil:
		h.passkeyFail(w, r, http.StatusForbidden, RefusePasskeyVerify, true, err)
		return
	}
	if !h.useChallenge(flow) {
		h.passkeyFail(w, r, http.StatusForbidden, RefusePasskeyReplayed, true, errors.New("challenge already used"))
		return
	}
	// User verification is latched: a passkey that has verified its user
	// must keep doing so, so a later assertion without UV is not a quiet
	// downgrade to "someone holding the device".
	if row.UserVerified != 0 && !res.UserVerified {
		h.passkeyFail(w, r, http.StatusForbidden, RefusePasskeyVerify, true, errors.New("user verification missing for a UV credential"))
		return
	}
	lr, err := h.Resolver.PasskeyLogin(r.Context(), PasskeyLoginRequest{
		CredentialRowID: row.ID, UserID: row.UserID, Credential: res.Credential,
		PresentedSession: h.presentedSession(r), IP: ClientIP(r), UA: r.UserAgent(),
	})
	if err != nil {
		var ref *RefusedError
		if errors.As(err, &ref) {
			if ref.Reason == RefusePasskeyClone {
				h.audit(r, "user", row.UserID, "auth.passkey_clone_suspected", row.ID, map[string]string{
					"passkey_id": row.ID,
					"stored":     fmt.Sprint(res.StoredSignCount),
					"presented":  fmt.Sprint(res.Credential.SignCount),
				})
			}
			h.passkeyFail(w, r, http.StatusForbidden, ref.Reason, true, err)
			return
		}
		h.passkeyFail(w, r, http.StatusInternalServerError, "resolve", true, err)
		return
	}
	setSessionCookie(w, lr.RawToken, lr.Session.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": SafeReturnTo(flow.ReturnTo)})
}

func credentialFromRow(r sqlc.FindWebAuthnCredentialForLoginRow) passkey.Credential {
	var tr []string
	_ = json.Unmarshal([]byte(r.TransportsJson), &tr)
	return passkey.Credential{
		ID: r.CredentialID, PublicKey: r.PublicKey, SignCount: uint32(r.SignCount), //nolint:gosec // G115: stored from a uint32
		AAGUID: r.Aaguid, Transports: tr, AttestationType: r.AttestationType, AttestationFmt: r.AttestationFormat,
		UserVerified: r.UserVerified != 0, BackupEligible: r.BackupEligible != 0, BackupState: r.BackupState != 0,
	}
}

// normaliseSignupName trims a typed display name and refuses it when empty,
// too long or carrying control characters.
func normaliseSignupName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len([]rune(s)) > maxSignupNameLen {
		return "", false
	}
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return "", false
		}
	}
	return s, true
}

// normaliseSignupEmail accepts a bare address (no display name).
func normaliseSignupEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", false
	}
	return s, true
}

// PasskeySignupBegin is GET /auth/passkey/signup/begin?name=&invite= (or
// ?name=&email=&bootstrap=1 with the /setup cookie): options for creating an
// account whose first sign-in method is a passkey. Only a pending invite or
// the bootstrap token allows it (SPEC §7.9); both are checked again at
// finish, inside the transaction.
func (h *Handler) PasskeySignupBegin(w http.ResponseWriter, r *http.Request) {
	if !h.passkeyGate(w, r, true) {
		return
	}
	q := r.URL.Query()
	name, ok := normaliseSignupName(q.Get("name"))
	if !ok {
		h.passkeyFail(w, r, http.StatusBadRequest, "name", false, errors.New("bad name"))
		return
	}
	flow, err := h.Flows.NewFlow(PasskeyProviderID, IntentPasskeySignup)
	if err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "flow_create", true, err)
		return
	}
	db := sqlc.New(h.Resolver.DB)
	var email string
	switch {
	case q.Get("bootstrap") == "1":
		hash := h.Flows.setupHash(r)
		if valid, err := h.Resolver.Bootstrap.Valid(r.Context(), hash); err != nil || !valid || hash == "" {
			h.passkeyFail(w, r, http.StatusForbidden, RefuseSetupInvalid, true, err)
			return
		}
		if email, ok = normaliseSignupEmail(q.Get("email")); !ok {
			h.passkeyFail(w, r, http.StatusBadRequest, "email", false, errors.New("bad email"))
			return
		}
		flow.Intent, flow.Bootstrap, flow.BootstrapHash, flow.SignupEmail = IntentPasskeySignup, true, hash, email
	case q.Get("invite") != "" && len(q.Get("invite")) <= maxInviteTokenLen:
		inv, err := action.PendingInvite(r.Context(), db, q.Get("invite"), h.Sessions.now())
		if err != nil {
			h.passkeyFail(w, r, http.StatusForbidden, RefuseInviteInvalid, true, err)
			return
		}
		email, flow.InviteToken = inv.Email, q.Get("invite")
	default:
		h.passkeyFail(w, r, http.StatusForbidden, RefuseInviteInvalid, true, errors.New("no invite or bootstrap token"))
		return
	}
	if _, err := db.FindUserByEmailAnyState(r.Context(), email); err == nil {
		h.passkeyFail(w, r, http.StatusConflict, RefuseAccountExists, true, errors.New("email taken"))
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		h.passkeyFail(w, r, http.StatusInternalServerError, "lookup", true, err)
		return
	}
	handle := make([]byte, passkey.HandleLen)
	if _, err := rand.Read(handle); err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "handle", true, err)
		return
	}
	options, session, err := h.Passkeys.BeginRegistration(passkey.User{Handle: handle, Name: email, DisplayName: name})
	if err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "begin", true, err)
		return
	}
	flow.SignupName = name
	h.beginCeremony(w, r, flow, options, session, true)
}

// PasskeySignupFinish is POST /auth/passkey/signup/finish (CSRF-exempt,
// bound to the flow cookie): verify the new passkey, create the account,
// accept the invite or claim the platform, and sign in.
func (h *Handler) PasskeySignupFinish(w http.ResponseWriter, r *http.Request) {
	flow, err := h.passkeyFlow(w, r, IntentPasskeySignup)
	if !h.passkeyGate(w, r, true) {
		return
	}
	if err != nil {
		h.passkeyFail(w, r, http.StatusBadRequest, "flow_cookie", true, err)
		return
	}
	body, err := readPasskeyBody(w, r)
	if err != nil {
		h.passkeyFail(w, r, http.StatusBadRequest, RefusePasskeyVerify, true, err)
		return
	}
	handle, err := passkey.SessionUserHandle(flow.WebAuthn)
	if err != nil || len(handle) != passkey.HandleLen {
		h.passkeyFail(w, r, http.StatusBadRequest, "flow_cookie", true, err)
		return
	}
	cred, err := h.Passkeys.FinishRegistration(passkey.User{Handle: handle, Name: flow.SignupEmail, DisplayName: flow.SignupName}, flow.WebAuthn, body)
	if err != nil {
		h.passkeyFail(w, r, http.StatusForbidden, RefusePasskeyVerify, true, err)
		return
	}
	if !h.useChallenge(flow) {
		h.passkeyFail(w, r, http.StatusForbidden, RefusePasskeyReplayed, true, errors.New("challenge already used"))
		return
	}
	req := PasskeySignupRequest{
		Handle: handle, Name: flow.SignupName, InviteToken: flow.InviteToken, Credential: cred,
		PresentedSession: h.presentedSession(r), IP: ClientIP(r), UA: r.UserAgent(),
	}
	if flow.Bootstrap {
		req.BootstrapHash, req.Email, req.InviteToken = flow.BootstrapHash, flow.SignupEmail, ""
	}
	res, err := h.Resolver.PasskeySignup(r.Context(), req)
	if err != nil {
		var ref *RefusedError
		if errors.As(err, &ref) {
			h.passkeyFail(w, r, http.StatusForbidden, ref.Reason, true, err)
			return
		}
		h.passkeyFail(w, r, http.StatusInternalServerError, "resolve", true, err)
		return
	}
	if flow.Bootstrap {
		clearSetupCookie(w)
	}
	setSessionCookie(w, res.RawToken, res.Session.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": DefaultReturnTo})
}

// passkeyUser is the signed-in user's WebAuthn identity: the handle (created
// on first use) and the passkeys they already have.
func (h *Handler) passkeyUser(ctx context.Context, userID string) (passkey.User, error) {
	q := sqlc.New(h.Resolver.DB)
	u, err := q.GetUserWebAuthnHandle(ctx, userID)
	if err != nil {
		return passkey.User{}, fmt.Errorf("auth: passkey user: %w", err)
	}
	if u.DeletedAt.Valid {
		return passkey.User{}, refuse(RefuseUserDeleted)
	}
	if len(u.WebauthnHandle) == 0 {
		handle := make([]byte, passkey.HandleLen)
		if _, err := rand.Read(handle); err != nil {
			return passkey.User{}, fmt.Errorf("auth: passkey handle: %w", err)
		}
		if _, err := q.SetUserWebAuthnHandle(ctx, sqlc.SetUserWebAuthnHandleParams{Handle: handle, ID: userID}); err != nil {
			return passkey.User{}, fmt.Errorf("auth: set passkey handle: %w", err)
		}
		// Re-read: a concurrent request may have set it first.
		if u, err = q.GetUserWebAuthnHandle(ctx, userID); err != nil {
			return passkey.User{}, fmt.Errorf("auth: passkey user: %w", err)
		}
	}
	rows, err := q.ListUserWebAuthnCredentialIDs(ctx, userID)
	if err != nil {
		return passkey.User{}, fmt.Errorf("auth: list passkeys: %w", err)
	}
	pu := passkey.User{Handle: u.WebauthnHandle, Name: u.Email, DisplayName: u.Name}
	for _, c := range rows {
		var tr []string
		_ = json.Unmarshal([]byte(c.TransportsJson), &tr)
		pu.Credentials = append(pu.Credentials, passkey.Credential{ID: c.CredentialID, Transports: tr})
	}
	return pu, nil
}

// PasskeyAddBegin is POST /settings/passkeys/begin (signed in, CSRF): options
// for adding a passkey to the session user. The ceremony is bound to the
// session like an explicit link (SPEC §7.3 step 2).
func (h *Handler) PasskeyAddBegin(w http.ResponseWriter, r *http.Request) {
	sess, ok := SessionFrom(r.Context())
	if !ok || sess.TokenHash == "" {
		h.passkeyFail(w, r, http.StatusUnauthorized, "signed_out", false, errors.New("no session"))
		return
	}
	if !h.passkeyGate(w, r, false) {
		return
	}
	u, err := h.passkeyUser(r.Context(), sess.UserID)
	if err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "user", false, err)
		return
	}
	if len(u.Credentials) >= MaxPasskeysPerUser {
		h.passkeyFail(w, r, http.StatusConflict, RefusePasskeyLimit, false, errors.New("limit"))
		return
	}
	flow, err := h.Flows.NewFlow(PasskeyProviderID, IntentPasskeyRegister)
	if err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "flow_create", false, err)
		return
	}
	flow.LinkSessionHash = sess.TokenHash
	options, session, err := h.Passkeys.BeginRegistration(u)
	if err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "begin", false, err)
		return
	}
	h.beginCeremony(w, r, flow, options, session, false)
}

// PasskeyAddFinish is POST /settings/passkeys/finish (signed in, CSRF):
// verify the attestation and store the passkey.
func (h *Handler) PasskeyAddFinish(w http.ResponseWriter, r *http.Request) {
	flow, ferr := h.passkeyFlow(w, r, IntentPasskeyRegister)
	sess, ok := SessionFrom(r.Context())
	if !ok || sess.TokenHash == "" {
		h.passkeyFail(w, r, http.StatusUnauthorized, "signed_out", false, errors.New("no session"))
		return
	}
	if !h.passkeyGate(w, r, false) {
		return
	}
	if ferr != nil {
		h.passkeyFail(w, r, http.StatusBadRequest, "flow_cookie", false, ferr)
		return
	}
	if subtle.ConstantTimeCompare([]byte(flow.LinkSessionHash), []byte(sess.TokenHash)) != 1 {
		h.passkeyFail(w, r, http.StatusForbidden, RefuseLinkSession, false, errors.New("ceremony from another session"))
		return
	}
	body, err := readPasskeyBody(w, r)
	if err != nil {
		h.passkeyFail(w, r, http.StatusBadRequest, RefusePasskeyVerify, false, err)
		return
	}
	u, err := h.passkeyUser(r.Context(), sess.UserID)
	if err != nil {
		h.passkeyFail(w, r, http.StatusInternalServerError, "user", false, err)
		return
	}
	if handle, err := passkey.SessionUserHandle(flow.WebAuthn); err != nil || !bytes.Equal(handle, u.Handle) {
		h.passkeyFail(w, r, http.StatusForbidden, RefuseLinkSession, false, errors.New("ceremony for another user"))
		return
	}
	cred, err := h.Passkeys.FinishRegistration(u, flow.WebAuthn, body)
	if err != nil {
		h.passkeyFail(w, r, http.StatusForbidden, RefusePasskeyVerify, false, err)
		return
	}
	if !h.useChallenge(flow) {
		h.passkeyFail(w, r, http.StatusForbidden, RefusePasskeyReplayed, false, errors.New("challenge already used"))
		return
	}
	if _, err := h.Resolver.AddPasskey(r.Context(), sess.UserID, cred, ClientIP(r)); err != nil {
		var ref *RefusedError
		if errors.As(err, &ref) {
			h.passkeyFail(w, r, http.StatusConflict, ref.Reason, false, err)
			return
		}
		h.passkeyFail(w, r, http.StatusInternalServerError, "store", false, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": SignInMethodsURL + "?notice=passkey_added"})
}
