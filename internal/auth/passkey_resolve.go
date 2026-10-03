package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth/passkey"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Passkey resolution (WU-612, SPEC §7.9). Like the IdP login (resolve.go),
// every write runs in one IMMEDIATE transaction through internal functions
// and writes its own audit rows: these are authentication events, not
// actions.

// PasskeyProviderID is the provider id recorded on passkey sessions and in
// audit rows. It is reserved (idp.ValidateID refuses it), so it is never an
// organisation's provider and SSO-enforced organisations refuse passkey
// sessions (SPEC §7.4).
const PasskeyProviderID = "passkey"

// MaxPasskeysPerUser bounds how many passkeys one account may register.
const MaxPasskeysPerUser = 20

// Passkey refusal reasons (fixed codes, mapped to copy by the handler).
const (
	RefusePasskeysOff     = "passkeys_disabled"
	RefusePasskeyClone    = "passkey_clone"
	RefusePasskeyExists   = "passkey_exists"
	RefusePasskeyLimit    = "passkey_limit"
	RefuseInviteInvalid   = "invite_invalid"
	RefuseSetupInvalid    = "setup_invalid"
	RefuseAccountExists   = "account_exists"
	RefusePasskeyUnknown  = "passkey_unknown"
	RefusePasskeyVerify   = "passkey_verify"
	RefusePasskeyReplayed = "passkey_replay"
)

// PasskeyLoginRequest is a verified assertion to turn into a session.
type PasskeyLoginRequest struct {
	CredentialRowID  string
	UserID           string
	Credential       passkey.Credential
	PresentedSession string
	IP, UA           string
}

// PasskeyLogin records a verified passkey assertion and signs the user in:
// it re-reads the stored sign count inside the transaction and refuses a
// count that did not advance (a cloned authenticator; the caller audits
// auth.passkey_clone_suspected), updates the credential, rotates any
// presented session and creates a passkey session.
func (rv *Resolver) PasskeyLogin(ctx context.Context, req PasskeyLoginRequest) (*LoginResult, error) {
	now := rv.Sessions.now().UTC().Format(timeFormat)
	var res *LoginResult
	err := immediateTx(ctx, rv.DB, func(q *sqlc.Queries) error {
		ps, err := q.GetPlatformSettings(ctx)
		if err != nil {
			return fmt.Errorf("auth: platform settings: %w", err)
		}
		if !action.PasskeysEnabledIn(ps.SettingsJson) {
			return refuse(RefusePasskeysOff)
		}
		if ps.BootstrapDone == 0 {
			return refuse(RefuseNotBootstrap)
		}
		u, err := q.GetUserWebAuthnHandle(ctx, req.UserID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (u.DeletedAt.Valid || u.ID == formerMemberUserID)) {
			return refuse(RefuseUserDeleted)
		}
		if err != nil {
			return fmt.Errorf("auth: passkey user: %w", err)
		}
		cur, err := q.GetWebAuthnCredentialCount(ctx, req.CredentialRowID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && cur.UserID != req.UserID) {
			return refuse(RefusePasskeyUnknown) // deleted while signing in
		}
		if err != nil {
			return fmt.Errorf("auth: passkey count: %w", err)
		}
		if SignCountRegressed(uint32(cur.SignCount), req.Credential.SignCount) { //nolint:gosec // G115: sign_count is stored from a uint32
			return refuse(RefusePasskeyClone)
		}
		if _, err := q.UpdateWebAuthnCredentialLogin(ctx, sqlc.UpdateWebAuthnCredentialLoginParams{
			SignCount:    int64(req.Credential.SignCount),
			UserVerified: boolInt(req.Credential.UserVerified),
			BackupState:  boolInt(req.Credential.BackupState),
			LastUsedAt:   sql.NullString{String: now, Valid: true},
			ID:           req.CredentialRowID,
			UserID:       req.UserID,
		}); err != nil {
			return fmt.Errorf("auth: passkey update: %w", err)
		}
		if req.PresentedSession != "" {
			if err := q.DeleteSession(ctx, hashToken(req.PresentedSession)); err != nil {
				return fmt.Errorf("auth: revoke presented session: %w", err)
			}
		}
		raw, sess, err := rv.Sessions.create(ctx, q, req.UserID, req.IP, req.UA,
			SessionMeta{ProviderID: PasskeyProviderID, AuthMethod: AuthMethodPasskey})
		if err != nil {
			return err
		}
		res = &LoginResult{UserID: req.UserID, RawToken: raw, Session: sess}
		return writeAudit(ctx, q, req.UserID, "auth.login", PasskeyProviderID, req.IP, now, map[string]string{
			"provider": PasskeyProviderID, "method": AuthMethodPasskey, "passkey_id": req.CredentialRowID,
			"ua": truncateUA(req.UA),
		})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// SignCountRegressed is the clone check (WebAuthn §6.1.1): once a credential
// has reported a non-zero signature counter, every assertion must report a
// larger one. Authenticators without a counter (synced passkeys) always
// report 0 and are never flagged.
func SignCountRegressed(stored, got uint32) bool {
	return stored > 0 && got <= stored
}

// PasskeySignupRequest creates an account whose first sign-in method is a
// passkey (SPEC §7.9): with a pending invite or the bootstrap token.
type PasskeySignupRequest struct {
	Handle      []byte
	Name        string
	Email       string // bootstrap claims only; an invite supplies its own
	InviteToken string
	// BootstrapHash is the bootstrap token hash proven at /setup.
	BootstrapHash    string
	Credential       passkey.Credential
	PresentedSession string
	IP, UA           string
}

// PasskeySignup creates the user, stores the passkey, accepts the invite or
// claims the platform (re-checking the token against the platform inside
// the transaction, so of racing claims only the first wins), and signs the
// new user in.
func (rv *Resolver) PasskeySignup(ctx context.Context, req PasskeySignupRequest) (*LoginResult, error) {
	now := rv.Sessions.now().UTC().Format(timeFormat)
	var res *LoginResult
	err := immediateTx(ctx, rv.DB, func(q *sqlc.Queries) error {
		ps, err := q.GetPlatformSettings(ctx)
		if err != nil {
			return fmt.Errorf("auth: platform settings: %w", err)
		}
		if !action.PasskeysEnabledIn(ps.SettingsJson) {
			return refuse(RefusePasskeysOff)
		}
		email, verified, method := "", int64(1), ""
		switch {
		case req.BootstrapHash != "":
			if !rv.Bootstrap.claims(ps, req.BootstrapHash) {
				return refuse(RefuseSetupInvalid)
			}
			if err := q.SetBootstrapDone(ctx); err != nil {
				return fmt.Errorf("auth: mark bootstrapped: %w", err)
			}
			// The claimant typed the address; nobody has confirmed it.
			email, verified, method = req.Email, 0, SignupBootstrap
		case req.InviteToken != "":
			if ps.BootstrapDone == 0 {
				return refuse(RefuseNotBootstrap)
			}
			inv, err := action.PendingInvite(ctx, q, req.InviteToken, rv.Sessions.now())
			if errors.Is(err, action.ErrInviteInvalid) {
				return refuse(RefuseInviteInvalid)
			}
			if err != nil {
				return fmt.Errorf("auth: invite: %w", err)
			}
			email, method = inv.Email, SignupInvite
		default:
			return refuse(RefuseInviteInvalid)
		}
		if email == "" {
			return refuse(RefuseInviteInvalid)
		}
		if _, err := q.FindUserByEmailAnyState(ctx, email); err == nil {
			return refuse(RefuseAccountExists)
		} else if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("auth: find user by email: %w", err)
		}
		if err := passkeyNotRegistered(ctx, q, req.Credential.ID); err != nil {
			return err
		}
		userID := newID()
		if err := q.CreateUserWithPasskey(ctx, sqlc.CreateUserWithPasskeyParams{
			ID: userID, Email: email, Name: req.Name, WebauthnHandle: req.Handle, EmailVerified: verified,
		}); err != nil {
			return fmt.Errorf("auth: create user: %w", err)
		}
		pkID, name, err := insertPasskey(ctx, q, userID, req.Credential, now)
		if err != nil {
			return err
		}
		res = &LoginResult{UserID: userID, Created: true, SignupMethod: method}
		detail := map[string]string{"provider": PasskeyProviderID, "method": method}
		switch method {
		case SignupInvite:
			acc, err := action.AcceptInvite(ctx, q, req.InviteToken, userID, rv.Sessions.now())
			if err != nil {
				return fmt.Errorf("auth: accept invite at sign-up: %w", err)
			}
			res.InviteOrgID = acc.OrgID
			detail["invite_id"], detail["org_id"] = acc.InviteID, acc.OrgID
		case SignupBootstrap:
			detail["email_verified"] = "0"
			if err := ensurePlatformAdmin(ctx, q, userID); err != nil {
				return err
			}
		}
		if err := writeAudit(ctx, q, userID, "auth.signup", PasskeyProviderID, req.IP, now, detail); err != nil {
			return err
		}
		if method == SignupBootstrap {
			if err := writeAudit(ctx, q, userID, "auth.bootstrap", PasskeyProviderID, req.IP, now,
				map[string]string{"provider": PasskeyProviderID, "via": "token"}); err != nil {
				return err
			}
		}
		if err := writeAudit(ctx, q, userID, "passkey.registered", pkID, req.IP, now,
			map[string]string{"passkey_id": pkID, "name": name}); err != nil {
			return err
		}
		if req.PresentedSession != "" {
			if err := q.DeleteSession(ctx, hashToken(req.PresentedSession)); err != nil {
				return fmt.Errorf("auth: revoke presented session: %w", err)
			}
		}
		raw, sess, err := rv.Sessions.create(ctx, q, userID, req.IP, req.UA,
			SessionMeta{ProviderID: PasskeyProviderID, AuthMethod: AuthMethodPasskey})
		if err != nil {
			return err
		}
		res.RawToken, res.Session = raw, sess
		return writeAudit(ctx, q, userID, "auth.login", PasskeyProviderID, req.IP, now, map[string]string{
			"provider": PasskeyProviderID, "method": AuthMethodPasskey, "passkey_id": pkID, "ua": truncateUA(req.UA),
		})
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// AddPasskey stores a passkey a signed-in user just registered.
func (rv *Resolver) AddPasskey(ctx context.Context, userID string, c passkey.Credential, ip string) (string, error) {
	now := rv.Sessions.now().UTC().Format(timeFormat)
	var id string
	err := immediateTx(ctx, rv.DB, func(q *sqlc.Queries) error {
		on, err := action.PasskeysEnabled(ctx, q)
		if err != nil {
			return err
		}
		if !on {
			return refuse(RefusePasskeysOff)
		}
		n, err := q.CountUserWebAuthnCredentials(ctx, userID)
		if err != nil {
			return fmt.Errorf("auth: count passkeys: %w", err)
		}
		if n >= MaxPasskeysPerUser {
			return refuse(RefusePasskeyLimit)
		}
		if err := passkeyNotRegistered(ctx, q, c.ID); err != nil {
			return err
		}
		pkID, name, err := insertPasskey(ctx, q, userID, c, now)
		if err != nil {
			return err
		}
		id = pkID
		return writeAudit(ctx, q, userID, "passkey.registered", pkID, ip, now,
			map[string]string{"passkey_id": pkID, "name": name})
	})
	return id, err
}

// passkeyNotRegistered refuses a credential id that is already stored.
func passkeyNotRegistered(ctx context.Context, q *sqlc.Queries, credID []byte) error {
	_, err := q.FindWebAuthnCredentialForLogin(ctx, credID)
	switch {
	case err == nil:
		return refuse(RefusePasskeyExists)
	case errors.Is(err, sql.ErrNoRows):
		return nil
	default:
		return fmt.Errorf("auth: find passkey: %w", err)
	}
}

func insertPasskey(ctx context.Context, q *sqlc.Queries, userID string, c passkey.Credential, now string) (id, name string, err error) {
	tr, err := json.Marshal(c.Transports)
	if err != nil {
		return "", "", fmt.Errorf("auth: passkey transports: %w", err)
	}
	aaguid := c.AAGUID
	if aaguid == nil {
		aaguid = []byte{}
	}
	id, name = newID(), passkey.NameForAAGUID(c.AAGUID)
	if err := q.CreateWebAuthnCredential(ctx, sqlc.CreateWebAuthnCredentialParams{
		ID: id, UserID: userID, CredentialID: c.ID, PublicKey: c.PublicKey,
		SignCount: int64(c.SignCount), Aaguid: aaguid, TransportsJson: string(tr),
		AttestationType: c.AttestationType, AttestationFormat: c.AttestationFmt,
		UserVerified: boolInt(c.UserVerified), BackupEligible: boolInt(c.BackupEligible),
		BackupState: boolInt(c.BackupState), Name: name, CreatedAt: now,
	}); err != nil {
		return "", "", fmt.Errorf("auth: store passkey: %w", err)
	}
	return id, name, nil
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
