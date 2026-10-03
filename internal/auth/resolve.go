package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/perm"
	"github.com/thomasteoh/boardchestrator/internal/tenant"
)

// Refusal reasons (stable codes; logged, and mapped to fixed user-facing copy
// by the handler — never echoed raw).
const (
	RefuseUserDeleted     = "user_deleted"
	RefuseNotBootstrap    = "not_bootstrap_admin"
	RefuseNoAccount       = "no_account"
	RefuseEmailUnverified = "email_unverified"
	RefuseInvalid         = "invalid_assertion"
	// Link intent (SPEC §7.3 step 2) refusals.
	RefuseLinkSession    = "link_session"
	RefuseIdentityInUse  = "identity_in_use"
	RefuseProviderLinked = "provider_already_linked"
)

// Sign-up methods recorded in the auth.signup audit row (SPEC §7.3 step 4).
const (
	SignupOpen      = "open"
	SignupInvite    = "invite"
	SignupBootstrap = "bootstrap"
	// SignupJIT is reserved for org JIT provisioning (SPEC §7.5, WU-607/608);
	// see signUpMethod.
	SignupJIT = "jit"
)

// formerMemberUserID is migration 0017's sentinel "Former member" user, which
// no identity may ever sign in as.
const formerMemberUserID = "ffffffffffffffffffffffffffffffff"

// RefusedError is a login that resolved cleanly to "no": the person is not
// allowed in. Anything else Resolve returns is an internal failure.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "auth: login refused: " + e.Reason }

func refuse(reason string) error { return &RefusedError{Reason: reason} }

// Resolver maps a verified Assertion to a user and a fresh session
// (SPEC §7.3): steps 1-4 (org JIT is WU-607/608), 5 and 6.
type Resolver struct {
	DB          *sql.DB
	Sessions    *SessionStore
	AdminEmails []string
	// SecretKey is the 32-byte AES key for _enc columns (GitHub access token,
	// ID token). Empty disables storing them.
	SecretKey []byte
	// Bootstrap checks a bootstrap flow's token (SPEC §7.3 step 5). nil:
	// only BC_ADMIN_EMAILS can claim the platform.
	Bootstrap *Bootstrap
}

// LoginRequest is one resolution attempt.
type LoginRequest struct {
	Assertion  *Assertion
	Policy     ResolvePolicy
	AuthMethod string
	// PresentedSession is the raw session cookie on the callback request, if
	// any; it is revoked (rotation), or for a link it must be the session
	// that started the link.
	PresentedSession string
	IP, UA           string
	// Intent is the flow intent (IntentLogin when empty). For IntentLink,
	// LinkSessionHash is the hash of the session that started the link.
	Intent          string
	LinkSessionHash string
	// InviteToken is the invite carried by the flow, if any.
	InviteToken string
	// BootstrapHash is the bootstrap token hash a /setup flow proved ("" =
	// not a bootstrap flow). It is checked again here, in the transaction,
	// against the platform's current state.
	BootstrapHash string
}

// LoginResult is a successful resolution.
type LoginResult struct {
	UserID   string
	RawToken string
	Session  Session
	Created  bool // a new user was created
	Linked   bool // a new identity was attached to an existing user
	// LinkIntent marks an explicit link (SPEC §7.3 step 2): no session is
	// issued; the browser keeps the session that started the link.
	// AlreadyLinked is set when the identity was already the caller's.
	LinkIntent    bool
	AlreadyLinked bool
	// SignupMethod is set when Created (open|invite|bootstrap).
	SignupMethod string
	// InviteOrgID is the org whose invite was accepted during sign-up.
	InviteOrgID string
}

func (rv *Resolver) isAdmin(email string) bool {
	for _, ae := range rv.AdminEmails {
		if ae != "" && strings.EqualFold(ae, email) {
			return true
		}
	}
	return false
}

// Resolve runs login resolution in one IMMEDIATE transaction, so concurrent
// logins for the same identity serialise instead of racing the
// UNIQUE(provider, subject) insert.
func (rv *Resolver) Resolve(ctx context.Context, req LoginRequest) (*LoginResult, error) {
	a := req.Assertion
	if a == nil || a.ProviderID == "" || a.Subject == "" {
		return nil, refuse(RefuseInvalid)
	}
	now := rv.Sessions.now().UTC().Format(timeFormat)

	var res *LoginResult
	err := immediateTx(ctx, rv.DB, func(q *sqlc.Queries) error {
		r, err := rv.resolveTx(ctx, q, req, now)
		res = r
		return err
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (rv *Resolver) resolveTx(ctx context.Context, q *sqlc.Queries, req LoginRequest, now string) (*LoginResult, error) {
	a := req.Assertion
	if req.Intent == IntentLink {
		return rv.linkTx(ctx, q, req, now)
	}
	res := &LoginResult{}

	// Bootstrap gate (SPEC §7.3 step 5): until the platform is claimed, only
	// BC_ADMIN_EMAILS or a flow that proved the bootstrap token may sign in.
	// Read inside this IMMEDIATE transaction, so of two racing claims only
	// the first sees an unclaimed platform; a bootstrap flow minted before
	// someone else claimed it is then an ordinary login.
	ps, err := q.GetPlatformSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: platform settings: %w", err)
	}
	isAdmin := a.EmailVerified && rv.isAdmin(a.Email)
	bootstrapClaim := ps.BootstrapDone == 0
	tokenClaim := false
	if bootstrapClaim {
		tokenClaim = req.BootstrapHash != "" && rv.Bootstrap.claims(ps, req.BootstrapHash)
		if !isAdmin && !tokenClaim {
			return nil, refuse(RefuseNotBootstrap)
		}
		if err := q.SetBootstrapDone(ctx); err != nil {
			return nil, fmt.Errorf("auth: mark bootstrapped: %w", err)
		}
	}

	// Step 1: identity hit by (provider, subject).
	var identityID string
	ident, err := q.FindIdentityForLogin(ctx, sqlc.FindIdentityForLoginParams{Provider: a.ProviderID, Subject: a.Subject})
	switch {
	case err == nil:
		if ident.DeletedAt.Valid {
			return nil, refuse(RefuseUserDeleted)
		}
		res.UserID, identityID = ident.UserID, ident.ID
		if err := q.TouchIdentityLogin(ctx, sqlc.TouchIdentityLoginParams{
			Email: a.Email, LastLoginAt: sql.NullString{String: now, Valid: true}, ID: ident.ID,
		}); err != nil {
			return nil, fmt.Errorf("auth: touch identity: %w", err)
		}
	case errors.Is(err, sql.ErrNoRows):
		out, err := rv.linkOrSignUp(ctx, q, req, bootstrapClaim)
		if err != nil {
			return nil, err
		}
		identityID = newID()
		if err := q.LinkIdentity(ctx, sqlc.LinkIdentityParams{
			ID: identityID, UserID: out.userID, Provider: a.ProviderID, Subject: a.Subject, Email: a.Email,
			LastLoginAt: sql.NullString{String: now, Valid: true},
			CreatedAt:   sql.NullString{String: now, Valid: true},
		}); err != nil {
			return nil, fmt.Errorf("auth: link identity: %w", err)
		}
		res.UserID, res.Created, res.Linked = out.userID, out.method != "", out.method == ""
		res.SignupMethod = out.method
		if out.method == "" {
			if err := writeAudit(ctx, q, out.userID, "identity.linked_by_email", a.ProviderID, req.IP, now,
				map[string]string{"provider": a.ProviderID}); err != nil {
				return nil, err
			}
		} else {
			if out.method == SignupInvite {
				acc, err := action.AcceptInvite(ctx, q, req.InviteToken, out.userID, rv.Sessions.now())
				if err != nil {
					return nil, fmt.Errorf("auth: accept invite at sign-up: %w", err)
				}
				res.InviteOrgID = acc.OrgID
				out.detail["invite_id"] = acc.InviteID
				out.detail["org_id"] = acc.OrgID
			}
			if err := writeAudit(ctx, q, out.userID, "auth.signup", a.ProviderID, req.IP, now, out.detail); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("auth: find identity: %w", err)
	}

	if isAdmin || tokenClaim {
		if err := ensurePlatformAdmin(ctx, q, res.UserID); err != nil {
			return nil, err
		}
	}
	if bootstrapClaim {
		via := "admin_email"
		if tokenClaim && !isAdmin {
			via = "token"
		}
		if err := writeAudit(ctx, q, res.UserID, "auth.bootstrap", a.ProviderID, req.IP, now,
			map[string]string{"provider": a.ProviderID, "via": via}); err != nil {
			return nil, err
		}
	}

	if err := rv.storeAccessToken(ctx, q, a, identityID); err != nil {
		return nil, err
	}

	// Step 6: rotate. Whatever session this browser presented is revoked.
	if req.PresentedSession != "" {
		if err := q.DeleteSession(ctx, hashToken(req.PresentedSession)); err != nil {
			return nil, fmt.Errorf("auth: revoke presented session: %w", err)
		}
	}
	meta := SessionMeta{ProviderID: a.ProviderID, AuthMethod: req.AuthMethod, IdPSID: a.SID, IdPSubject: a.Subject}
	if a.IDTokenRaw != "" && len(rv.SecretKey) == 32 {
		enc, err := tenant.Encrypt(rv.SecretKey, a.IDTokenRaw)
		if err != nil {
			return nil, fmt.Errorf("auth: encrypt id token: %w", err)
		}
		meta.IDTokenEnc = enc
	}
	raw, sess, err := rv.Sessions.create(ctx, q, res.UserID, req.IP, req.UA, meta)
	if err != nil {
		return nil, err
	}
	res.RawToken, res.Session = raw, sess
	if err := writeAudit(ctx, q, res.UserID, "auth.login", a.ProviderID, req.IP, now, map[string]string{
		"provider": a.ProviderID, "method": req.AuthMethod, "ua": truncateUA(req.UA),
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// storeAccessToken keeps the provider access token (GitHub, WU-406)
// encrypted on the identity for reuse.
func (rv *Resolver) storeAccessToken(ctx context.Context, q *sqlc.Queries, a *Assertion, identityID string) error {
	if a.AccessToken == "" || len(rv.SecretKey) != 32 {
		return nil
	}
	enc, err := tenant.Encrypt(rv.SecretKey, a.AccessToken)
	if err != nil {
		return fmt.Errorf("auth: encrypt access token: %w", err)
	}
	if err := q.SetIdentityTokenByID(ctx, sqlc.SetIdentityTokenByIDParams{TokenEnc: []byte(enc), ID: identityID}); err != nil {
		return fmt.Errorf("auth: store access token: %w", err)
	}
	return nil
}

// linkTx is SPEC §7.3 step 2: attach the asserted identity to the user whose
// session started the link. The browser must still present that same live
// session; nothing about the identity's email matters here, because the
// person proved control of both the session and the IdP account.
func (rv *Resolver) linkTx(ctx context.Context, q *sqlc.Queries, req LoginRequest, now string) (*LoginResult, error) {
	a := req.Assertion
	if req.LinkSessionHash == "" || req.PresentedSession == "" ||
		subtle.ConstantTimeCompare([]byte(hashToken(req.PresentedSession)), []byte(req.LinkSessionHash)) != 1 {
		return nil, refuse(RefuseLinkSession)
	}
	sess, err := q.GetSession(ctx, req.LinkSessionHash) // excludes deleted users
	if errors.Is(err, sql.ErrNoRows) {
		return nil, refuse(RefuseLinkSession)
	}
	if err != nil {
		return nil, fmt.Errorf("auth: link session: %w", err)
	}
	exp, err := time.Parse(timeFormat, sess.ExpiresAt)
	if err != nil || !rv.Sessions.now().Before(exp) {
		return nil, refuse(RefuseLinkSession)
	}
	userID := sess.UserID
	res := &LoginResult{UserID: userID, LinkIntent: true}

	ident, err := q.FindIdentityForLogin(ctx, sqlc.FindIdentityForLoginParams{Provider: a.ProviderID, Subject: a.Subject})
	switch {
	case err == nil:
		if ident.UserID != userID {
			return nil, refuse(RefuseIdentityInUse) // never merge accounts
		}
		res.AlreadyLinked = true
		return res, nil
	case !errors.Is(err, sql.ErrNoRows):
		return nil, fmt.Errorf("auth: find identity: %w", err)
	}
	// One identity per provider per user: features that act through a
	// provider (GitHub, WU-406) look the identity up by (user, provider).
	if _, err := q.FindIdentityByUserAndProvider(ctx, sqlc.FindIdentityByUserAndProviderParams{
		UserID: userID, Provider: a.ProviderID,
	}); err == nil {
		return nil, refuse(RefuseProviderLinked)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("auth: find provider identity: %w", err)
	}
	identityID := newID()
	if err := q.LinkIdentity(ctx, sqlc.LinkIdentityParams{
		ID: identityID, UserID: userID, Provider: a.ProviderID, Subject: a.Subject, Email: a.Email,
		CreatedAt: sql.NullString{String: now, Valid: true},
	}); err != nil {
		return nil, fmt.Errorf("auth: link identity: %w", err)
	}
	if err := rv.storeAccessToken(ctx, q, a, identityID); err != nil {
		return nil, err
	}
	if err := writeAudit(ctx, q, userID, "identity.linked", a.ProviderID, req.IP, now,
		map[string]string{"provider": a.ProviderID, "identity_id": identityID}); err != nil {
		return nil, err
	}
	res.Linked = true
	return res, nil
}

// unseenOutcome is what linkOrSignUp decided for an unseen identity: link to
// userID (method "") or sign up a new userID by method.
type unseenOutcome struct {
	userID string
	method string
	detail map[string]string // auth.signup audit detail
}

// linkOrSignUp handles an unseen identity: step 3 (link by verified email on
// a trusted provider) then step 4 (sign-up).
func (rv *Resolver) linkOrSignUp(ctx context.Context, q *sqlc.Queries, req LoginRequest, bootstrapClaim bool) (unseenOutcome, error) {
	a := req.Assertion
	verified := a.Email != "" && a.EmailVerified

	// Step 3: link by email only when the IdP verified it and the provider is
	// trusted for email. An untrusted provider falls through to sign-up,
	// which refuses because the address is taken, with the same copy as "no
	// account", so it cannot be used to probe which emails exist.
	if verified && req.Policy.TrustEmail {
		existing, err := q.FindUserByEmailAnyState(ctx, a.Email)
		switch {
		case err == nil:
			if existing.DeletedAt.Valid || existing.ID == formerMemberUserID {
				return unseenOutcome{}, refuse(RefuseUserDeleted)
			}
			return unseenOutcome{userID: existing.ID}, nil
		case !errors.Is(err, sql.ErrNoRows):
			return unseenOutcome{}, fmt.Errorf("auth: find user by email: %w", err)
		}
	}

	// Step 4: sign-up.
	method, email, err := rv.signUpMethod(ctx, q, req, verified, bootstrapClaim)
	if err != nil {
		return unseenOutcome{}, err
	}
	if _, err := q.FindUserByEmailAnyState(ctx, email); err == nil {
		return unseenOutcome{}, refuse(RefuseNoAccount)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return unseenOutcome{}, fmt.Errorf("auth: find user by email: %w", err)
	}
	id := newID()
	if err := q.CreateUser(ctx, sqlc.CreateUserParams{ID: id, Email: email, Name: a.Name, AvatarUrl: a.Picture}); err != nil {
		return unseenOutcome{}, fmt.Errorf("auth: create user: %w", err)
	}
	return unseenOutcome{userID: id, method: method,
		detail: map[string]string{"provider": a.ProviderID, "method": method}}, nil
}

// signUpMethod decides whether an unseen identity may create a user (SPEC
// §7.3 step 4, Q8) and with which email:
//   - invite: the flow carries a pending, unexpired invite token. Possession
//     of the invite is the proof, so the IdP need not have verified its
//     email; the new user gets the invite's email.
//   - bootstrap: the unclaimed platform's claim, by a verified
//     BC_ADMIN_EMAILS address or a flow that proved the bootstrap token (the
//     gate in resolveTx already checked which).
//   - open: the provider allows sign-up and verified the email.
//
// Org JIT (SPEC §7.5) is WU-607/608: it goes between bootstrap and open, as
// "provider is org-owned with jit_enabled and the email domain is verified
// for that org", returning SignupJIT; the membership is then created next to
// the invite acceptance in resolveTx.
func (rv *Resolver) signUpMethod(ctx context.Context, q *sqlc.Queries, req LoginRequest, verified, bootstrapClaim bool) (method, email string, err error) {
	a := req.Assertion
	if req.InviteToken != "" {
		inv, err := action.PendingInvite(ctx, q, req.InviteToken, rv.Sessions.now())
		switch {
		case err == nil:
			return SignupInvite, inv.Email, nil
		case !errors.Is(err, action.ErrInviteInvalid):
			return "", "", fmt.Errorf("auth: invite: %w", err)
		}
		// An invalid invite grants nothing; the other rules still apply.
	}
	if !verified {
		// Without an invite, an unverified email can never claim an address.
		return "", "", refuse(RefuseEmailUnverified)
	}
	switch {
	case bootstrapClaim:
		return SignupBootstrap, a.Email, nil
	case req.Policy.AllowSignup:
		return SignupOpen, a.Email, nil
	}
	return "", "", refuse(RefuseNoAccount)
}

// ensurePlatformAdmin grants a BC_ADMIN_EMAILS user an Org Owner membership in
// the platform sentinel org (SPEC §6), idempotently.
func ensurePlatformAdmin(ctx context.Context, q *sqlc.Queries, userID string) error {
	rows, err := q.FindMemberships(ctx, sqlc.FindMembershipsParams{
		OrgID:        perm.PlatformOrg,
		ActorType:    "user",
		ActorID:      userID,
		ResourceType: "org",
		ResourceID:   perm.PlatformOrg,
	})
	if err != nil {
		return fmt.Errorf("auth: check platform membership: %w", err)
	}
	if len(rows) > 0 {
		return nil
	}
	if _, err := q.CreateMembership(ctx, sqlc.CreateMembershipParams{
		ID:           newID(),
		OrgID:        perm.PlatformOrg,
		ActorID:      userID,
		ActorType:    "user",
		ResourceType: "org",
		ResourceID:   perm.PlatformOrg,
		RoleID:       sql.NullString{String: perm.PlatformOwnerRole, Valid: true},
	}); err != nil {
		return fmt.Errorf("auth: grant platform admin: %w", err)
	}
	return nil
}

// writeAudit appends an authentication audit row for a user directly (SPEC
// §7.3: auth events are not actions). Auth rows carry no org: they show in
// the platform audit view.
func writeAudit(ctx context.Context, q *sqlc.Queries, userID, action, subject, ip, now string, detail map[string]string) error {
	return writeAuditAs(ctx, q, "user", userID, action, subject, ip, now, detail)
}

// writeAuditAs is writeAudit for any actor type ("anonymous" for failed
// logins, with an empty actor id).
func writeAuditAs(ctx context.Context, q *sqlc.Queries, actorType, actorID, action, subject, ip, now string, detail map[string]string) error {
	dj, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("auth: audit detail: %w", err)
	}
	if err := q.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID:         newID(),
		ActorType:  actorType,
		ActorID:    actorID,
		Action:     action,
		Subject:    subject,
		DetailJson: string(dj),
		Ip:         ip,
		CreatedAt:  now,
	}); err != nil {
		return fmt.Errorf("auth: audit %s: %w", action, err)
	}
	return nil
}

// immediateTx runs fn inside BEGIN IMMEDIATE on a dedicated connection. A
// deferred transaction that reads then writes can fail with SQLITE_BUSY
// (no busy-wait) when another writer commits in between; taking the write lock
// up front makes concurrent logins queue on busy_timeout instead.
func immediateTx(ctx context.Context, d *sql.DB, fn func(q *sqlc.Queries) error) (err error) {
	conn, err := d.Conn(ctx)
	if err != nil {
		return fmt.Errorf("auth: db conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("auth: begin: %w", err)
	}
	done := false
	defer func() {
		if !done {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()
	if err := fn(sqlc.New(conn)); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("auth: commit: %w", err)
	}
	done = true
	return nil
}
