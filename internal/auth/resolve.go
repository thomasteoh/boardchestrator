package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
// (SPEC §7.3). WU-601 implements steps 1, 3, 4 (sign-up open), the existing
// BC_ADMIN_EMAILS bootstrap gate, and 6.
type Resolver struct {
	DB          *sql.DB
	Sessions    *SessionStore
	AdminEmails []string
	// SecretKey is the 32-byte AES key for _enc columns (GitHub access token,
	// ID token). Empty disables storing them.
	SecretKey []byte
}

// LoginRequest is one resolution attempt.
type LoginRequest struct {
	Assertion  *Assertion
	Policy     ResolvePolicy
	AuthMethod string
	// PresentedSession is the raw session cookie on the callback request, if
	// any; it is revoked (rotation).
	PresentedSession string
	IP, UA           string
}

// LoginResult is a successful resolution.
type LoginResult struct {
	UserID   string
	RawToken string
	Session  Session
	Created  bool // a new user was created
	Linked   bool // a new identity was attached to an existing user
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
	res := &LoginResult{}

	// Bootstrap gate (SPEC §7.3 step 5, admin-email half; the token half is
	// WU-605): until the platform is claimed, only BC_ADMIN_EMAILS may sign in.
	ps, err := q.GetPlatformSettings(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: platform settings: %w", err)
	}
	isAdmin := a.EmailVerified && rv.isAdmin(a.Email)
	if ps.BootstrapDone == 0 {
		if !isAdmin {
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
		userID, created, err := rv.linkOrSignUp(ctx, q, req)
		if err != nil {
			return nil, err
		}
		identityID = newID()
		if err := q.LinkIdentity(ctx, sqlc.LinkIdentityParams{
			ID: identityID, UserID: userID, Provider: a.ProviderID, Subject: a.Subject, Email: a.Email,
			LastLoginAt: sql.NullString{String: now, Valid: true},
		}); err != nil {
			return nil, fmt.Errorf("auth: link identity: %w", err)
		}
		res.UserID, res.Created, res.Linked = userID, created, !created
		if !created {
			if err := writeAudit(ctx, q, userID, "identity.linked_by_email", a.ProviderID, req.IP, now,
				map[string]string{"provider": a.ProviderID}); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("auth: find identity: %w", err)
	}

	if isAdmin {
		if err := ensurePlatformAdmin(ctx, q, res.UserID); err != nil {
			return nil, err
		}
	}

	// WU-406: keep the provider access token (GitHub) encrypted for reuse.
	if a.AccessToken != "" && len(rv.SecretKey) == 32 {
		enc, err := tenant.Encrypt(rv.SecretKey, a.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("auth: encrypt access token: %w", err)
		}
		if err := q.SetIdentityTokenByID(ctx, sqlc.SetIdentityTokenByIDParams{TokenEnc: []byte(enc), ID: identityID}); err != nil {
			return nil, fmt.Errorf("auth: store access token: %w", err)
		}
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
	return res, nil
}

// linkOrSignUp handles an unseen identity: step 3 (link by verified email on
// a trusted provider) then step 4 (sign-up).
func (rv *Resolver) linkOrSignUp(ctx context.Context, q *sqlc.Queries, req LoginRequest) (userID string, created bool, err error) {
	a := req.Assertion
	if a.Email == "" || !a.EmailVerified {
		// An unverified email can neither link nor claim an address.
		return "", false, refuse(RefuseEmailUnverified)
	}
	existing, err := q.FindUserByEmailAnyState(ctx, a.Email)
	switch {
	case err == nil:
		if existing.DeletedAt.Valid || existing.ID == formerMemberUserID {
			return "", false, refuse(RefuseUserDeleted)
		}
		if !req.Policy.TrustEmail {
			return "", false, refuse(RefuseNoAccount)
		}
		return existing.ID, false, nil
	case errors.Is(err, sql.ErrNoRows):
		if !req.Policy.AllowSignup {
			return "", false, refuse(RefuseNoAccount)
		}
		id := newID()
		if err := q.CreateUser(ctx, sqlc.CreateUserParams{ID: id, Email: a.Email, Name: a.Name, AvatarUrl: a.Picture}); err != nil {
			return "", false, fmt.Errorf("auth: create user: %w", err)
		}
		return id, true, nil
	default:
		return "", false, fmt.Errorf("auth: find user by email: %w", err)
	}
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

// writeAudit appends an authentication audit row directly (SPEC §7.3: auth
// events are not actions).
func writeAudit(ctx context.Context, q *sqlc.Queries, userID, action, subject, ip, now string, detail map[string]string) error {
	dj, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("auth: audit detail: %w", err)
	}
	if err := q.CreateAuditLog(ctx, sqlc.CreateAuditLogParams{
		ID:         newID(),
		ActorType:  "user",
		ActorID:    userID,
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
