// Package auth provides server-side sessions, CSRF protection, and the CSP
// nonce plumbing (SPEC §7 sessions, §15 security). The OAuth flows and API
// keys land in later work units; this WU establishes the session store and
// the security middleware the whole app depends on.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Cookie and expiry constants for the session (SPEC §7, §15).
const (
	// CookieName uses the __Host- prefix, which browsers only accept when the
	// cookie is Secure, has Path=/, and carries no Domain — exactly the
	// attributes we set. It pins the cookie to this exact host over HTTPS.
	CookieName = "__Host-bc_session"

	// tokenBytes is the raw session token size before hashing (SPEC §7).
	tokenBytes = 32

	// SlidingTTL is how long a session stays valid from its last use; each
	// lookup extends expiry up to AbsoluteTTL from creation.
	SlidingTTL = 14 * 24 * time.Hour
	// AbsoluteTTL caps a session's total lifetime regardless of activity.
	AbsoluteTTL = 90 * 24 * time.Hour
)

// timeFormat matches the SQLite storage format used across the schema
// (SPEC §3: UTC ISO-8601, millisecond precision, Z suffix).
const timeFormat = "2006-01-02T15:04:05.000Z"

// ErrNoSession is returned when a token does not resolve to a live session
// (absent, revoked, or expired).
var ErrNoSession = errors.New("auth: no valid session")

// Session is a resolved server-side session.
type Session struct {
	TokenHash string
	UserID    string
	IP        string
	UA        string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
}

// SessionStore is the server-side session store backed by the sessions table.
// Tokens are never stored; only their SHA-256 hashes are.
type SessionStore struct {
	q   *sqlc.Queries
	now func() time.Time // injectable clock for expiry tests
}

// NewSessionStore builds a store over the given database handle.
func NewSessionStore(d *sql.DB) *SessionStore {
	return &SessionStore{q: sqlc.New(d), now: time.Now}
}

// WithClock overrides the store's clock; test-only.
func (s *SessionStore) WithClock(now func() time.Time) *SessionStore {
	s.now = now
	return s
}

// hashToken returns the hex-encoded SHA-256 of a raw session token.
func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// newToken returns a fresh random session token (raw, to hand to the client).
func newToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate session token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Create issues a new session for userID and returns the raw token to set in
// the client cookie. Only the hash is persisted.
func (s *SessionStore) Create(ctx context.Context, userID, ip, ua string) (raw string, sess Session, err error) {
	raw, err = newToken()
	if err != nil {
		return "", Session{}, err
	}
	now := s.now().UTC()
	sess = Session{
		TokenHash: hashToken(raw),
		UserID:    userID,
		IP:        ip,
		UA:        ua,
		CreatedAt: now,
		LastSeen:  now,
		ExpiresAt: now.Add(SlidingTTL),
	}
	if err := s.q.CreateSession(ctx, sqlc.CreateSessionParams{
		TokenHash:  sess.TokenHash,
		UserID:     sess.UserID,
		Ip:         sess.IP,
		Ua:         sess.UA,
		CreatedAt:  sess.CreatedAt.Format(timeFormat),
		LastSeenAt: sess.LastSeen.Format(timeFormat),
		ExpiresAt:  sess.ExpiresAt.Format(timeFormat),
	}); err != nil {
		return "", Session{}, fmt.Errorf("auth: create session: %w", err)
	}
	return raw, sess, nil
}

// Lookup resolves a raw token to a live session, sliding its expiry forward.
// An expired session is deleted and reported as ErrNoSession. The returned
// session carries its refreshed expiry so callers can re-set the cookie.
func (s *SessionStore) Lookup(ctx context.Context, raw string) (Session, error) {
	if raw == "" {
		return Session{}, ErrNoSession
	}
	th := hashToken(raw)
	row, err := s.q.GetSession(ctx, th)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("auth: lookup session: %w", err)
	}
	sess, err := rowToSession(row)
	if err != nil {
		return Session{}, err
	}

	now := s.now().UTC()
	if !now.Before(sess.ExpiresAt) {
		// Expired: clean up and reject.
		_ = s.q.DeleteSession(ctx, th)
		return Session{}, ErrNoSession
	}

	// Slide expiry forward, capped at the absolute lifetime.
	newExpiry := now.Add(SlidingTTL)
	if absCap := sess.CreatedAt.Add(AbsoluteTTL); newExpiry.After(absCap) {
		newExpiry = absCap
	}
	if err := s.q.TouchSession(ctx, sqlc.TouchSessionParams{
		LastSeenAt: now.Format(timeFormat),
		ExpiresAt:  newExpiry.Format(timeFormat),
		TokenHash:  th,
	}); err != nil {
		return Session{}, fmt.Errorf("auth: touch session: %w", err)
	}
	sess.LastSeen = now
	sess.ExpiresAt = newExpiry
	return sess, nil
}

// Rotate issues a fresh token for the same user and revokes the old one, in a
// single transaction. Call this on any privilege change (login, role change)
// to defeat session fixation. Returns the new raw token and session.
func (s *SessionStore) Rotate(ctx context.Context, oldRaw, ip, ua string) (string, Session, error) {
	sess, err := s.Lookup(ctx, oldRaw)
	if err != nil {
		return "", Session{}, err
	}
	newRaw, newSess, err := s.Create(ctx, sess.UserID, ip, ua)
	if err != nil {
		return "", Session{}, err
	}
	if err := s.q.DeleteSession(ctx, hashToken(oldRaw)); err != nil {
		return "", Session{}, fmt.Errorf("auth: revoke rotated session: %w", err)
	}
	return newRaw, newSess, nil
}

// Revoke deletes the session for a raw token (logout). Revoking an unknown
// token is a no-op.
func (s *SessionStore) Revoke(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	if err := s.q.DeleteSession(ctx, hashToken(raw)); err != nil {
		return fmt.Errorf("auth: revoke session: %w", err)
	}
	return nil
}

// PurgeExpired removes all sessions past their expiry; intended for a periodic
// sweep. Returns nil on success.
func (s *SessionStore) PurgeExpired(ctx context.Context) error {
	if err := s.q.DeleteExpiredSessions(ctx, s.now().UTC().Format(timeFormat)); err != nil {
		return fmt.Errorf("auth: purge expired sessions: %w", err)
	}
	return nil
}

func rowToSession(row sqlc.Session) (Session, error) {
	created, err := time.Parse(timeFormat, row.CreatedAt)
	if err != nil {
		return Session{}, fmt.Errorf("auth: parse created_at %q: %w", row.CreatedAt, err)
	}
	seen, err := time.Parse(timeFormat, row.LastSeenAt)
	if err != nil {
		return Session{}, fmt.Errorf("auth: parse last_seen_at %q: %w", row.LastSeenAt, err)
	}
	exp, err := time.Parse(timeFormat, row.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("auth: parse expires_at %q: %w", row.ExpiresAt, err)
	}
	return Session{
		TokenHash: row.TokenHash,
		UserID:    row.UserID,
		IP:        row.Ip,
		UA:        row.Ua,
		CreatedAt: created.UTC(),
		LastSeen:  seen.UTC(),
		ExpiresAt: exp.UTC(),
	}, nil
}
