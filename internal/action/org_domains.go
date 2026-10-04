package action

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// Organisation email domains (WU-606, SPEC §7.4). An org adds a domain, gets
// a TXT record to publish, and verifies it. A verified domain routes
// home-realm discovery to the org's IdP and, from WU-607/608, bounds what the
// org's IdP is trusted for.
//
// Uniqueness: any number of orgs may hold a pending claim on a domain, but
// only one may verify it (partial unique index, migration 0036). So a pending
// claim never blocks the real owner, and a verified domain cannot be claimed
// again (add and verify are both refused with ErrDomainTaken).

// DomainChallengePrefix is the label the TXT record is published under.
const DomainChallengePrefix = "_boardchestrator-challenge."

// domainVerifyPrefix starts the TXT record value.
const domainVerifyPrefix = "bc-verify="

// DomainVerifyTimeout bounds one TXT lookup.
const DomainVerifyTimeout = 5 * time.Second

// maxOrgDomains caps the domains one org may hold (pending or verified).
const maxOrgDomains = 50

// Domain errors. All wrap ErrInvalidInput; their text is fixed copy that never
// contains the domain or anything else from the request.
var (
	ErrDomainInvalid        = fmt.Errorf("%w: not a valid domain name", ErrInvalidInput)
	ErrDomainIP             = fmt.Errorf("%w: enter a domain name, not an IP address", ErrInvalidInput)
	ErrDomainPublicSuffix   = fmt.Errorf("%w: that is a public suffix (like com or co.uk), not a domain an organisation can own", ErrInvalidInput)
	ErrDomainExists         = fmt.Errorf("%w: this organisation has already added that domain", ErrInvalidInput)
	ErrDomainTaken          = fmt.Errorf("%w: that domain has been verified by another organisation", ErrInvalidInput)
	ErrDomainLimit          = fmt.Errorf("%w: this organisation has reached its domain limit", ErrInvalidInput)
	ErrDomainAlreadyChecked = fmt.Errorf("%w: that domain is already verified", ErrInvalidInput)
	// ErrDomainRecordMissing: the lookup worked but no TXT record carries
	// this org's token.
	ErrDomainRecordMissing = fmt.Errorf("%w: the verification TXT record wasn't found", ErrInvalidInput)
	// ErrDomainLookup: the DNS lookup failed or timed out.
	ErrDomainLookup = fmt.Errorf("%w: the DNS lookup failed", ErrInvalidInput)
)

// TXTResolver looks up TXT records. *net.Resolver satisfies it.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type txtResolverBox struct{ r TXTResolver }

var txtResolver atomic.Pointer[txtResolverBox]

// SetTXTResolver replaces the resolver org.domain.verify uses (tests inject a
// fake); nil restores net.DefaultResolver.
func SetTXTResolver(r TXTResolver) {
	if r == nil {
		txtResolver.Store(nil)
		return
	}
	txtResolver.Store(&txtResolverBox{r: r})
}

func currentTXTResolver() TXTResolver {
	if b := txtResolver.Load(); b != nil {
		return b.r
	}
	return net.DefaultResolver
}

// domainProfile maps and validates like a DNS lookup (UTS #46 non-transitional,
// STD3 host-name rules, bidi rule, DNS length limits).
var domainProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.VerifyDNSLength(true),
)

// NormaliseDomain returns the canonical form of a domain an organisation
// claims: lower-case ASCII with IDNA A-labels ("bücher.example" ->
// "xn--bcher-kva.example") and no trailing dot. It refuses IP addresses,
// single-label names and public suffixes (com, co.uk, github.io).
func NormaliseDomain(in string) (string, error) {
	s := strings.TrimSpace(in)
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", ErrDomainInvalid
	}
	if net.ParseIP(strings.Trim(s, "[]")) != nil {
		return "", ErrDomainIP
	}
	a, err := domainProfile.ToASCII(s)
	if err != nil || a == "" {
		return "", ErrDomainInvalid
	}
	a = strings.ToLower(a)
	labels := strings.Split(a, ".")
	if len(labels) < 2 {
		return "", ErrDomainInvalid
	}
	// No TLD is all digits; this also refuses IPv4 shorthands like 127.1.
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", ErrDomainIP
	}
	if ps, _ := publicsuffix.PublicSuffix(a); ps == a {
		return "", ErrDomainPublicSuffix
	}
	return a, nil
}

// EmailDomain returns the normalised domain of an email address.
func EmailDomain(email string) (string, error) {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "", ErrDomainInvalid
	}
	return NormaliseDomain(email[at+1:])
}

// VerifiedOrgForEmail returns the org that has verified email's domain, or ""
// when none has (including malformed emails). Exact domain match only: a
// verified example.com does not cover eng.example.com. This is the one
// home-realm lookup (SPEC §7.4); WU-607/608 use it to check that an org IdP's
// asserted email is on one of that org's verified domains.
func VerifiedOrgForEmail(ctx context.Context, q *sqlc.Queries, email string) (string, error) {
	d, err := EmailDomain(email)
	if err != nil {
		return "", nil
	}
	org, err := q.FindVerifiedDomainOrg(ctx, d)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("verified domain lookup: %w", err)
	}
	return org, nil
}

// DomainChallenge is the TXT record that proves control of domain.
func DomainChallenge(domain, token string) (name, value string) {
	return DomainChallengePrefix + domain, domainVerifyPrefix + token
}

// OrgDomainView is one domain as the org.domain.* actions return it.
type OrgDomainView struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	// Status is pending, verified, or taken (another org verified it).
	Status     string `json:"status"`
	VerifiedAt string `json:"verified_at,omitempty"`
	CreatedAt  string `json:"created_at"`
	// RecordName/RecordValue are the TXT record to publish; set while
	// pending.
	RecordName  string `json:"record_name,omitempty"`
	RecordValue string `json:"record_value,omitempty"`
}

func domainView(id, domain, token string, verifiedAt sql.NullString, createdAt string, taken bool) OrgDomainView {
	v := OrgDomainView{ID: id, Domain: domain, CreatedAt: createdAt, Status: "pending"}
	switch {
	case verifiedAt.Valid:
		v.Status, v.VerifiedAt = "verified", verifiedAt.String
	case taken:
		v.Status = "taken"
	default:
		v.RecordName, v.RecordValue = DomainChallenge(domain, token)
	}
	return v
}

type orgDomainInput struct {
	OrgID  string `json:"org_id,omitempty"`
	ID     string `json:"id,omitempty"`
	Domain string `json:"domain,omitempty"`
}

func decodeOrgDomainInput(in json.RawMessage) (orgDomainInput, error) {
	var v orgDomainInput
	if len(in) == 0 {
		return v, nil
	}
	if err := json.Unmarshal(in, &v); err != nil {
		return v, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	return v, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

func init() {
	for _, def := range []Definition{
		{Name: "org.domain.list", Impact: ImpactRead, Handle: handleOrgDomainList},
		{Name: "org.domain.add", Impact: ImpactHigh, Handle: handleOrgDomainAdd},
		{Name: "org.domain.verify", Impact: ImpactHigh, Handle: handleOrgDomainVerify},
		{Name: "org.domain.remove", Impact: ImpactHigh, Handle: handleOrgDomainRemove},
	} {
		def.Permission = "org.sso"
		def.Scope = ScopeOrg
		def.Input = FuncSchema(func(raw json.RawMessage) error { return nil })
		Register(def)
	}
}

func handleOrgDomainList(ctx context.Context, ac ActionCtx, _ json.RawMessage) (any, error) {
	rows, err := ac.Tx.ListOrgDomains(ctx, ac.Org)
	if err != nil {
		return nil, fmt.Errorf("org.domain.list: %w", err)
	}
	out := make([]OrgDomainView, 0, len(rows))
	for _, r := range rows {
		out = append(out, domainView(r.ID, r.Domain, r.VerifyToken, r.VerifiedAt, r.CreatedAt, r.Taken == 1))
	}
	return map[string]any{"domains": out}, nil
}

func handleOrgDomainAdd(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	input, err := decodeOrgDomainInput(in)
	if err != nil {
		return nil, err
	}
	domain, err := NormaliseDomain(input.Domain)
	if err != nil {
		return nil, err
	}
	n, err := ac.Tx.CountOrgDomains(ctx, ac.Org)
	if err != nil {
		return nil, fmt.Errorf("org.domain.add: count: %w", err)
	}
	if n >= maxOrgDomains {
		return nil, ErrDomainLimit
	}
	taken, err := ac.Tx.DomainVerifiedByOtherOrg(ctx, sqlc.DomainVerifiedByOtherOrgParams{Domain: domain, OrgID: ac.Org})
	if err != nil {
		return nil, fmt.Errorf("org.domain.add: check: %w", err)
	}
	if taken == 1 {
		return nil, ErrDomainTaken
	}
	row, err := ac.Tx.CreateOrgDomain(ctx, sqlc.CreateOrgDomainParams{
		ID: newID(), OrgID: ac.Org, Domain: domain, VerifyToken: newID(),
		CreatedAt: time.Now().UTC().Format(timeFormat),
	})
	if isUniqueViolation(err) {
		return nil, ErrDomainExists
	}
	if err != nil {
		return nil, fmt.Errorf("org.domain.add: %w", err)
	}
	return domainView(row.ID, row.Domain, row.VerifyToken, row.VerifiedAt, row.CreatedAt, false), nil
}

// handleOrgDomainVerify looks the challenge up in DNS and marks the domain
// verified. The row is read outside the dispatch transaction so the
// transaction stays idle during the lookup; the one write is conditional on
// the token that was checked.
func handleOrgDomainVerify(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	input, err := decodeOrgDomainInput(in)
	if err != nil {
		return nil, err
	}
	read := ac.Tx.Queries
	if ac.DB != nil {
		read = sqlc.New(ac.DB)
	}
	row, err := read.GetOrgDomain(ctx, sqlc.GetOrgDomainParams{ID: input.ID, OrgID: ac.Org})
	if err != nil {
		return nil, fmt.Errorf("org.domain.verify: %w", err) // sql.ErrNoRows for another org's id
	}
	if row.VerifiedAt.Valid {
		return nil, ErrDomainAlreadyChecked
	}
	taken, err := read.DomainVerifiedByOtherOrg(ctx, sqlc.DomainVerifiedByOtherOrgParams{Domain: row.Domain, OrgID: ac.Org})
	if err != nil {
		return nil, fmt.Errorf("org.domain.verify: check: %w", err)
	}
	if taken == 1 {
		return nil, ErrDomainTaken
	}
	if err := checkDomainTXT(ctx, row.Domain, row.VerifyToken); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(timeFormat)
	n, err := ac.Tx.MarkOrgDomainVerified(ctx, sqlc.MarkOrgDomainVerifiedParams{
		VerifiedAt: sql.NullString{String: now, Valid: true},
		ID:         row.ID, OrgID: ac.Org, VerifyToken: row.VerifyToken,
	})
	if isUniqueViolation(err) {
		return nil, ErrDomainTaken // another org verified it during the lookup
	}
	if err != nil {
		return nil, fmt.Errorf("org.domain.verify: %w", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("org.domain.verify: %w", sql.ErrNoRows) // removed or verified meanwhile
	}
	return domainView(row.ID, row.Domain, row.VerifyToken, sql.NullString{String: now, Valid: true}, row.CreatedAt, false), nil
}

// checkDomainTXT reports whether the challenge record for domain carries
// token.
func checkDomainTXT(ctx context.Context, domain, token string) error {
	ctx, cancel := context.WithTimeout(ctx, DomainVerifyTimeout)
	defer cancel()
	name, want := DomainChallenge(domain, token)
	records, err := currentTXTResolver().LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return ErrDomainRecordMissing
		}
		return fmt.Errorf("%w (%v)", ErrDomainLookup, err)
	}
	for _, rec := range records {
		if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(rec)), []byte(want)) == 1 {
			return nil
		}
	}
	return ErrDomainRecordMissing
}

func handleOrgDomainRemove(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	input, err := decodeOrgDomainInput(in)
	if err != nil {
		return nil, err
	}
	row, err := ac.Tx.GetOrgDomain(ctx, sqlc.GetOrgDomainParams{ID: input.ID, OrgID: ac.Org})
	if err != nil {
		return nil, fmt.Errorf("org.domain.remove: %w", err)
	}
	if _, err := ac.Tx.DeleteOrgDomain(ctx, sqlc.DeleteOrgDomainParams{ID: row.ID, OrgID: ac.Org}); err != nil {
		return nil, fmt.Errorf("org.domain.remove: %w", err)
	}
	return map[string]any{"id": row.ID, "domain": row.Domain, "removed": true}, nil
}
