// Package scim serves SCIM 2.0 provisioning (RFC 7643/7644, SPEC §7.8) at
// /scim/v2 for an organisation's identity provider. A bearer SCIM token
// (scim.token.create) authenticates the IdP and fixes the organisation;
// every read and write is scoped to it. Writes are internal provisioning
// functions, not dispatched actions: they run as the service actor
// "scim:<token id>" and write their own audit rows.
package scim

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/ratelimit"
)

// Prefix is the SCIM base path.
const Prefix = "/scim/v2"

// ContentType is the SCIM media type (RFC 7644 §3.1).
const ContentType = "application/scim+json"

// Default per-token rate (SPEC §7.11): 600 requests a minute.
const (
	DefaultPerMinute = 600
	DefaultBurst     = 100
)

const (
	maxBody     = 1 << 20
	timeFormat  = "2006-01-02T15:04:05.000Z"
	touchPeriod = time.Minute
)

// Options configure a Handler.
type Options struct {
	DB *sql.DB
	// BaseURL is the instance's public URL (BC_BASE_URL); resource
	// locations are BaseURL + Prefix + "/Users/<id>".
	BaseURL string
	// Events receives membership.synced events after commit (optional).
	Events action.EventSink
	// PerMinute and Burst override the per-token rate (zero = defaults).
	PerMinute, Burst int
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Handler serves /scim/v2.
type Handler struct {
	db     *sql.DB
	base   string
	events action.EventSink
	lim    *ratelimit.Limiter
	mux    *http.ServeMux
	now    func() time.Time
}

// New builds the handler.
func New(o Options) *Handler {
	per, burst := DefaultPerMinute, DefaultBurst
	if o.PerMinute > 0 && o.Burst > 0 {
		per, burst = o.PerMinute, o.Burst
	}
	h := &Handler{
		db: o.DB, base: strings.TrimRight(o.BaseURL, "/") + Prefix, events: o.Events,
		lim: ratelimit.New(per, burst), now: o.Now,
	}
	if h.now == nil {
		h.now = time.Now
	}
	m := http.NewServeMux()
	m.HandleFunc("GET "+Prefix+"/ServiceProviderConfig", h.serviceProviderConfig)
	m.HandleFunc("GET "+Prefix+"/ResourceTypes", h.resourceTypes)
	m.HandleFunc("GET "+Prefix+"/ResourceTypes/{id}", h.resourceTypes)
	m.HandleFunc("GET "+Prefix+"/Schemas", h.schemas)
	m.HandleFunc("GET "+Prefix+"/Schemas/{id}", h.schemas)
	m.HandleFunc("GET "+Prefix+"/Users", h.listUsers)
	m.HandleFunc("POST "+Prefix+"/Users", h.createUser)
	m.HandleFunc("GET "+Prefix+"/Users/{id}", h.getUser)
	m.HandleFunc("PUT "+Prefix+"/Users/{id}", h.putUser)
	m.HandleFunc("PATCH "+Prefix+"/Users/{id}", h.patchUser)
	m.HandleFunc("DELETE "+Prefix+"/Users/{id}", h.deleteUser)
	m.HandleFunc("GET "+Prefix+"/Groups", h.listGroups)
	m.HandleFunc("POST "+Prefix+"/Groups", h.createGroup)
	m.HandleFunc("GET "+Prefix+"/Groups/{id}", h.getGroup)
	m.HandleFunc("PUT "+Prefix+"/Groups/{id}", h.putGroup)
	m.HandleFunc("PATCH "+Prefix+"/Groups/{id}", h.patchGroup)
	m.HandleFunc("DELETE "+Prefix+"/Groups/{id}", h.deleteGroup)
	m.HandleFunc(Prefix+"/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "", "Endpoint not found.")
	})
	h.mux = m
	return h
}

// Mount registers the handler on r for Prefix and everything under it.
func (h *Handler) Mount(r interface {
	Handle(pattern string, h http.Handler)
}) {
	r.Handle(Prefix, h)
	r.Handle(Prefix+"/*", h)
}

// IsSCIMPath reports whether path is under Prefix.
func IsSCIMPath(path string) bool {
	return path == Prefix || strings.HasPrefix(path, Prefix+"/")
}

type ctxKey struct{}

// caller is the authenticated token.
type caller struct {
	TokenID string
	OrgID   string
	Actor   action.Actor
}

func callerFrom(ctx context.Context) caller {
	c, _ := ctx.Value(ctxKey{}).(caller)
	return c
}

// ServeHTTP authenticates the bearer token, applies the per-token rate
// limit and routes the request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := auth.ClientIP(r)
	c, ok := h.authenticate(r)
	if !ok {
		// Failed attempts share a per-address bucket, so a bad token can't
		// hammer the database.
		if allowed, wait := h.lim.Allow("ip:" + ip); !allowed {
			tooMany(w, wait)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		writeError(w, http.StatusUnauthorized, "", "Authentication failed: a valid SCIM bearer token is required.")
		return
	}
	if allowed, wait := h.lim.Allow("tok:" + c.TokenID); !allowed {
		tooMany(w, wait)
		return
	}
	c.Actor = action.Actor{Type: action.ActorService, ID: "scim:" + c.TokenID, IP: ip}
	h.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	ratelimit.WriteRetryAfter(w, wait)
	writeError(w, http.StatusTooManyRequests, "", "Too many requests. Retry after the Retry-After interval.")
}

// authenticate resolves the bearer token: well-formed, known prefix, hash
// equal (constant time), not revoked, not expired.
func (h *Handler) authenticate(r *http.Request) (caller, bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return caller{}, false
	}
	token = strings.TrimSpace(token)
	prefix, ok := action.ParseSCIMToken(token)
	if !ok || h.db == nil {
		return caller{}, false
	}
	q := sqlc.New(h.db)
	row, err := q.FindSCIMTokenByPrefix(r.Context(), prefix)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("scim: token lookup", "err", err)
		}
		return caller{}, false
	}
	if subtle.ConstantTimeCompare([]byte(action.SCIMTokenHash(token)), []byte(row.TokenHash)) != 1 {
		return caller{}, false
	}
	now := h.now().UTC()
	if row.RevokedAt.Valid || (row.ExpiresAt.Valid && row.ExpiresAt.String <= now.Format(timeFormat)) {
		return caller{}, false
	}
	if err := q.TouchSCIMToken(r.Context(), sqlc.TouchSCIMTokenParams{
		Now: sql.NullString{String: now.Format(timeFormat), Valid: true}, ID: row.ID, OrgID: row.OrgID,
		Before: sql.NullString{String: now.Add(-touchPeriod).Format(timeFormat), Valid: true},
	}); err != nil {
		slog.Warn("scim: touch token", "err", err)
	}
	return caller{TokenID: row.ID, OrgID: row.OrgID}, true
}

// --- Responses ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("scim: write response", "err", err)
	}
}

// writeError writes the RFC 7644 §3.12 error envelope.
func writeError(w http.ResponseWriter, status int, scimType, detail string) {
	body := map[string]any{
		"schemas": []string{SchemaError},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	}
	if scimType != "" {
		body["scimType"] = scimType
	}
	writeJSON(w, status, body)
}

// apiError is a SCIM error a provisioning function returns.
type apiError struct {
	Status   int
	SCIMType string
	Detail   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("scim: %d %s: %s", e.Status, e.SCIMType, e.Detail)
}

func badRequest(scimType, format string, args ...any) error {
	return &apiError{Status: http.StatusBadRequest, SCIMType: scimType, Detail: fmt.Sprintf(format, args...)}
}

func conflict(format string, args ...any) error {
	return &apiError{Status: http.StatusConflict, SCIMType: "uniqueness", Detail: fmt.Sprintf(format, args...)}
}

func notFound(id string) error {
	return &apiError{Status: http.StatusNotFound, Detail: "Resource " + id + " not found."}
}

// fail writes err: an apiError as itself, anything else as a logged 500
// with no internal detail.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	if errors.As(err, &ae) {
		writeError(w, ae.Status, ae.SCIMType, ae.Detail)
		return
	}
	slog.Error("scim: request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "", "Internal server error.")
}

func writeList(w http.ResponseWriter, total, start int, resources []map[string]any) {
	if resources == nil {
		resources = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{SchemaListResponse},
		"totalResults": total,
		"startIndex":   start,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

// readBody decodes a JSON object request body.
func readBody(r *http.Request) (map[string]any, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return nil, badRequest("invalidSyntax", "The request body could not be read.")
	}
	if len(b) > maxBody {
		return nil, &apiError{Status: http.StatusRequestEntityTooLarge, Detail: "The request body is too large."}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, badRequest("invalidSyntax", "The request body must be a JSON object.")
	}
	return m, nil
}

// --- Listing ------------------------------------------------------------------

// listParams are the query parameters of a list request.
type listParams struct {
	filter     *Filter
	start      int
	count      int
	attributes []string
	excluded   []string
}

func parseList(r *http.Request) (listParams, error) {
	q := r.URL.Query()
	p := listParams{start: 1, count: MaxResults}
	if f := q.Get("filter"); f != "" {
		flt, err := ParseFilter(f)
		if err != nil {
			return p, badRequest("invalidFilter", "%s", strings.TrimPrefix(err.Error(), errInvalidFilter.Error()+": "))
		}
		p.filter = flt
	}
	if s := q.Get("startIndex"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return p, badRequest("invalidValue", "startIndex must be an integer.")
		}
		if n > 1 {
			p.start = n
		}
	}
	if s := q.Get("count"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return p, badRequest("invalidValue", "count must be an integer.")
		}
		p.count = max(0, min(n, MaxResults))
	}
	p.attributes = splitAttrs(q.Get("attributes"))
	p.excluded = splitAttrs(q.Get("excludedAttributes"))
	return p, nil
}

func splitAttrs(s string) []string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			if path, err := attrPath(a); err == nil {
				out = append(out, path[0])
			}
		}
	}
	return out
}

// project applies attributes/excludedAttributes to a resource's top-level
// attributes; id and schemas are always returned.
func project(res map[string]any, attributes, excluded []string) map[string]any {
	keep := func(k string) bool {
		lk := strings.ToLower(k)
		if lk == "id" || lk == "schemas" {
			return true
		}
		if len(attributes) > 0 {
			for _, a := range attributes {
				if a == lk {
					return true
				}
			}
			return false
		}
		for _, a := range excluded {
			if a == lk {
				return false
			}
		}
		return true
	}
	for k := range res {
		if !keep(k) {
			delete(res, k)
		}
	}
	return res
}

// page filters, paginates and projects resources.
func page(w http.ResponseWriter, p listParams, all []map[string]any) {
	var matched []map[string]any
	for _, res := range all {
		if p.filter == nil || p.filter.Match(res) {
			matched = append(matched, res)
		}
	}
	var out []map[string]any
	for i := p.start - 1; i < len(matched) && len(out) < p.count; i++ {
		out = append(out, project(matched[i], p.attributes, p.excluded))
	}
	writeList(w, len(matched), p.start, out)
}

// projectOne applies attributes/excludedAttributes to a single resource.
func projectOne(r *http.Request, res map[string]any) map[string]any {
	q := r.URL.Query()
	return project(res, splitAttrs(q.Get("attributes")), splitAttrs(q.Get("excludedAttributes")))
}

func meta(resourceType, created, modified, location string) map[string]any {
	return map[string]any{
		"resourceType": resourceType, "created": created, "lastModified": modified, "location": location,
	}
}
