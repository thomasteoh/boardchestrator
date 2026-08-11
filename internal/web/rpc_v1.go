package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
)

// WU-401 REST API core: uniform RPC over `/api/v1/actions/{name}`.
// Bearer (API-key) auth, problem+json errors with stable codes,
// Idempotency-Key header, per-key token-bucket rate limit + headers.

// rateLimiter is the per-API-key token bucket for the v1 RPC (WU-401).
// Burst 60 requests, refilling 1 token/sec — tunable via SetRateLimit later.
var rateLimiter = newTokenBucket(60, time.Second)

// SetRateLimit reconfigures the v1 RPC rate limiter (tests + operators).
func SetRateLimit(capacity int, refill time.Duration) {
	rateLimiter.mu.Lock()
	rateLimiter.capacity = capacity
	rateLimiter.refill = refill
	rateLimiter.mu.Unlock()
}

// problem is an RFC 7807 problem+json body.
type problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func writeProblem(w http.ResponseWriter, status int, typ, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem{Type: typ, Title: title, Status: status, Detail: detail})
}

// mapDispatchError converts a dispatch sentinel error into a problem+json
// response with a stable `type` code (WU-401).
func mapDispatchError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, action.ErrUnknownAction):
		writeProblem(w, http.StatusNotFound, "unknown_action", "Unknown action", err.Error())
	case errors.Is(err, action.ErrInvalidInput):
		writeProblem(w, http.StatusBadRequest, "invalid_input", "Invalid input", err.Error())
	case errors.Is(err, action.ErrScope):
		writeProblem(w, http.StatusUnprocessableEntity, "scope_error", "Scope resolution failed", err.Error())
	case errors.Is(err, action.ErrForbidden):
		writeProblem(w, http.StatusForbidden, "forbidden", "Forbidden", err.Error())
	case errors.Is(err, action.ErrApprovalPending{}):
		writeProblem(w, http.StatusConflict, "approval_pending", "Approval pending", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "internal", "Internal error", err.Error())
	}
}

// tokenBucket is a per-key rate limiter (WU-401): fixed refill over a window.
type tokenBucket struct {
	mu       sync.Mutex
	capacity int
	refill   time.Duration // one token per refill
	tokens   map[string]bucketState
	now      func() time.Time
}

type bucketState struct {
	tokens float64
	last   time.Time
}

// newTokenBucket returns a limiter with `capacity` burst tokens refilling one
// token per `refill` interval per key.
func newTokenBucket(capacity int, refill time.Duration) *tokenBucket {
	return &tokenBucket{
		capacity: capacity,
		refill:   refill,
		tokens:   map[string]bucketState{},
		now:      time.Now,
	}
}

// allow takes one token for key, returning whether it may proceed, the
// remaining tokens, and the retry-after duration when denied. The limit
// applies per API-key actor (WU-401 AC).
func (b *tokenBucket) allow(key string) (ok bool, remaining float64, retryAfter time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	st, ok := b.tokens[key]
	if !ok {
		b.tokens[key] = bucketState{tokens: float64(b.capacity), last: now}
		return true, float64(b.capacity - 1), 0
	}
	// Refill elapsed tokens.
	elapsed := now.Sub(st.last)
	added := elapsed.Seconds() / b.refill.Seconds()
	st.tokens = st.tokens + added
	if st.tokens > float64(b.capacity) {
		st.tokens = float64(b.capacity)
	}
	st.last = now
	b.tokens[key] = st
	if st.tokens < 1 {
		return false, st.tokens, time.Until(st.last.Add(b.refill))
	}
	st.tokens--
	b.tokens[key] = st
	return true, st.tokens, 0
}

// handleRPCv1 is the uniform REST RPC handler (WU-401).
func handleRPCv1(rate *tokenBucket) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if disp == nil {
			writeProblem(w, http.StatusInternalServerError, "internal", "Dispatcher not configured", "")
			return
		}

		// Bearer API-key auth. The actor is resolved by the middleware from
		// the Authorization header and stashed in context.
		actor, ok := auth.APIKeyActorFrom(r.Context())
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", "Bearer API key required", "")
			return
		}

		// Per-key rate limit (WU-401 AC: 429 with headers).
		if rate != nil {
			ok, remaining, retry := rate.allow(actor.ID)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rate.capacity))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatFloat(remaining, 'f', -1, 64))
			if !ok {
				if retry > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
				}
				writeProblem(w, http.StatusTooManyRequests, "rate_limited", "Rate limit exceeded", "")
				return
			}
		}

		name := r.URL.Path[len("/api/v1/actions/"):]
		var input json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid_input", "Invalid JSON body", err.Error())
			return
		}

		opts := action.Opts{}
		if v := r.Header.Get("Idempotency-Key"); v != "" {
			opts.Idem = v
		}
		if v := r.Header.Get("X-Org-Id"); v != "" {
			opts.Org = v
		}
		if v := r.Header.Get("X-Project-Id"); v != "" {
			opts.Proj = v
		}
		if v := r.Header.Get("X-Team-Id"); v != "" {
			opts.Team = v
		}

		result, err := disp.Dispatch(r.Context(), actor, name, input, opts)
		if err != nil {
			mapDispatchError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}
