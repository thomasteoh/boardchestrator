package server

import (
	"net/http"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/ratelimit"
	"github.com/thomasteoh/boardchestrator/internal/web"
)

// Sign-in rate limit (SPEC §7.11): per client IP, 20 a minute, bursts of 10.
const (
	signInPerMinute = 20
	signInBurst     = 10
)

// rateLimitedPath reports whether path is a sign-in route: /login, /setup
// and everything under /auth/.
func rateLimitedPath(path string) bool {
	return path == "/login" || path == auth.SetupURL || strings.HasPrefix(path, "/auth/")
}

// signInRateLimit limits the sign-in routes per client IP (auth.ClientIP,
// so it must run after auth.ClientIPMiddleware). Each Server has its own
// buckets.
func (s *Server) signInRateLimit() func(http.Handler) http.Handler {
	per, burst := signInPerMinute, signInBurst
	if rl := s.cfg.SignInRateLimit; rl.PerMinute > 0 && rl.Burst > 0 {
		per, burst = rl.PerMinute, rl.Burst
	}
	lim := ratelimit.New(per, burst)
	limited := lim.Middleware(auth.ClientIP, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		web.RenderErrorPage(w, r, http.StatusTooManyRequests, "Too many sign-in attempts",
			"Please wait a minute, then try again.")
	})
	return func(next http.Handler) http.Handler {
		lh := limited(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rateLimitedPath(r.URL.Path) {
				lh.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
