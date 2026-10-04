package auth

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedProxies are the peers (BC_TRUSTED_PROXIES) whose X-Forwarded-For
// header is believed. Empty means X-Forwarded-For is never read.
type TrustedProxies []netip.Prefix

func (tp TrustedProxies) trusts(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range tp {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP is the address of the client that sent r. The TCP peer is the
// answer unless it is a trusted proxy; then X-Forwarded-For is walked from
// the right (the hop the trusted proxy appended) to the first address that
// is not itself a trusted proxy. Anything left of that hop is client-supplied
// and ignored. A malformed hop stops the walk at the last trusted address, so
// a forged header can never pick the key.
func (tp TrustedProxies) ClientIP(r *http.Request) string {
	peer := remoteHost(r.RemoteAddr)
	pa, err := netip.ParseAddr(peer)
	if err != nil || len(tp) == 0 || !tp.trusts(pa) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	cur := pa.Unmap()
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if h == "" {
			continue
		}
		a, err := netip.ParseAddr(h)
		if err != nil {
			break
		}
		cur = a.Unmap()
		if !tp.trusts(cur) {
			break
		}
	}
	return cur.String()
}

type ctxKeyClientIP struct{}

// ClientIPMiddleware resolves the client address once per request (see
// TrustedProxies.ClientIP) for ClientIP to return.
func ClientIPMiddleware(tp TrustedProxies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := tp.ClientIP(r)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyClientIP{}, ip)))
		})
	}
}

// ClientIP is the client address resolved by ClientIPMiddleware, or the TCP
// peer when the middleware did not run (X-Forwarded-For is then never read).
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(ctxKeyClientIP{}).(string); ok && ip != "" {
		return ip
	}
	return remoteHost(r.RemoteAddr)
}

// remoteHost is RemoteAddr without the port.
func remoteHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
