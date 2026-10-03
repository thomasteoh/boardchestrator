package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIP(t *testing.T) {
	tp := TrustedProxies{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	cases := []struct {
		name   string
		tp     TrustedProxies
		remote string
		xff    []string
		want   string
	}{
		{"no proxies configured ignores XFF", nil, "203.0.113.9:5000", []string{"1.2.3.4"}, "203.0.113.9"},
		{"untrusted peer ignores XFF", tp, "203.0.113.9:5000", []string{"1.2.3.4"}, "203.0.113.9"},
		{"trusted peer, client hop", tp, "10.1.2.3:443", []string{"198.51.100.7"}, "198.51.100.7"},
		{"forged left hops ignored", tp, "10.1.2.3:443", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"proxy chain walked right to left", tp, "10.1.2.3:443", []string{"6.6.6.6, 198.51.100.7, 10.9.9.9"}, "198.51.100.7"},
		{"multiple headers joined", tp, "10.1.2.3:443", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"malformed hop stops at last trusted", tp, "10.1.2.3:443", []string{"198.51.100.7, garbage"}, "10.1.2.3"},
		{"all trusted gives leftmost", tp, "10.1.2.3:443", []string{"10.4.4.4, 10.5.5.5"}, "10.4.4.4"},
		{"trusted peer without XFF", tp, "10.1.2.3:443", nil, "10.1.2.3"},
		{"ipv6 peer", tp, "[::1]:443", []string{"2001:db8::1"}, "2001:db8::1"},
		{"mapped v4 hop", tp, "10.1.2.3:443", []string{"::ffff:198.51.100.7"}, "198.51.100.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = c.remote
			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := c.tp.ClientIP(r); got != c.want {
				t.Fatalf("ClientIP = %q, want %q", got, c.want)
			}
			var seen string
			ClientIPMiddleware(c.tp)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = ClientIP(r)
			})).ServeHTTP(httptest.NewRecorder(), r)
			if seen != c.want {
				t.Fatalf("via middleware = %q, want %q", seen, c.want)
			}
		})
	}
	// Without the middleware XFF is never read.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.1.2.3:443"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := ClientIP(r); got != "10.1.2.3" {
		t.Fatalf("ClientIP without middleware = %q", got)
	}
}
