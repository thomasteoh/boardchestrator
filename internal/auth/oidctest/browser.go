package oidctest

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Browser is a minimal cookie-keeping user agent for login tests. It follows
// redirects across hosts one hop at a time and, unlike net/http/cookiejar,
// keeps Secure and __Host- cookies over plain-HTTP test servers so production
// cookie attributes can be exercised unchanged.
type Browser struct {
	t       testing.TB
	client  *http.Client
	mu      sync.Mutex
	cookies map[string]map[string]*http.Cookie // host → name → cookie
	// SetCookies records every Set-Cookie header seen, in order.
	SetCookies []*http.Cookie
}

// NewBrowser returns an empty browser.
func NewBrowser(t testing.TB) *Browser {
	return &Browser{
		t: t,
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		cookies: map[string]map[string]*http.Cookie{},
	}
}

// Cookie returns the named cookie held for rawURL's host, or nil.
func (b *Browser) Cookie(rawURL, name string) *http.Cookie {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cookies[u.Host][name]
}

// SetCookie plants a cookie for rawURL's host (e.g. a stale or forged one).
func (b *Browser) SetCookie(rawURL string, c *http.Cookie) {
	u, err := url.Parse(rawURL)
	if err != nil {
		b.t.Fatalf("browser: parse %q: %v", rawURL, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cookies[u.Host] == nil {
		b.cookies[u.Host] = map[string]*http.Cookie{}
	}
	b.cookies[u.Host][c.Name] = c
}

// DeleteCookie forgets the named cookie for rawURL's host.
func (b *Browser) DeleteCookie(rawURL, name string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.cookies[u.Host], name)
}

// Do sends req with the browser's cookies for its host and stores any
// Set-Cookie on the response. It does not follow redirects.
func (b *Browser) Do(req *http.Request) (*http.Response, error) {
	b.mu.Lock()
	for _, c := range b.cookies[req.URL.Host] {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	b.mu.Unlock()
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range resp.Cookies() {
		b.SetCookies = append(b.SetCookies, c)
		if b.cookies[req.URL.Host] == nil {
			b.cookies[req.URL.Host] = map[string]*http.Cookie{}
		}
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies[req.URL.Host], c.Name)
			continue
		}
		b.cookies[req.URL.Host][c.Name] = c
	}
	return resp, nil
}

// Get issues a GET without following redirects.
func (b *Browser) Get(rawURL string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	return b.Do(req)
}

// Step is one hop of a followed redirect chain.
type Step struct {
	URL    string
	Status int
	Body   string
}

// Follow GETs rawURL and follows up to max redirects across hosts, stopping
// early before any URL for which stop returns true (that URL is returned
// unvisited as the last step's Location). It returns every hop.
func (b *Browser) Follow(rawURL string, max int, stop func(next *url.URL) bool) ([]Step, error) {
	var steps []Step
	cur := rawURL
	for i := 0; i <= max; i++ {
		resp, err := b.Get(cur)
		if err != nil {
			return steps, err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		steps = append(steps, Step{URL: cur, Status: resp.StatusCode, Body: string(body)})
		var loc *url.URL
		if next := ContinueURL(string(body)); resp.StatusCode == http.StatusOK && next != "" {
			// A continue page (auth.ContinueTo): follow its meta refresh
			// as a browser would.
			base, _ := url.Parse(cur)
			if loc, err = base.Parse(next); err != nil {
				return steps, fmt.Errorf("browser: continue page %s: %w", cur, err)
			}
		} else {
			if resp.StatusCode < 300 || resp.StatusCode >= 400 {
				return steps, nil
			}
			if loc, err = resp.Location(); err != nil {
				return steps, fmt.Errorf("browser: redirect without Location from %s", cur)
			}
		}
		if stop != nil && stop(loc) {
			steps = append(steps, Step{URL: loc.String()})
			return steps, nil
		}
		cur = loc.String()
	}
	return steps, fmt.Errorf("browser: more than %d redirects from %s", max, rawURL)
}

var continueRe = regexp.MustCompile(`<meta http-equiv="refresh" content="0;url=([^"]*)">`)

// ContinueURL returns the destination of an auth.ContinueTo page (the meta
// refresh target, HTML-unescaped), or "" when body is not one. Tests use it
// where a form submission leads to another origin.
func ContinueURL(body string) string {
	m := continueRe.FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, "data-bc-continue") {
		return ""
	}
	return html.UnescapeString(m[1])
}

// NextURL is where resp sends the browser: its Location for a redirect, or
// the target of a continue page (which consumes the body). "" otherwise.
func NextURL(resp *http.Response) string {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.Header.Get("Location")
	}
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return ContinueURL(string(body))
}
