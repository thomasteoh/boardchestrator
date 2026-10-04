package server_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/auth/oidctest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/perm"
)

// WU-605: bootstrap token, sign-in rate limits, auth audit rows. End to end
// through the production wiring (newSMHarness) against oidctest.

const bsToken = "bootstrap-token-0123456789abcdef"

var nonceRe = regexp.MustCompile(`nonce="[^"]*"`)

// get fetches path with b (no redirects) and returns status, headers and a
// body with CSP nonces blanked, for comparing pages.
func (h *smHarness) get(b *oidctest.Browser, path string, hdr ...string) (int, http.Header, string) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.app.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := b.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, nonceRe.ReplaceAllString(string(body), `nonce=""`)
}

func (h *smHarness) isPlatformOwner(userID string) bool {
	return h.n(`SELECT COUNT(*) FROM memberships WHERE org_id = ? AND actor_type='user' AND actor_id = ?
		AND resource_type='org' AND resource_id = ? AND role_id = ?`,
		perm.PlatformOrg, userID, perm.PlatformOrg, perm.PlatformOwnerRole) == 1
}

func (h *smHarness) userID(email string) string {
	h.t.Helper()
	var id string
	if err := h.db.QueryRow(`SELECT id FROM users WHERE email = ?`, email).Scan(&id); err != nil {
		h.t.Fatalf("user %s: %v", email, err)
	}
	return id
}

func (h *smHarness) bootstrapped() bool {
	return h.n(`SELECT bootstrap_done FROM platform_settings WHERE id = 1`) == 1
}

// beginClaim opens the claim page with token, then follows the claim button
// for provider up to (not including) the app callback, returning it.
func (h *smHarness) beginClaim(b *oidctest.Browser, token, provider, hint string) string {
	h.t.Helper()
	status, _, body := h.get(b, "/setup?token="+url.QueryEscape(token))
	if status != http.StatusOK || !strings.Contains(body, "Claim this instance") ||
		!strings.Contains(body, `href="/auth/`+provider+`?bootstrap=1"`) {
		h.t.Fatalf("claim page: %d %q", status, body)
	}
	steps, err := b.Follow(h.app.URL+"/auth/"+provider+"?bootstrap=1&login_hint="+url.QueryEscape(hint), 8,
		func(next *url.URL) bool { return strings.HasSuffix(next.Path, "/callback") })
	if err != nil {
		h.t.Fatal(err)
	}
	return steps[len(steps)-1].URL
}

func TestBootstrapTokenClaim(t *testing.T) {
	// Sign-up is closed on corp and carol is on no admin list: only the
	// token lets her in.
	h := newSMHarness(t, smOpts{unclaimed: true, bootstrapToken: bsToken, corpSignup: false})
	h.corp.AddUser("carol", oidctest.User{Subject: "carol-c", Email: "carol@corp.example", EmailVerified: true})

	// Without the token she is refused.
	if end := h.follow(oidctest.NewBrowser(t), "/auth/corp?login_hint=carol"); end.Status != http.StatusForbidden {
		t.Fatalf("login without token while unclaimed: %d", end.Status)
	}
	// Nor does ?bootstrap=1 alone (no setup cookie) do anything.
	if end := h.follow(oidctest.NewBrowser(t), "/auth/corp?bootstrap=1&login_hint=carol"); end.Status != http.StatusForbidden {
		t.Fatalf("bootstrap=1 without setup cookie: %d", end.Status)
	}
	if h.n(`SELECT COUNT(*) FROM users WHERE email='carol@corp.example'`) != 0 {
		t.Fatal("user created without the token")
	}

	// A wrong token is a plain 404.
	b := oidctest.NewBrowser(t)
	wrongStatus, wrongHdr, wrongBody := h.get(b, "/setup?token=not-the-token")
	if wrongStatus != http.StatusNotFound || b.Cookie(h.app.URL, auth.SetupCookieName) != nil {
		t.Fatalf("wrong token: %d, setup cookie set: %v", wrongStatus, b.Cookie(h.app.URL, auth.SetupCookieName) != nil)
	}
	if strings.Contains(wrongBody, "Claim") {
		t.Fatal("wrong token shows the claim page")
	}

	// The right token claims the instance.
	cb := h.beginClaim(b, bsToken, "corp", "carol")
	if end := h.follow(b, cb); end.Status != http.StatusOK {
		t.Fatalf("claim: %d %q", end.Status, end.Body)
	}
	carol := h.userID("carol@corp.example")
	if !h.isPlatformOwner(carol) || !h.bootstrapped() {
		t.Fatalf("after claim: owner=%v bootstrapped=%v", h.isPlatformOwner(carol), h.bootstrapped())
	}
	if b.Cookie(h.app.URL, auth.SetupCookieName) != nil {
		t.Error("setup cookie survives the claim")
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.signup' AND actor_id=? AND json_extract(detail_json,'$.method')='bootstrap'`, carol) != 1 ||
		h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.bootstrap' AND actor_id=? AND json_extract(detail_json,'$.via')='token'`, carol) != 1 {
		t.Error("bootstrap sign-up / claim not audited")
	}

	// The token is now dead, and the answer is the same 404 as a wrong
	// token: no oracle for "right token, too late".
	b2 := oidctest.NewBrowser(t)
	lateStatus, lateHdr, lateBody := h.get(b2, "/setup?token="+bsToken)
	if lateStatus != wrongStatus || lateBody != wrongBody ||
		lateHdr.Get("Content-Type") != wrongHdr.Get("Content-Type") || b2.Cookie(h.app.URL, auth.SetupCookieName) != nil {
		t.Fatalf("after bootstrap: %d vs %d, bodies equal %v", lateStatus, wrongStatus, lateBody == wrongBody)
	}
	// And it matches an unknown page's body.
	_, _, unknownBody := h.get(b2, "/no-such-page")
	if strings.ReplaceAll(unknownBody, "/no-such-page", "") != strings.ReplaceAll(wrongBody, "/setup", "") &&
		unknownBody != wrongBody {
		t.Errorf("setup 404 differs from an ordinary 404")
	}
	// A second person cannot use it.
	h.corp.AddUser("dave", oidctest.User{Subject: "dave-c", Email: "dave@corp.example", EmailVerified: true})
	if end := h.follow(b2, "/auth/corp?bootstrap=1&login_hint=dave"); end.Status != http.StatusForbidden {
		t.Fatalf("dave after bootstrap: %d", end.Status)
	}
	if h.n(`SELECT COUNT(*) FROM users WHERE email='dave@corp.example'`) != 0 {
		t.Fatal("dave got an account")
	}
}

func TestBootstrapRaceOnlyFirstIsOwner(t *testing.T) {
	// Open sign-up, so the loser still gets in, as an ordinary user.
	h := newSMHarness(t, smOpts{unclaimed: true, bootstrapToken: bsToken, corpSignup: true})
	h.corp.AddUser("a", oidctest.User{Subject: "a-c", Email: "a@corp.example", EmailVerified: true})
	h.corp.AddUser("b", oidctest.User{Subject: "b-c", Email: "b@corp.example", EmailVerified: true})
	ba, bb := oidctest.NewBrowser(t), oidctest.NewBrowser(t)
	// Both flows are minted while the platform is unclaimed.
	cbA := h.beginClaim(ba, bsToken, "corp", "a")
	cbB := h.beginClaim(bb, bsToken, "corp", "b")
	if end := h.follow(ba, cbA); end.Status != http.StatusOK {
		t.Fatalf("first claim: %d", end.Status)
	}
	if end := h.follow(bb, cbB); end.Status != http.StatusOK {
		t.Fatalf("second claim (ordinary sign-up): %d %q", end.Status, end.Body)
	}
	a, b := h.userID("a@corp.example"), h.userID("b@corp.example")
	if !h.isPlatformOwner(a) || h.isPlatformOwner(b) {
		t.Fatalf("owners: a=%v b=%v; want only a", h.isPlatformOwner(a), h.isPlatformOwner(b))
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.bootstrap'`) != 1 {
		t.Fatal("more than one bootstrap claim audited")
	}

	// Truly concurrent: of N stale-or-fresh claims racing, exactly one owner.
	h2 := newSMHarness(t, smOpts{unclaimed: true, bootstrapToken: bsToken, corpSignup: true})
	const n = 4
	cbs := make([]string, n)
	browsers := make([]*oidctest.Browser, n)
	for i := range n {
		hint := "r" + strconv.Itoa(i)
		h2.corp.AddUser(hint, oidctest.User{Subject: hint, Email: hint + "@corp.example", EmailVerified: true})
		browsers[i] = oidctest.NewBrowser(t)
		cbs[i] = h2.beginClaim(browsers[i], bsToken, "corp", hint)
	}
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = browsers[i].Follow(cbs[i], 8, nil)
		}(i)
	}
	wg.Wait()
	if got := h2.n(`SELECT COUNT(*) FROM memberships WHERE org_id = ? AND actor_type='user'`, perm.PlatformOrg); got != 1 {
		t.Fatalf("%d platform owners after a concurrent claim race, want 1", got)
	}
}

func TestBootstrapGeneratedToken(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, nil)))
	h := newSMHarness(t, smOpts{unclaimed: true}) // no BC_BOOTSTRAP_TOKEN, no BC_ADMIN_EMAILS
	slog.SetDefault(prev)

	mu.Lock()
	logs := buf.String()
	mu.Unlock()
	m := regexp.MustCompile(`claim_url=\S*/setup\?token=([0-9a-f]{64})`).FindStringSubmatch(logs)
	if m == nil || !strings.Contains(logs, "level=WARN") {
		t.Fatalf("no claim URL logged at WARN:\n%s", logs)
	}
	token := m[1]
	var settings string
	if err := h.db.QueryRow(`SELECT settings_json FROM platform_settings WHERE id = 1`).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(token))
	if strings.Contains(settings, token) || !strings.Contains(settings, hex.EncodeToString(sum[:])) {
		t.Fatalf("settings_json %s: want the token's hash only", settings)
	}

	h.corp.AddUser("erin", oidctest.User{Subject: "erin-c", Email: "erin@corp.example", EmailVerified: true})
	b := oidctest.NewBrowser(t)
	if end := h.follow(b, h.beginClaim(b, token, "corp", "erin")); end.Status != http.StatusOK {
		t.Fatalf("claim with generated token: %d", end.Status)
	}
	if !h.isPlatformOwner(h.userID("erin@corp.example")) {
		t.Fatal("generated-token claim did not grant platform owner")
	}
	if err := h.db.QueryRow(`SELECT settings_json FROM platform_settings WHERE id = 1`).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(settings, "bootstrap_token_hash") {
		t.Errorf("hash kept after the claim: %s", settings)
	}
	if status, _, _ := h.get(oidctest.NewBrowser(t), "/setup?token="+token); status != http.StatusNotFound {
		t.Fatalf("generated token after claim: %d", status)
	}
}

func TestBootstrapNoTokenWithAdminEmails(t *testing.T) {
	// BC_ADMIN_EMAILS set and no token: nothing is generated, /setup is 404.
	h := newSMHarness(t, smOpts{unclaimed: true, adminEmails: []string{"admin@example.com"}})
	var settings string
	_ = h.db.QueryRow(`SELECT settings_json FROM platform_settings WHERE id = 1`).Scan(&settings)
	if strings.Contains(settings, "bootstrap_token_hash") {
		t.Fatalf("token generated despite BC_ADMIN_EMAILS: %s", settings)
	}
	if status, _, _ := h.get(oidctest.NewBrowser(t), "/setup?token=anything"); status != http.StatusNotFound {
		t.Fatalf("/setup: %d", status)
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestSignInRateLimit(t *testing.T) {
	h := newSMHarness(t, smOpts{defaultRateLimit: true})
	b := oidctest.NewBrowser(t)
	for i := range 10 {
		if status, _, _ := h.get(b, "/login"); status != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, status)
		}
	}
	status, hdr, body := h.get(b, "/login")
	if status != http.StatusTooManyRequests {
		t.Fatalf("11th /login: %d", status)
	}
	if ra, err := strconv.Atoi(hdr.Get("Retry-After")); err != nil || ra < 1 || ra > 3 {
		t.Fatalf("Retry-After %q", hdr.Get("Retry-After"))
	}
	if !strings.Contains(body, "Too many sign-in attempts") || !strings.Contains(hdr.Get("Content-Type"), "text/html") {
		t.Fatalf("429 page: %q %q", hdr.Get("Content-Type"), body)
	}
	// /auth/* and /setup share the bucket; other pages are not limited.
	for _, p := range []string{"/auth/google", "/auth/logout", "/setup?token=x"} {
		if status, _, _ := h.get(b, p); status != http.StatusTooManyRequests {
			t.Errorf("%s while limited: %d", p, status)
		}
	}
	if status, _, _ := h.get(b, "/healthz"); status != http.StatusOK {
		t.Errorf("/healthz limited: %d", status)
	}
	// No trusted proxies: X-Forwarded-For is ignored, so a forged header
	// does not buy a fresh bucket.
	if status, _, _ := h.get(b, "/login", "X-Forwarded-For", "198.51.100.77"); status != http.StatusTooManyRequests {
		t.Errorf("forged XFF from an untrusted peer escaped the limit: %d", status)
	}
}

func TestSignInRateLimitPerIPBehindTrustedProxy(t *testing.T) {
	h := newSMHarness(t, smOpts{defaultRateLimit: true,
		trustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}})
	b := oidctest.NewBrowser(t)
	for range 10 {
		h.get(b, "/login", "X-Forwarded-For", "198.51.100.1")
	}
	if status, _, _ := h.get(b, "/login", "X-Forwarded-For", "198.51.100.1"); status != http.StatusTooManyRequests {
		t.Fatalf("client 1 not limited: %d", status)
	}
	// A different client behind the same proxy has its own bucket ...
	if status, _, _ := h.get(b, "/login", "X-Forwarded-For", "198.51.100.2"); status != http.StatusOK {
		t.Fatalf("client 2 limited by client 1: %d", status)
	}
	// ... and forging hops to the left of the proxy's does not help client 1.
	if status, _, _ := h.get(b, "/login", "X-Forwarded-For", "203.0.113.5, 198.51.100.1"); status != http.StatusTooManyRequests {
		t.Fatalf("forged left hop escaped the limit: %d", status)
	}

	// The audit row records the forwarded client address.
	h.google.AddUser("bob", oidctest.User{Subject: "bob-g", Email: "bob@example.com", EmailVerified: true})
	steps, err := b.Follow(h.app.URL+"/auth/google?login_hint=bob", 8, func(next *url.URL) bool {
		return strings.HasSuffix(next.Path, "/callback")
	})
	if err != nil {
		t.Fatal(err)
	}
	cb := steps[len(steps)-1].URL
	req, _ := http.NewRequest(http.MethodGet, cb, nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	resp, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback: %d", resp.StatusCode)
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.login' AND actor_id='u-bob' AND ip='198.51.100.9'`) != 1 {
		t.Fatal("auth.login IP is not the forwarded client")
	}
	if h.n(`SELECT COUNT(*) FROM sessions WHERE user_id='u-bob' AND ip='198.51.100.9'`) != 1 {
		t.Error("session IP is not the forwarded client")
	}
}

func TestAuthAuditRows(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	h.google.AddUser("bob", oidctest.User{Subject: "bob-g", Email: "bob@example.com", EmailVerified: true})

	// Success.
	b := oidctest.NewBrowser(t)
	if end := h.follow(b, "/auth/google?login_hint=bob"); end.Status != http.StatusOK {
		t.Fatalf("login: %d", end.Status)
	}
	var actorType, subject, ip, detail string
	if err := h.db.QueryRow(`SELECT actor_type, subject, ip, detail_json FROM audit_log WHERE action='auth.login' AND actor_id='u-bob'`).
		Scan(&actorType, &subject, &ip, &detail); err != nil {
		t.Fatalf("auth.login row: %v", err)
	}
	if actorType != "user" || subject != "google" || ip == "" || strings.Contains(ip, ":5") ||
		!strings.Contains(detail, `"method":"oidc"`) || !strings.Contains(detail, `"provider":"google"`) || !strings.Contains(detail, `"ua":`) {
		t.Fatalf("auth.login row: %s %s %s %s", actorType, subject, ip, detail)
	}

	// Logout.
	sess := b.Cookie(h.app.URL, auth.CookieName)
	if sess == nil {
		t.Fatal("no session cookie")
	}
	var tokenHash string
	sum := sha256.Sum256([]byte(sess.Value))
	tokenHash = hex.EncodeToString(sum[:])
	csrf := auth.CSRFToken(smSessionSecret, tokenHash)
	if resp := h.post(b, "/auth/logout", csrf); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.logout' AND actor_type='user' AND actor_id='u-bob' AND ip <> ''`) != 1 {
		t.Fatal("no auth.logout row")
	}
	// A logout without a session writes nothing.
	if resp := h.post(oidctest.NewBrowser(t), "/auth/logout", ""); resp.StatusCode >= 500 {
		t.Fatalf("anonymous logout: %d", resp.StatusCode)
	}
	if h.n(`SELECT COUNT(*) FROM audit_log WHERE action='auth.logout'`) != 1 {
		t.Fatal("anonymous logout audited")
	}

	// Failure: the IdP signs for another audience.
	h.google.SetMisbehaviour(oidctest.Misbehaviour{WrongAudience: true})
	if end := h.follow(oidctest.NewBrowser(t), "/auth/google?login_hint=bob"); end.Status != http.StatusForbidden {
		t.Fatalf("bad login: %d", end.Status)
	}
	h.google.SetMisbehaviour(oidctest.Misbehaviour{})
	// Failure: a refusal (sign-up closed on corp, unknown user).
	h.corp.AddUser("zed", oidctest.User{Subject: "zed-c", Email: "zed@corp.example", EmailVerified: true})
	if end := h.follow(oidctest.NewBrowser(t), "/auth/corp?login_hint=zed"); end.Status != http.StatusForbidden {
		t.Fatalf("refused login: %d", end.Status)
	}
	rows, err := h.db.Query(`SELECT actor_type, actor_id, ip, detail_json FROM audit_log WHERE action='auth.login_failed' ORDER BY created_at`)
	if err != nil {
		t.Fatal(err)
	}
	var reasons []string
	for rows.Next() {
		var at, aid, ip, d string
		if err := rows.Scan(&at, &aid, &ip, &d); err != nil {
			t.Fatal(err)
		}
		if at != "anonymous" || aid != "" || ip == "" {
			t.Errorf("login_failed actor %q/%q ip %q", at, aid, ip)
		}
		for _, bad := range []string{"someone-else", "audience", "oidc", "zed@", "err"} {
			if strings.Contains(strings.ToLower(d), bad) {
				t.Errorf("login_failed detail leaks %q: %s", bad, d)
			}
		}
		reasons = append(reasons, d)
	}
	_ = rows.Close()
	if len(reasons) != 2 || !strings.Contains(reasons[0], `"reason":"assertion"`) || !strings.Contains(reasons[1], `"reason":"no_account"`) {
		t.Fatalf("login_failed rows: %v", reasons)
	}

	// No secrets anywhere in the auth rows: no JWTs, codes, states or tokens.
	all, err := h.db.Query(`SELECT detail_json FROM audit_log WHERE action LIKE 'auth.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer all.Close()
	for all.Next() {
		var d string
		_ = all.Scan(&d)
		for _, bad := range []string{"eyJ", `"code"`, `"state"`, "token", sess.Value} {
			if strings.Contains(d, bad) {
				t.Errorf("audit detail contains %q: %s", bad, d)
			}
		}
	}
}

func TestAuditViews(t *testing.T) {
	h := newSMHarness(t, smOpts{})
	for _, q := range []string{
		`INSERT INTO orgs (id, name, slug) VALUES ('org-b','Beta','beta')`,
		`INSERT INTO roles (id, org_id, name, is_system, grants_json) VALUES ('r-owner','org-acme','Owner',0,'["*"]')`,
		`INSERT INTO memberships (id, org_id, actor_id, actor_type, resource_type, resource_id, role_id) VALUES
		 ('m-plat','00000000000000000000000000000000','u-admin','user','org','00000000000000000000000000000000','00000000000000000000000000000000'),
		 ('m-bob','org-acme','u-bob','user','org','org-acme','r-owner')`,
		`INSERT INTO audit_log (id, org_id, actor_type, actor_id, action, subject, ip) VALUES
		 ('a-acme','org-acme','user','u-bob','project.create','acme-thing','10.0.0.1'),
		 ('a-beta','org-b','user','u-alice','project.create','beta-secret-thing','10.0.0.2')`,
	} {
		if _, err := h.db.Exec(q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	// Sign-in events for Bob and a failure.
	h.google.AddUser("bob", oidctest.User{Subject: "bob-g", Email: "bob@example.com", EmailVerified: true})
	if end := h.follow(oidctest.NewBrowser(t), "/auth/google?login_hint=bob"); end.Status != http.StatusOK {
		t.Fatalf("login: %d", end.Status)
	}
	h.google.SetMisbehaviour(oidctest.Misbehaviour{Expired: true})
	h.follow(oidctest.NewBrowser(t), "/auth/google?login_hint=bob")
	h.google.SetMisbehaviour(oidctest.Misbehaviour{})

	// Platform admin sees the sign-in rows, not org rows.
	admin := oidctest.NewBrowser(t)
	h.signedIn(admin, "u-admin")
	status, _, body := h.get(admin, "/admin/audit")
	if status != http.StatusOK {
		t.Fatalf("/admin/audit as admin: %d", status)
	}
	for _, want := range []string{"Platform audit log", "auth.login", "auth.login_failed", "anonymous:", "user:u-bob", `&#34;reason&#34;:&#34;assertion&#34;`} {
		if !strings.Contains(body, want) {
			t.Errorf("platform audit view lacks %q", want)
		}
	}
	if strings.Contains(body, "beta-secret-thing") || strings.Contains(body, "acme-thing") {
		t.Error("platform audit view shows org rows")
	}

	// Bob owns acme: his org view shows acme's rows only, and no sign-ins.
	bob := oidctest.NewBrowser(t)
	h.signedIn(bob, "u-bob")
	status, _, body = h.get(bob, "/app/org/org-acme/audit")
	if status != http.StatusOK || !strings.Contains(body, "acme-thing") {
		t.Fatalf("acme audit as owner: %d", status)
	}
	if strings.Contains(body, "beta-secret-thing") || strings.Contains(body, "auth.login") {
		t.Error("org audit view shows another org's or platform rows")
	}
	// He is no member of Beta, and not a platform admin.
	for _, p := range []string{"/app/org/org-b/audit", "/app/org/org-b/audit/export", "/admin/audit"} {
		status, _, body := h.get(bob, p)
		if status != http.StatusForbidden || strings.Contains(body, "beta-secret-thing") || strings.Contains(body, "auth.login") {
			t.Errorf("%s as acme owner: %d", p, status)
		}
	}
	// The action cannot be steered to another org through input.org_id.
	disp := action.New(h.db,
		action.WithScopeResolver(action.NewDBScopeResolver(h.db)),
		action.WithPermissionChecker(perm.NewCheckerAdapter(h.db)))
	out, err := disp.Dispatch(context.Background(), action.Actor{Type: action.ActorUser, ID: "u-bob"},
		"audit.log.list", json.RawMessage(`{"org_id":"org-b"}`), action.Opts{Org: "org-acme"})
	if err != nil {
		t.Fatal(err)
	}
	listed, _ := out.([]sqlc.AuditLog)
	if len(listed) == 0 {
		t.Fatal("audit.log.list returned nothing for acme")
	}
	for _, r := range listed {
		if r.OrgID.String != "org-acme" {
			t.Errorf("audit.log.list for acme returned a row of %q", r.OrgID.String)
		}
	}
	// Anonymous visitors are sent to sign in.
	if status, hdr, _ := h.get(oidctest.NewBrowser(t), "/admin/audit"); status != http.StatusSeeOther ||
		!strings.HasPrefix(hdr.Get("Location"), "/login") {
		t.Errorf("anonymous /admin/audit: %d %s", status, hdr.Get("Location"))
	}
}
