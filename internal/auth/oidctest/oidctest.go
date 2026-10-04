// Package oidctest is an in-process fake OpenID Connect provider for tests
// (SPEC §7). It serves discovery, JWKS, /authorize (auto-approving), /token
// (PKCE-checked, RS256-signed ID tokens honouring the authorize nonce),
// /userinfo and /end_session, mints back-channel logout tokens
// (LogoutToken), and can be told to misbehave: wrong aud or iss,
// wrong or missing nonce, expired tokens, unsigned alg:none tokens, and
// arbitrary claim overrides.
//
// Typical use:
//
//	idp := oidctest.New(t)
//	idp.SetUser(oidctest.User{Subject: "alice", Email: "alice@example.com", EmailVerified: true})
//	// point the connector at idp.Issuer() with idp.ClientID / idp.ClientSecret
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Default client credentials registered with every Server.
const (
	DefaultClientID     = "bc-test-client"
	DefaultClientSecret = "bc-test-secret"
)

// User is the identity the IdP asserts.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
	Groups        []string
	SID           string
	// Extra claims merged into the ID token and userinfo.
	Extra map[string]any
}

// Misbehaviour makes the next issued ID tokens wrong in specific ways.
type Misbehaviour struct {
	WrongAudience bool // aud = "someone-else"
	WrongIssuer   bool // iss = issuer + "/evil"
	WrongNonce    bool // nonce differs from the authorize request
	OmitNonce     bool // no nonce claim
	Expired       bool // exp an hour in the past
	AlgNone       bool // unsigned token with alg "none"
	WrongKey      bool // signed by a key not in the JWKS
	// OmitEmailFromIDToken leaves email out of the ID token so the RP must
	// fetch it from userinfo.
	OmitEmailFromIDToken bool
	// UserinfoSubject, when set, is returned as userinfo's sub.
	UserinfoSubject string
	// Claims override or add ID-token claims last (nil value deletes).
	Claims map[string]any
}

// AuthorizeRequest records what the RP sent to /authorize.
type AuthorizeRequest struct {
	ClientID, RedirectURI, State, Nonce, Scope string
	CodeChallenge, CodeChallengeMethod         string
	LoginHint                                  string
}

// TokenRequest records what the RP sent to /token.
type TokenRequest struct {
	Code, CodeVerifier, RedirectURI string
	ClientAuth                      string // "basic" | "post"
}

type codeGrant struct {
	req  AuthorizeRequest
	user User
}

// Server is the fake IdP.
type Server struct {
	srv          *httptest.Server
	ClientID     string
	ClientSecret string
	key          *rsa.PrivateKey
	rogueKey     *rsa.PrivateKey
	kid          string

	mu          sync.Mutex
	defaultUser User
	users       map[string]User // by login_hint
	misbehave   Misbehaviour
	codes       map[string]codeGrant
	tokens      map[string]User // access token → user
	authorizeLg []AuthorizeRequest
	tokenLg     []TokenRequest
	endSession  []url.Values
	requirePKCE bool
	// noEndSession hides end_session_endpoint from discovery.
	noEndSession bool
}

// Keys are generated once per test binary: RSA generation dominates test time
// under -race, and isolation between fake IdPs does not need distinct keys.
var (
	keysOnce          sync.Once
	signKey, rogueKey *rsa.PrivateKey
	keysErr           error
)

func testKeys() (*rsa.PrivateKey, *rsa.PrivateKey, error) {
	keysOnce.Do(func() {
		if signKey, keysErr = rsa.GenerateKey(rand.Reader, 2048); keysErr != nil {
			return
		}
		rogueKey, keysErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	return signKey, rogueKey, keysErr
}

// New starts a fake IdP that is closed with t.Cleanup. The default user is
// subject "user-1", email "user1@example.com", verified.
func New(t testing.TB) *Server {
	t.Helper()
	key, rogue, err := testKeys()
	if err != nil {
		t.Fatalf("oidctest: generate keys: %v", err)
	}
	s := &Server{
		ClientID:     DefaultClientID,
		ClientSecret: DefaultClientSecret,
		key:          key,
		rogueKey:     rogue,
		kid:          "oidctest-1",
		defaultUser:  User{Subject: "user-1", Email: "user1@example.com", EmailVerified: true, Name: "User One"},
		users:        map[string]User{},
		codes:        map[string]codeGrant{},
		tokens:       map[string]User{},
		requirePKCE:  true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /userinfo", s.userinfo)
	mux.HandleFunc("GET /end_session", s.endSessionHandler)
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// Issuer is the IdP's issuer URL (also its base URL).
func (s *Server) Issuer() string { return s.srv.URL }

// URL is an alias for Issuer.
func (s *Server) URL() string { return s.srv.URL }

// SetUser sets the identity asserted for logins without a matching login_hint.
func (s *Server) SetUser(u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.defaultUser = u
}

// AddUser registers u for logins whose authorize request carries
// login_hint=hint, so concurrent tests can each choose their own subject.
func (s *Server) AddUser(hint string, u User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[hint] = u
}

// SetMisbehaviour applies m to every subsequently issued token.
func (s *Server) SetMisbehaviour(m Misbehaviour) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.misbehave = m
}

// RequirePKCE toggles rejection of token requests without a valid
// code_verifier (default on).
func (s *Server) RequirePKCE(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requirePKCE = on
}

// AuthorizeRequests returns every /authorize request seen.
func (s *Server) AuthorizeRequests() []AuthorizeRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuthorizeRequest(nil), s.authorizeLg...)
}

// TokenRequests returns every successful /token request seen.
func (s *Server) TokenRequests() []TokenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]TokenRequest(nil), s.tokenLg...)
}

// EndSessionRequests returns the query of every /end_session request seen.
func (s *Server) EndSessionRequests() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.endSession...)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// SetEndSessionSupported toggles whether discovery advertises
// end_session_endpoint (default on). Connectors cache discovery, so set it
// before the first login through a fresh provider.
func (s *Server) SetEndSessionSupported(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.noEndSession = !on
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := s.Issuer()
	s.mu.Lock()
	noEnd := s.noEndSession
	s.mu.Unlock()
	doc := map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"jwks_uri":                              iss + "/jwks",
		"userinfo_endpoint":                     iss + "/userinfo",
		"end_session_endpoint":                  iss + "/end_session",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "name", "picture", "groups", "sid"},
		"backchannel_logout_supported":          true,
		"backchannel_logout_session_supported":  true,
	}
	if noEnd {
		delete(doc, "end_session_endpoint")
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := s.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": s.kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func randToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// authorize auto-approves and redirects back with code and state.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ar := AuthorizeRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		Scope:               q.Get("scope"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		LoginHint:           q.Get("login_hint"),
	}
	if ar.ClientID != s.ClientID || ar.RedirectURI == "" || q.Get("response_type") != "code" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	u, ok := s.users[ar.LoginHint]
	if !ok {
		u = s.defaultUser
	}
	code := randToken()
	s.codes[code] = codeGrant{req: ar, user: u}
	s.authorizeLg = append(s.authorizeLg, ar)
	s.mu.Unlock()

	dest, err := url.Parse(ar.RedirectURI)
	if err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	v := dest.Query()
	v.Set("code", code)
	v.Set("state", ar.State)
	dest.RawQuery = v.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func tokenError(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request")
		return
	}
	tr := TokenRequest{
		Code:         r.PostForm.Get("code"),
		CodeVerifier: r.PostForm.Get("code_verifier"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
	}
	id, secret, basic := r.BasicAuth()
	if basic {
		tr.ClientAuth = "basic"
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		tr.ClientAuth = "post"
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if subtle.ConstantTimeCompare([]byte(id), []byte(s.ClientID)) != 1 ||
		subtle.ConstantTimeCompare([]byte(secret), []byte(s.ClientSecret)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, "unsupported_grant_type")
		return
	}

	s.mu.Lock()
	g, ok := s.codes[tr.Code]
	delete(s.codes, tr.Code) // single use
	requirePKCE := s.requirePKCE
	m := s.misbehave
	s.mu.Unlock()
	if !ok || g.req.RedirectURI != tr.RedirectURI {
		tokenError(w, "invalid_grant")
		return
	}
	if g.req.CodeChallenge != "" || requirePKCE {
		if g.req.CodeChallengeMethod != "S256" || !pkceMatches(tr.CodeVerifier, g.req.CodeChallenge) {
			tokenError(w, "invalid_grant")
			return
		}
	}

	idToken, err := s.mintIDToken(g, m)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	access := randToken()
	s.mu.Lock()
	s.tokens[access] = g.user
	s.tokenLg = append(s.tokenLg, tr)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func pkceMatches(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

func userClaims(u User) map[string]any {
	c := map[string]any{"sub": u.Subject}
	if u.Email != "" {
		c["email"] = u.Email
		c["email_verified"] = u.EmailVerified
	}
	if u.Name != "" {
		c["name"] = u.Name
	}
	if u.Picture != "" {
		c["picture"] = u.Picture
	}
	if len(u.Groups) > 0 {
		c["groups"] = u.Groups
	}
	if u.SID != "" {
		c["sid"] = u.SID
	}
	for k, v := range u.Extra {
		c[k] = v
	}
	return c
}

func (s *Server) mintIDToken(g codeGrant, m Misbehaviour) (string, error) {
	now := time.Now()
	c := userClaims(g.user)
	c["iss"] = s.Issuer()
	c["aud"] = s.ClientID
	c["iat"] = now.Unix()
	c["exp"] = now.Add(time.Hour).Unix()
	if g.req.Nonce != "" {
		c["nonce"] = g.req.Nonce
	}
	if m.WrongAudience {
		c["aud"] = "someone-else"
	}
	if m.WrongIssuer {
		c["iss"] = s.Issuer() + "/evil"
	}
	if m.WrongNonce {
		c["nonce"] = "not-the-nonce"
	}
	if m.OmitNonce {
		delete(c, "nonce")
	}
	if m.Expired {
		c["iat"] = now.Add(-2 * time.Hour).Unix()
		c["exp"] = now.Add(-time.Hour).Unix()
	}
	if m.OmitEmailFromIDToken {
		delete(c, "email")
		delete(c, "email_verified")
	}
	for k, v := range m.Claims {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	switch {
	case m.AlgNone:
		return UnsignedJWT(c)
	case m.WrongKey:
		return signJWT(s.rogueKey, s.kid, c)
	default:
		return s.Sign(c)
	}
}

// BackChannelLogoutEvent is the events member of a logout token.
const BackChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// LogoutTokenOptions shapes a back-channel logout token (OIDC Back-Channel
// Logout 1.0). The zero value plus a Subject or SID is a valid token: iss,
// aud, iat now, exp in two minutes, a fresh jti, the logout event, typ
// logout+jwt, signed with the JWKS key.
type LogoutTokenOptions struct {
	Subject, SID string
	// JTI defaults to a random value; OmitJTI leaves it out.
	JTI     string
	OmitJTI bool
	// IssuedAt defaults to now; OmitExp leaves exp out.
	IssuedAt time.Time
	OmitExp  bool
	Expired  bool // exp a minute in the past
	// Nonce adds a nonce claim (forbidden in logout tokens).
	Nonce         string
	WrongAudience bool
	WrongIssuer   bool
	OmitEvents    bool
	// EventsArray sends events as an array of names instead of an object.
	EventsArray bool
	WrongKey    bool
	AlgNone     bool
	// Typ is the JOSE typ header ("" = logout+jwt; "-" = no typ).
	Typ string
	// Claims override or add claims last (nil value deletes).
	Claims map[string]any
}

// LogoutToken mints a back-channel logout token.
func (s *Server) LogoutToken(o LogoutTokenOptions) (string, error) {
	iat := o.IssuedAt
	if iat.IsZero() {
		iat = time.Now()
	}
	c := map[string]any{
		"iss":    s.Issuer(),
		"aud":    s.ClientID,
		"iat":    iat.Unix(),
		"exp":    iat.Add(2 * time.Minute).Unix(),
		"events": map[string]any{BackChannelLogoutEvent: map[string]any{}},
	}
	if o.Subject != "" {
		c["sub"] = o.Subject
	}
	if o.SID != "" {
		c["sid"] = o.SID
	}
	switch {
	case o.OmitJTI:
	case o.JTI != "":
		c["jti"] = o.JTI
	default:
		c["jti"] = randToken()
	}
	if o.OmitExp {
		delete(c, "exp")
	}
	if o.Expired {
		c["exp"] = time.Now().Add(-time.Minute).Unix()
	}
	if o.Nonce != "" {
		c["nonce"] = o.Nonce
	}
	if o.WrongAudience {
		c["aud"] = "someone-else"
	}
	if o.WrongIssuer {
		c["iss"] = s.Issuer() + "/evil"
	}
	if o.OmitEvents {
		delete(c, "events")
	}
	if o.EventsArray {
		c["events"] = []string{BackChannelLogoutEvent}
	}
	for k, v := range o.Claims {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	typ := o.Typ
	switch typ {
	case "":
		typ = "logout+jwt"
	case "-":
		typ = ""
	}
	switch {
	case o.AlgNone:
		return UnsignedJWT(c)
	case o.WrongKey:
		return signJWTTyp(s.rogueKey, s.kid, typ, c)
	default:
		return signJWTTyp(s.key, s.kid, typ, c)
	}
}

// Sign returns claims as an RS256 JWT signed with the IdP's JWKS key, for
// tests that need hand-built tokens (e.g. back-channel logout tokens).
func (s *Server) Sign(claims map[string]any) (string, error) {
	return signJWT(s.key, s.kid, claims)
}

func signJWT(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	return signJWTTyp(key, kid, "JWT", claims)
}

// signJWTTyp signs with the given typ header ("" omits it).
func signJWTTyp(key *rsa.PrivateKey, kid, typ string, claims map[string]any) (string, error) {
	hdr := map[string]string{"alg": "RS256", "kid": kid}
	if typ != "" {
		hdr["typ"] = typ
	}
	h, err := json.Marshal(hdr)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// UnsignedJWT returns claims as an alg:none JWT with an empty signature.
func UnsignedJWT(claims map[string]any) (string, error) {
	h, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + ".", nil
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	u, ok := s.tokens[tok]
	m := s.misbehave
	s.mu.Unlock()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid_token", http.StatusUnauthorized)
		return
	}
	c := userClaims(u)
	if m.UserinfoSubject != "" {
		c["sub"] = m.UserinfoSubject
	}
	writeJSON(w, http.StatusOK, c)
}

// endSessionHandler records RP-initiated logout and redirects to
// post_logout_redirect_uri (with state) when given.
func (s *Server) endSessionHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	s.endSession = append(s.endSession, q)
	s.mu.Unlock()
	dest := q.Get("post_logout_redirect_uri")
	if dest == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	u, err := url.Parse(dest)
	if err != nil {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if st := q.Get("state"); st != "" {
		v := u.Query()
		v.Set("state", st)
		u.RawQuery = v.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}
