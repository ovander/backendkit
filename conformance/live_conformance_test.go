//go:build conformance

// Live checks: every fixture against what a running Socrate really returns.
// Run with scripts/conformance-local.sh, or see the package documentation for
// the environment they read. Without it they fail: the conformance build tag
// is the opt-in.

package conformance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const userScope = "openid profile email"

type liveClient struct{ id, secret string }

type live struct {
	issuer, redirect, audience, tenant, password string
	plain, dual, claims                          liveClient
	keys                                         map[string]*rsa.PublicKey
}

func liveEnv(t *testing.T) *live {
	t.Helper()
	get := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s is not set: the conformance tests need a running Socrate (scripts/conformance-local.sh)", name)
		}
		return v
	}
	l := &live{
		issuer:   strings.TrimSuffix(get("SOCRATE_ISSUER"), "/"),
		redirect: get("SOCRATE_REDIRECT_URI"),
		audience: get("SOCRATE_AUDIENCE"),
		tenant:   get("SOCRATE_TENANT_ID"),
		password: get("SOCRATE_USER_PASSWORD"),
		plain:    liveClient{get("SOCRATE_PLAIN_CLIENT_ID"), get("SOCRATE_PLAIN_CLIENT_SECRET")},
		dual:     liveClient{get("SOCRATE_DUAL_CLIENT_ID"), get("SOCRATE_DUAL_CLIENT_SECRET")},
		claims:   liveClient{get("SOCRATE_CLAIMS_CLIENT_ID"), get("SOCRATE_CLAIMS_CLIENT_SECRET")},
		keys:     map[string]*rsa.PublicKey{},
	}
	jwks := l.getJSON(t, l.issuer+"/.well-known/jwks.json")
	keys, _ := jwks["keys"].([]any)
	for _, k := range keys {
		jwk, _ := k.(map[string]any)
		n, err1 := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["n"]))
		e, err2 := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["e"]))
		if err1 != nil || err2 != nil {
			t.Fatalf("JWKS key %v: undecodable n or e", jwk["kid"])
		}
		l.keys[fmt.Sprint(jwk["kid"])] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(l.keys) == 0 {
		t.Fatal("the live JWKS has no key")
	}
	return l
}

func email(name string) string { return name + "@example.test" }

func (l *live) getJSON(t *testing.T, u string) map[string]any {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	return decodeBody(t, resp, http.StatusOK)
}

func decodeBody(t *testing.T, resp *http.Response, want int) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: HTTP %d, want %d: %.300s", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, b)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s: not a JSON object: %v", resp.Request.URL.Path, err)
	}
	return doc
}

// verify checks tok's RS256 signature against the live JWKS and returns its
// header and claims.
func (l *live) verify(t *testing.T, tok string) (map[string]any, map[string]any) {
	t.Helper()
	parsed, err := jwt.Parse(tok, func(tk *jwt.Token) (any, error) {
		k, ok := l.keys[fmt.Sprint(tk.Header["kid"])]
		if !ok {
			return nil, fmt.Errorf("kid %v is not in the JWKS", tk.Header["kid"])
		}
		return k, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(l.issuer))
	if err != nil {
		t.Fatalf("token does not verify against the live JWKS: %v", err)
	}
	if err := Match("jose_header", parsed.Header, Params{}); err != nil {
		t.Errorf("JOSE header: %v", err)
	}
	return parsed.Header, map[string]any(parsed.Claims.(jwt.MapClaims))
}

func check(t *testing.T, name string, got any, p Params) {
	t.Helper()
	if err := Match(name, got, p); err != nil {
		t.Errorf("live %v", err)
	}
}

// signIn runs the hosted Authorization Code + PKCE flow — sign-in form,
// consent, callback — and returns the token response.
func (l *live) signIn(t *testing.T, c liveClient, user, nonce, mfaCode string) map[string]any {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	verifier := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	sum := sha256.Sum256([]byte(verifier))
	state := uuid.NewString()
	q := url.Values{
		"response_type": {"code"}, "client_id": {c.id}, "redirect_uri": {l.redirect},
		"scope": {userScope}, "state": {state}, "nonce": {nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}
	page := htmlPage(t, hc, http.MethodGet, l.issuer+"/oauth/authorize?"+q.Encode(), nil)
	form := hiddenInputs(page)
	form.Set("email", email(user))
	form.Set("password", l.password)
	if mfaCode != "" {
		form.Set("mfa_code", mfaCode)
	}
	page = htmlPage(t, hc, http.MethodPost, l.issuer+"/oauth/authorize", form)
	form = hiddenInputs(page)
	if form.Get("consent_token") == "" {
		t.Fatalf("sign-in of %s did not reach the consent page", user)
	}
	form.Set("authorized", "true")
	page = htmlPage(t, hc, http.MethodPost, l.issuer+"/oauth/authorize", form)
	m := regexp.MustCompile(`http-equiv="refresh" content="0;url=([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("consent did not redirect to the client")
	}
	cb, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatalf("callback URL: %v", err)
	}
	if got := cb.Query().Get("state"); got != state {
		t.Fatalf("callback state = %q, want %q", got, state)
	}
	if got := cb.Query().Get("iss"); got != l.issuer {
		t.Errorf("callback iss = %q, want %q (RFC 9207)", got, l.issuer)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("callback has no code (error=%q)", cb.Query().Get("error"))
	}
	return l.token(t, c, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {l.redirect}, "code_verifier": {verifier},
	}, "")
}

func htmlPage(t *testing.T, hc *http.Client, method, u string, form url.Values) string {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, u, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: HTTP %d", method, req.URL.Path, resp.StatusCode)
	}
	if m := regexp.MustCompile(`(?s)class="alert alert-error">\s*(.*?)\s*</div>`).FindStringSubmatch(string(b)); m != nil {
		t.Fatalf("%s %s: the page shows an error: %s", method, req.URL.Path, html.UnescapeString(m[1]))
	}
	return string(b)
}

var reHidden = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)

func hiddenInputs(page string) url.Values {
	v := url.Values{}
	for _, m := range reHidden.FindAllStringSubmatch(page, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// token posts a grant to /oauth/token with client_secret_basic, and a DPoP
// proof when one is given.
func (l *live) token(t *testing.T, c liveClient, form url.Values, dpop string) map[string]any {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, l.issuer+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.id), url.QueryEscape(c.secret))
	if dpop != "" {
		req.Header.Set("DPoP", dpop)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	return decodeBody(t, resp, http.StatusOK)
}

func (l *live) introspect(t *testing.T, c liveClient, tok string) map[string]any {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, l.issuer+"/oauth/introspect",
		strings.NewReader(url.Values{"token": {tok}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.id, c.secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	return decodeBody(t, resp, http.StatusOK)
}

func (l *live) bearerJSON(t *testing.T, method, path, tok string, body any) map[string]any {
	t.Helper()
	return l.bearerDo(t, method, path, tok, body, http.StatusOK)
}

// bearerDo sends a JSON request with an optional bearer and decodes the
// answer, which must have status want (204: no body, nil).
func (l *live) bearerDo(t *testing.T, method, path, tok string, body any, want int) map[string]any {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, l.issuer+path, r)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if want == http.StatusNoContent {
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s %s: HTTP %d, want %d", method, path, resp.StatusCode, want)
		}
		return nil
	}
	return decodeBody(t, resp, want)
}

func asString(v any) string { s, _ := v.(string); return s }

func TestConformanceDiscoveryAndJWKS(t *testing.T) {
	l := liveEnv(t)
	// The suite's Socrate runs DPOP_MODE=observe; TestDiscovery proves that
	// discovery (DPoP off) is discovery_dpop minus its DPoP key.
	check(t, "discovery_dpop", l.getJSON(t, l.issuer+"/.well-known/openid-configuration"), Params{Issuer: l.issuer})
	check(t, "jwks", l.getJSON(t, l.issuer+"/.well-known/jwks.json"), Params{})
}

func TestConformanceAuthorizationCodeAndRefresh(t *testing.T) {
	l := liveEnv(t)
	const user = "conf-fixtures"
	p := Params{Issuer: l.issuer, ClientID: l.plain.id, Role: "user", Scope: userScope,
		Email: email(user), Name: "Conformance " + user, Nonce: "nonce-" + uuid.NewString()}

	resp := l.signIn(t, l.plain, user, p.Nonce, "")
	check(t, "token_response/authorization_code", resp, p)
	_, access := l.verify(t, asString(resp["access_token"]))
	check(t, "access/authorization_code", access, p)
	p.Subject = asString(access["sub"])
	_, id := l.verify(t, asString(resp["id_token"]))
	check(t, "id_token/authorization_code", id, p)
	if id["at_hash"] != atHash(asString(resp["access_token"])) {
		t.Errorf("id_token at_hash is not the access token's")
	}
	_, refresh := l.verify(t, asString(resp["refresh_token"]))
	check(t, "refresh_token/authorization_code", refresh, p)

	check(t, "userinfo", l.bearerJSON(t, http.MethodGet, "/oauth/userinfo", asString(resp["access_token"]), nil), p)
	check(t, "introspection/access", l.introspect(t, l.plain, asString(resp["access_token"])), p)

	refreshed := l.token(t, l.plain, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {asString(resp["refresh_token"])}}, "")
	pr := p
	pr.Nonce = ""
	check(t, "token_response/refresh", refreshed, pr)
	_, rAccess := l.verify(t, asString(refreshed["access_token"]))
	check(t, "access/refresh", rAccess, pr)
	if rAccess["auth_time"] != access["auth_time"] {
		t.Errorf("refresh changed auth_time: %v → %v (a refresh is not a sign-in)", access["auth_time"], rAccess["auth_time"])
	}
	_, rID := l.verify(t, asString(refreshed["id_token"]))
	check(t, "id_token/refresh", rID, pr)
	if refreshed["refresh_token"] == resp["refresh_token"] {
		t.Error("the refresh token was not rotated")
	}

	// The spent refresh token is inactive.
	check(t, "introspection/inactive", l.introspect(t, l.plain, asString(resp["refresh_token"])), Params{})
}

// totp is RFC 6238 with Socrate's parameters: SHA-1, 6 digits, 30 s steps.
func totp(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("TOTP secret: %v", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

func TestConformanceMFA(t *testing.T) {
	l := liveEnv(t)
	const user = "conf-mfa"
	// Enrol the user in TOTP through the self-service API (a fresh database
	// per run: the seeded user has no second factor yet).
	login := l.bearerJSON(t, http.MethodPost, "/api/auth/login", "", map[string]string{
		"email": email(user), "password": l.password, "app_client_id": l.plain.id})
	at := asString(login["access_token"])
	if status := l.bearerJSON(t, http.MethodGet, "/api/profile/mfa", at, nil); status["enabled"] == true {
		t.Fatalf("%s already has a second factor: seed a fresh database (scripts/conformance-local.sh does)", user)
	}
	enrol := l.bearerJSON(t, http.MethodPost, "/api/profile/mfa/enroll", at, map[string]string{})
	secret := asString(enrol["secret"])
	if secret == "" {
		t.Fatal("MFA enrolment returned no secret")
	}
	l.bearerDo(t, http.MethodPost, "/api/profile/mfa/confirm", at, map[string]string{"code": totp(t, secret, time.Now())}, http.StatusNoContent)

	p := Params{Issuer: l.issuer, ClientID: l.plain.id, Role: "user", Scope: userScope,
		Email: email(user), Name: "Conformance " + user, Nonce: "nonce-" + uuid.NewString()}
	resp := l.signIn(t, l.plain, user, p.Nonce, totp(t, secret, time.Now().Add(30*time.Second)))
	_, access := l.verify(t, asString(resp["access_token"]))
	check(t, "access/authorization_code_mfa", access, p)
	_, id := l.verify(t, asString(resp["id_token"]))
	check(t, "id_token/authorization_code_mfa", id, p)
}

func TestConformanceClientCredentials(t *testing.T) {
	l := liveEnv(t)
	p := Params{Issuer: l.issuer, ClientID: l.plain.id}
	resp := l.token(t, l.plain, url.Values{"grant_type": {"client_credentials"}}, "")
	check(t, "token_response/client_credentials", resp, p)
	_, access := l.verify(t, asString(resp["access_token"]))
	check(t, "access/client_credentials", access, p)
	check(t, "introspection/client_credentials", l.introspect(t, l.plain, asString(resp["access_token"])), p)
}

func TestConformanceAudienceDual(t *testing.T) {
	l := liveEnv(t)
	const user = "conf-fixtures"
	p := Params{Issuer: l.issuer, ClientID: l.dual.id, Audiences: []string{l.audience}, Role: "user", Scope: userScope}
	resp := l.signIn(t, l.dual, user, "n-"+uuid.NewString(), "")
	_, access := l.verify(t, asString(resp["access_token"]))
	check(t, "access/audience_dual", access, p)

	cc := l.token(t, l.dual, url.Values{"grant_type": {"client_credentials"}}, "")
	_, ccAccess := l.verify(t, asString(cc["access_token"]))
	check(t, "access/client_credentials_audience_dual", ccAccess, Params{Issuer: l.issuer, ClientID: l.dual.id, Audiences: []string{l.audience}})
}

func TestConformanceCustomClaims(t *testing.T) {
	l := liveEnv(t)
	const user = "conf-fixtures"
	p := Params{Issuer: l.issuer, ClientID: l.claims.id, Role: "user", Scope: userScope,
		Email: email(user), Name: "Conformance " + user, Nonce: "nonce-" + uuid.NewString(),
		TenantID: l.tenant, Attributes: map[string]any{"department": "research"}}
	resp := l.signIn(t, l.claims, user, p.Nonce, "")
	_, access := l.verify(t, asString(resp["access_token"]))
	check(t, "access/custom_claims", access, p)
	if access[DefaultClaimsNamespace+"client"] != l.claims.id {
		t.Errorf("app.client_id mapping = %v, want %s", access[DefaultClaimsNamespace+"client"], l.claims.id)
	}
	_, id := l.verify(t, asString(resp["id_token"]))
	check(t, "id_token/custom_claims", id, p)

	cc := l.token(t, l.claims, url.Values{"grant_type": {"client_credentials"}}, "")
	_, ccAccess := l.verify(t, asString(cc["access_token"]))
	check(t, "access/client_credentials_custom_claims", ccAccess, Params{Issuer: l.issuer, ClientID: l.claims.id, TenantID: l.tenant})
}

// dpopProof is an RFC 9449 proof for POST htu, and the key's RFC 7638 thumbprint.
func dpopProof(t *testing.T, key *ecdsa.PrivateKey, htu string) (string, string) {
	t.Helper()
	point, err := key.PublicKey.Bytes() // 0x04 || X || Y, 32 bytes each
	if err != nil || len(point) != 65 {
		t.Fatalf("DPoP public key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(point[1:33])
	y := base64.RawURLEncoding.EncodeToString(point[33:])
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y)
	sum := sha256.Sum256([]byte(canonical))
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"jti": uuid.NewString(), "htm": http.MethodPost, "htu": htu, "iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": x, "y": y}
	proof, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	return proof, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestConformanceClientCredentialsDPoP(t *testing.T) {
	l := liveEnv(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, jkt := dpopProof(t, key, l.issuer+"/oauth/token")
	resp := l.token(t, l.plain, url.Values{"grant_type": {"client_credentials"}}, proof)
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer (bound or not)", resp["token_type"])
	}
	_, access := l.verify(t, asString(resp["access_token"]))
	check(t, "access/client_credentials_dpop", access, Params{Issuer: l.issuer, ClientID: l.plain.id, JKT: jkt})
}
