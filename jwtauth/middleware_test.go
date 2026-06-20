package jwtauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/jwtauth"
)

// generateTestKey creates a fresh 2048-bit RSA key pair.
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

// jwksServer starts an httptest server that serves a single RSA key as JWKS.
func jwksServer(t *testing.T, kid string, key *rsa.PrivateKey) *httptest.Server {
	t.Helper()
	pub := &key.PublicKey

	nB64 := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	body, _ := json.Marshal(map[string]interface{}{
		"keys": []map[string]string{
			{"kty": "RSA", "use": "sig", "kid": kid, "n": nB64, "e": eB64},
		},
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
}

// signToken signs a JWT with the given key and kid.
func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func testLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(devNull{})
	return logrus.NewEntry(l)
}

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

func TestHandler_ValidToken_PopulatesContext(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger())

	claims := jwtauth.SocrateClaims{
		// TenantID requires custom server config; still accepted when present.
		TenantID: "00000000-0000-0000-0000-000000000001",
		// Socrate sets sub to a numeric string; the middleware derives a UUID from it.
		Email: "alice@example.com",
		Name:  "Alice",
		Role:  "editor",
		Plan:  "pro",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := signToken(t, key, "k1", claims)

	var capturedRole, capturedPlan, capturedEmail string
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRole = ctxutil.GetUserRole(r.Context())
		capturedPlan = ctxutil.GetUserPlan(r.Context())
		capturedEmail = ctxutil.GetUserEmail(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if capturedRole != "editor" {
		t.Errorf("role = %q, want editor", capturedRole)
	}
	if capturedPlan != "pro" {
		t.Errorf("plan = %q, want pro", capturedPlan)
	}
	if capturedEmail != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", capturedEmail)
	}
}

func TestHandler_MissingAuthHeader_Returns401(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger())
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandler_TamperedToken_Returns401(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger())
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	claims := jwtauth.SocrateClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := signToken(t, key, "k1", claims) + "tampered"

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ─── Audience validation (F-1 / INV-2) ──────────────────────────────────────

// okHandler is a 200 handler used to assert that a request was allowed through.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// serveWithToken signs claims, drives one request through m, and returns the
// recorded status code.
func serveWithToken(t *testing.T, m *jwtauth.Middleware, key *rsa.PrivateKey, claims jwtauth.SocrateClaims) int {
	t.Helper()
	token := signToken(t, key, "k1", claims)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	m.Handler(okHandler()).ServeHTTP(w, r)
	return w.Code
}

func claimsWithAudience(aud ...string) jwtauth.SocrateClaims {
	rc := jwt.RegisteredClaims{
		Subject:   "42",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	if len(aud) > 0 {
		rc.Audience = jwt.ClaimStrings(aud)
	}
	return jwtauth.SocrateClaims{RegisteredClaims: rc}
}

func TestHandler_CorrectAudience_Allowed(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger(), jwtauth.WithAudience("app-123"))

	if code := serveWithToken(t, m, key, claimsWithAudience("app-123")); code != http.StatusOK {
		t.Errorf("expected 200 for matching audience, got %d", code)
	}
}

func TestHandler_WrongAudience_Returns401(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger(), jwtauth.WithAudience("app-123"))

	if code := serveWithToken(t, m, key, claimsWithAudience("other-app")); code != http.StatusUnauthorized {
		t.Errorf("expected 401 for mismatched audience, got %d", code)
	}
}

func TestHandler_MissingAudienceWhenRequired_Returns401(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger(), jwtauth.WithAudience("app-123"))

	// Token carries no aud claim; with an expected audience configured it must be rejected.
	if code := serveWithToken(t, m, key, claimsWithAudience()); code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing audience, got %d", code)
	}
}

// TestHandler_NoAudienceConfigured_IgnoresAud is the backward-compatibility
// regression test: when WithAudience is not supplied, the aud claim is not
// checked and a token with any (or no) audience is accepted.
func TestHandler_NoAudienceConfigured_IgnoresAud(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger()) // no WithAudience

	if code := serveWithToken(t, m, key, claimsWithAudience("some-unrelated-app")); code != http.StatusOK {
		t.Errorf("expected 200 when audience validation is disabled, got %d", code)
	}
	if code := serveWithToken(t, m, key, claimsWithAudience()); code != http.StatusOK {
		t.Errorf("expected 200 for no-aud token when validation disabled, got %d", code)
	}
}

// ─── Revocation check (F-2 / INV-3) ─────────────────────────────────────────

func claimsWithVersion(sub string, version int) jwtauth.SocrateClaims {
	return jwtauth.SocrateClaims{
		TokenVersion: version,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
}

func TestHandler_RevocationCheck_AllowsLiveToken(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	var gotSub string
	var gotVersion int
	check := func(_ context.Context, c *jwtauth.SocrateClaims) error {
		gotSub, gotVersion = c.Subject, c.TokenVersion
		return nil // live
	}
	m := jwtauth.New(srv.URL, "", testLogger(), jwtauth.WithRevocationCheck(check))

	if code := serveWithToken(t, m, key, claimsWithVersion("42", 7)); code != http.StatusOK {
		t.Errorf("expected 200 for a live token, got %d", code)
	}
	if gotSub != "42" || gotVersion != 7 {
		t.Errorf("checker received sub=%q version=%d, want \"42\"/7", gotSub, gotVersion)
	}
}

func TestHandler_RevocationCheck_RejectsRevokedToken(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	check := func(_ context.Context, _ *jwtauth.SocrateClaims) error {
		return errors.New("token_version superseded")
	}
	m := jwtauth.New(srv.URL, "", testLogger(), jwtauth.WithRevocationCheck(check))

	// A 401 (rather than the handler's 200) proves the request was rejected
	// before reaching the handler.
	if code := serveWithToken(t, m, key, claimsWithVersion("42", 1)); code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a revoked token, got %d", code)
	}
}

// TestHandler_NoRevocationCheck_AllowsToken is the backward-compatibility
// regression test: with no checker configured the token is accepted as before.
func TestHandler_NoRevocationCheck_AllowsToken(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger()) // no WithRevocationCheck

	if code := serveWithToken(t, m, key, claimsWithVersion("42", 1)); code != http.StatusOK {
		t.Errorf("expected 200 when revocation checking is disabled, got %d", code)
	}
}

// ─── Minimum RSA key size (F-10 / INV-13) ───────────────────────────────────

func TestHandler_RejectsUndersizedRSAKey(t *testing.T) {
	// 1024-bit key: below the 2048-bit minimum. Its JWKS entry must be discarded,
	// leaving no usable signing key, so a token signed with it is rejected.
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate 1024-bit key: %v", err)
	}
	srv := jwksServer(t, "k1", weak)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger())

	if code := serveWithToken(t, m, weak, claimsWithVersion("42", 0)); code != http.StatusUnauthorized {
		t.Errorf("expected 401 for a token signed with a 1024-bit key, got %d", code)
	}
}
