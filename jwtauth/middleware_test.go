package jwtauth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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
		TenantID: "00000000-0000-0000-0000-000000000001",
		UserID:   "00000000-0000-0000-0000-000000000002",
		Email:    "alice@example.com",
		Name:     "Alice",
		Role:     "editor",
		Plan:     "pro",
		RegisteredClaims: jwt.RegisteredClaims{
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
