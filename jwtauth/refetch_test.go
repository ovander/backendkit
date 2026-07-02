package jwtauth_test

// Tests for the JWKS-refetch DoS guard (audit H-1): single-flight coalescing,
// a refetch cooldown, and a negative cache for unknown kids — plus the
// exp-required check (audit M-2).

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/backendkit/jwtauth"
)

// jwksBody encodes the given kid→key pairs as a JWKS document.
func jwksBody(t *testing.T, entries map[string]*rsa.PrivateKey) []byte {
	t.Helper()
	keys := make([]map[string]string, 0, len(entries))
	for kid, key := range entries {
		pub := &key.PublicKey
		keys = append(keys, map[string]string{
			"kty": "RSA",
			"use": "sig",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	b, err := json.Marshal(map[string]interface{}{"keys": keys})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// countingJWKS is an httptest JWKS server that counts fetches and lets the test
// swap the served key set (to simulate key rotation) and add a response delay
// (to widen the single-flight window).
type countingJWKS struct {
	mu      sync.Mutex
	body    []byte
	fetches int64
	delay   time.Duration
	srv     *httptest.Server
}

func newCountingJWKS(t *testing.T, delay time.Duration, entries map[string]*rsa.PrivateKey) *countingJWKS {
	t.Helper()
	c := &countingJWKS{delay: delay, body: jwksBody(t, entries)}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&c.fetches, 1)
		if c.delay > 0 {
			time.Sleep(c.delay)
		}
		c.mu.Lock()
		body := c.body
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *countingJWKS) setKeys(t *testing.T, entries map[string]*rsa.PrivateKey) {
	b := jwksBody(t, entries)
	c.mu.Lock()
	c.body = b
	c.mu.Unlock()
}

func (c *countingJWKS) count() int64 { return atomic.LoadInt64(&c.fetches) }

// driveToken drives a single signed token through m and returns the status code.
func driveToken(m *jwtauth.Middleware, token string) int {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	m.Handler(okHandler()).ServeHTTP(w, r)
	return w.Code
}

func validClaims(sub string) jwtauth.SocrateClaims {
	return jwtauth.SocrateClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
}

// (a) Many concurrent requests bearing an unknown kid must coalesce into exactly
// one outbound JWKS fetch (single-flight).
func TestJWKSRefetch_SingleFlight_ConcurrentUnknownKid_OneFetch(t *testing.T) {
	key := generateTestKey(t)
	// A 50ms server delay widens the in-flight window so all goroutines join the
	// same flight rather than racing sequential ones.
	js := newCountingJWKS(t, 50*time.Millisecond, map[string]*rsa.PrivateKey{"k1": key})

	m := jwtauth.New(js.srv.URL, "", testLogger())

	const n = 32
	unknown := signToken(t, key, "unknown-kid", validClaims("42"))

	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			if code := driveToken(m, unknown); code != http.StatusUnauthorized {
				t.Errorf("unknown-kid token: expected 401, got %d", code)
			}
		}()
	}
	close(release)
	wg.Wait()

	if got := js.count(); got != 1 {
		t.Fatalf("expected exactly 1 JWKS fetch for %d concurrent unknown-kid requests, got %d", n, got)
	}
}

// (b) Rapid successive unknown-kid requests within the cooldown window must not
// trigger any further network fetch — even for kids never seen before (so this
// exercises the cooldown, not just the negative cache).
func TestJWKSRefetch_CooldownSuppressesRefetch(t *testing.T) {
	key := generateTestKey(t)
	js := newCountingJWKS(t, 0, map[string]*rsa.PrivateKey{"k1": key})

	// Default 15s cooldown; the whole test runs well within it.
	m := jwtauth.New(js.srv.URL, "", testLogger())

	// A valid token performs the one legitimate fetch and arms the cooldown.
	if code := driveToken(m, signToken(t, key, "k1", validClaims("42"))); code != http.StatusOK {
		t.Fatalf("valid token: expected 200, got %d", code)
	}
	if got := js.count(); got != 1 {
		t.Fatalf("expected 1 fetch after first valid token, got %d", got)
	}

	// Distinct, never-before-seen unknown kids: none are negative-cached, so only
	// the cooldown can be what suppresses the fetch.
	for i := 0; i < 8; i++ {
		tok := signToken(t, key, "cooldown-miss-"+string(rune('a'+i)), validClaims("42"))
		if code := driveToken(m, tok); code != http.StatusUnauthorized {
			t.Errorf("unknown-kid token: expected 401, got %d", code)
		}
	}
	if got := js.count(); got != 1 {
		t.Fatalf("expected no additional fetch within cooldown, got %d fetches", got)
	}
}

// (c) After the cooldown elapses, the first miss triggers exactly one refetch, so
// a genuinely-rotated (new) kid resolves and the token validates.
func TestJWKSRefetch_RotatedKidResolvesAfterCooldown(t *testing.T) {
	k1 := generateTestKey(t)
	k2 := generateTestKey(t)

	js := newCountingJWKS(t, 0, map[string]*rsa.PrivateKey{"k1": k1})

	// Short cooldown so the test doesn't have to wait 15s.
	m := jwtauth.New(js.srv.URL, "", testLogger(),
		jwtauth.WithMinRefetchInterval(20*time.Millisecond),
		jwtauth.WithNegativeCacheTTL(20*time.Millisecond),
	)

	// Prime with the original key.
	if code := driveToken(m, signToken(t, k1, "k1", validClaims("42"))); code != http.StatusOK {
		t.Fatalf("initial token: expected 200, got %d", code)
	}
	if got := js.count(); got != 1 {
		t.Fatalf("expected 1 fetch after priming, got %d", got)
	}

	// Rotate: the IdP now publishes a new signing key k2.
	js.setKeys(t, map[string]*rsa.PrivateKey{"k1": k1, "k2": k2})

	// Wait past the cooldown so the next miss is allowed to refetch.
	time.Sleep(80 * time.Millisecond)

	if code := driveToken(m, signToken(t, k2, "k2", validClaims("99"))); code != http.StatusOK {
		t.Fatalf("rotated-kid token: expected 200, got %d", code)
	}
	if got := js.count(); got != 2 {
		t.Fatalf("expected exactly one additional fetch for the rotated kid, got %d total", got)
	}
}

// (M-2) A validly-signed token with no exp claim must be rejected now that
// expiration is required.
func TestHandler_TokenWithoutExp_Rejected(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	m := jwtauth.New(srv.URL, "", testLogger())

	// No ExpiresAt set.
	noExp := jwtauth.SocrateClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "42"},
	}
	if code := driveToken(m, signToken(t, key, "k1", noExp)); code != http.StatusUnauthorized {
		t.Fatalf("token without exp: expected 401, got %d", code)
	}

	// Control: an otherwise-identical token WITH exp is accepted.
	if code := driveToken(m, signToken(t, key, "k1", validClaims("42"))); code != http.StatusOK {
		t.Fatalf("token with exp: expected 200, got %d", code)
	}
}
