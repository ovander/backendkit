package jwtauth_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/jwtauth"
)

const (
	nsTenantClaim = "https://socrate/tenant_id"
	tenantA       = "00000000-0000-0000-0000-00000000000a"
	tenantB       = "00000000-0000-0000-0000-00000000000b"
)

// serveTenant signs claims (plus sub and exp) and returns the response code and
// the tenant the handler saw.
func serveTenant(t *testing.T, opts []jwtauth.Option, extra jwt.MapClaims) (int, uuid.UUID) {
	t.Helper()
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	claims := jwt.MapClaims{"sub": "42", "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	m := jwtauth.New(srv.URL, "", testLogger(), opts...)
	var seen uuid.UUID
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ctxutil.GetTenantID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+signToken(t, key, "k1", claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, seen
}

func TestHandler_TenantClaim(t *testing.T) {
	ns := []jwtauth.Option{jwtauth.WithTenantClaim(nsTenantClaim)}
	tests := []struct {
		name   string
		opts   []jwtauth.Option
		claims jwt.MapClaims
		code   int
		tenant string // "" = uuid.Nil
	}{
		{"default reads tenant_id", nil, jwt.MapClaims{"tenant_id": tenantA}, http.StatusOK, tenantA},
		{"default ignores a namespaced tenant claim", nil, jwt.MapClaims{nsTenantClaim: tenantA}, http.StatusOK, ""},
		{"named claim is read", ns, jwt.MapClaims{nsTenantClaim: tenantA}, http.StatusOK, tenantA},
		{"named claim wins over tenant_id", ns, jwt.MapClaims{nsTenantClaim: tenantA, "tenant_id": tenantB}, http.StatusOK, tenantA},
		{"plain tenant_id is ignored when another claim is named", ns, jwt.MapClaims{"tenant_id": tenantB}, http.StatusOK, ""},
		{"absent named claim sets no tenant", ns, nil, http.StatusOK, ""},
		{"surrounding spaces in the name are ignored", []jwtauth.Option{jwtauth.WithTenantClaim("  " + nsTenantClaim + " ")}, jwt.MapClaims{nsTenantClaim: tenantA}, http.StatusOK, tenantA},
		{"naming tenant_id equals the default", []jwtauth.Option{jwtauth.WithTenantClaim("tenant_id")}, jwt.MapClaims{"tenant_id": tenantA}, http.StatusOK, tenantA},
		{"non-UUID value is rejected", ns, jwt.MapClaims{nsTenantClaim: "acme"}, http.StatusUnauthorized, ""},
		{"number is rejected", ns, jwt.MapClaims{nsTenantClaim: 7}, http.StatusUnauthorized, ""},
		{"object is rejected", ns, jwt.MapClaims{nsTenantClaim: map[string]any{"id": tenantA}}, http.StatusUnauthorized, ""},
		{"null is rejected", ns, jwt.MapClaims{nsTenantClaim: nil}, http.StatusUnauthorized, ""},
		{"empty name fails closed", []jwtauth.Option{jwtauth.WithTenantClaim("")}, jwt.MapClaims{"tenant_id": tenantA}, http.StatusUnauthorized, ""},
		{"blank name fails closed", []jwtauth.Option{jwtauth.WithTenantClaim("   ")}, jwt.MapClaims{"tenant_id": tenantA}, http.StatusUnauthorized, ""},
		{"last option wins", []jwtauth.Option{jwtauth.WithTenantClaim(""), jwtauth.WithTenantClaim(nsTenantClaim)}, jwt.MapClaims{nsTenantClaim: tenantA}, http.StatusOK, tenantA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, seen := serveTenant(t, tt.opts, tt.claims)
			if code != tt.code {
				t.Fatalf("code = %d, want %d", code, tt.code)
			}
			want := uuid.Nil
			if tt.tenant != "" {
				want = uuid.MustParse(tt.tenant)
			}
			if code == http.StatusOK && seen != want {
				t.Errorf("tenant = %s, want %s", seen, want)
			}
		})
	}
}

// The revocation check sees the tenant the request context gets.
func TestHandler_TenantClaim_RevocationCheckSeesNamedTenant(t *testing.T) {
	var got string
	check := jwtauth.WithRevocationCheck(func(_ context.Context, c *jwtauth.SocrateClaims) error {
		got = c.TenantID
		return nil
	})
	code, _ := serveTenant(t, []jwtauth.Option{jwtauth.WithTenantClaim(nsTenantClaim), check},
		jwt.MapClaims{nsTenantClaim: tenantA, "tenant_id": tenantB})
	if code != http.StatusOK || got != tenantA {
		t.Errorf("code=%d, RevocationChecker saw TenantID %q, want 200 and %q", code, got, tenantA)
	}
}

// A forged token carrying the named claim is still refused: the claim is read
// only after the signature is verified.
func TestHandler_TenantClaim_UnsignedTokenRejected(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()
	m := jwtauth.New(srv.URL, "", testLogger(), jwtauth.WithTenantClaim(nsTenantClaim))

	other := generateTestKey(t)
	token := signToken(t, other, "k1", jwt.MapClaims{"sub": "42", "exp": time.Now().Add(time.Hour).Unix(), nsTenantClaim: tenantA})
	called := false
	h := m.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || called {
		t.Errorf("code=%d called=%v, want 401 and the handler not called", w.Code, called)
	}
}

func TestNew_WithTenantClaimLogging(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	entry := logrus.NewEntry(l)

	_ = jwtauth.New("http://example/jwks.json", "https://issuer.example", entry,
		jwtauth.WithAudience("app"), jwtauth.WithTenantClaim(nsTenantClaim))
	if buf.Len() != 0 {
		t.Errorf("expected no log with a named tenant claim, got: %s", buf.String())
	}

	buf.Reset()
	_ = jwtauth.New("http://example/jwks.json", "https://issuer.example", entry,
		jwtauth.WithAudience("app"), jwtauth.WithTenantClaim(" "))
	if !strings.Contains(buf.String(), "every token is rejected") {
		t.Errorf("expected the fail-closed error, got: %s", buf.String())
	}
}
