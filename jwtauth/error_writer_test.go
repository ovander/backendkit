package jwtauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/backendkit/apierror"
	"github.com/ovander/backendkit/jwtauth"
)

// Each rejection path, with and without an error writer.
func TestWithErrorWriter_EveryRejection(t *testing.T) {
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()
	valid := func(extra jwt.MapClaims) string {
		c := jwt.MapClaims{"sub": "42", "exp": time.Now().Add(time.Hour).Unix()}
		for k, v := range extra {
			c[k] = v
		}
		return signToken(t, key, "k1", c)
	}
	revoked := jwtauth.WithRevocationCheck(func(_ context.Context, _ *jwtauth.SocrateClaims) error { return errors.New("revoked") })
	cases := []struct {
		name   string
		auth   string
		opts   []jwtauth.Option
		detail string
	}{
		{"missing header", "", nil, "missing or invalid authorization header"},
		{"bad token", "Bearer not-a-jwt", nil, "invalid or expired token"},
		{"revoked", "Bearer " + valid(nil), []jwtauth.Option{revoked}, "token revoked"},
		{"invalid tenant", "Bearer " + valid(jwt.MapClaims{"tenant_id": "acme"}), nil, "invalid tenant_id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			serve := func(opts ...jwtauth.Option) *httptest.ResponseRecorder {
				m := jwtauth.New(srv.URL, "", testLogger(), opts...)
				h := m.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler reached") }))
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				if c.auth != "" {
					r.Header.Set("Authorization", c.auth)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}

			// Default: byte-for-byte the apierror envelope.
			want := httptest.NewRecorder()
			apierror.Unauthorized(c.detail).WriteJSON(want)
			got := serve(c.opts...)
			if got.Code != 401 || got.Body.String() != want.Body.String() || got.Header().Get("Content-Type") != "application/json" {
				t.Errorf("default body changed: %d %q, want %q", got.Code, got.Body.String(), want.Body.String())
			}

			// With ProblemWriter: problem+json with the same detail.
			got = serve(append(c.opts, jwtauth.WithErrorWriter(apierror.ProblemWriter))...)
			var p apierror.Problem
			if err := json.Unmarshal(got.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if got.Code != 401 || got.Header().Get("Content-Type") != "application/problem+json" ||
				p.Status != 401 || p.Detail != c.detail || p.Code != "unauthorized" {
				t.Errorf("problem: %d %q %s", got.Code, got.Header().Get("Content-Type"), got.Body.String())
			}

			// A nil writer is the default.
			got = serve(append(c.opts, jwtauth.WithErrorWriter(nil))...)
			if got.Body.String() != want.Body.String() {
				t.Errorf("nil writer changed the body: %q", got.Body.String())
			}
		})
	}
}
