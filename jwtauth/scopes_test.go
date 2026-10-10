package jwtauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/backendkit/apierror"
	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/jwtauth"
)

type scopeResult struct {
	code      int
	scopes    []string // ctxutil.GetScopes seen by the handler
	sub       string   // ctxutil.GetUserSub seen by the handler
	checked   []string // SocrateClaims.Scopes seen by a RevocationChecker
	header    http.Header
	body      string
	reachedUp bool
}

// serveScopes signs a token carrying extra claims and serves it through a
// Middleware built with opts.
func serveScopes(t *testing.T, opts []jwtauth.Option, extra jwt.MapClaims) scopeResult {
	t.Helper()
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	claims := jwt.MapClaims{"sub": "app:7", "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	var res scopeResult
	opts = append([]jwtauth.Option{jwtauth.WithRevocationCheck(func(_ context.Context, c *jwtauth.SocrateClaims) error {
		res.checked = c.Scopes()
		return nil
	})}, opts...)
	m := jwtauth.New(srv.URL, "", testLogger(), opts...)
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res.reachedUp = true
		res.scopes = ctxutil.GetScopes(r.Context())
		res.sub = ctxutil.GetUserSub(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+signToken(t, key, "k1", claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	res.code, res.header, res.body = w.Code, w.Header(), w.Body.String()
	return res
}

func TestScopes_ClaimShapes(t *testing.T) {
	tests := []struct {
		name  string
		extra jwt.MapClaims
		want  []string
	}{
		{"scope string (Socrate)", jwt.MapClaims{"scope": "openid  api swingdrift:worker"}, []string{"openid", "api", "swingdrift:worker"}},
		{"scp array", jwt.MapClaims{"scp": []string{"read", "write"}}, []string{"read", "write"}},
		{"scp string", jwt.MapClaims{"scp": "read write"}, []string{"read", "write"}},
		{"union, scope first, no duplicates", jwt.MapClaims{"scope": "a b", "scp": []string{"b", "c", ""}}, []string{"a", "b", "c"}},
		{"neither claim", nil, nil},
		{"empty scope", jwt.MapClaims{"scope": "  "}, nil},
		{"null claims", jwt.MapClaims{"scope": nil, "scp": nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := serveScopes(t, nil, tt.extra)
			if res.code != http.StatusOK {
				t.Fatalf("code = %d: %s", res.code, res.body)
			}
			if !slices.Equal(res.scopes, tt.want) || !slices.Equal(res.checked, tt.want) {
				t.Errorf("context scopes %q, claims scopes %q, want %q", res.scopes, res.checked, tt.want)
			}
		})
	}
}

// Without RequireScopes, a malformed scope claim changes nothing for callers:
// the token validates as before and simply carries no scopes.
func TestScopes_MalformedClaimIgnoredWithoutRequirement(t *testing.T) {
	for name, extra := range map[string]jwt.MapClaims{
		"scope number":   {"scope": 42},
		"scope array":    {"scope": []string{"a"}},
		"scp object":     {"scp": map[string]any{"a": true}},
		"scp mixed list": {"scp": []any{"a", 1}},
	} {
		t.Run(name, func(t *testing.T) {
			res := serveScopes(t, nil, extra)
			if res.code != http.StatusOK || res.scopes != nil || res.sub != "app:7" {
				t.Errorf("code %d, scopes %q, sub %q", res.code, res.scopes, res.sub)
			}
		})
	}
}

func TestRequireScopes(t *testing.T) {
	worker := []jwtauth.Option{jwtauth.RequireScopes("swingdrift:worker")}
	two := []jwtauth.Option{jwtauth.RequireScopes("a", "b", "a", " ")}
	tests := []struct {
		name  string
		opts  []jwtauth.Option
		extra jwt.MapClaims
		code  int
	}{
		{"carries the scope", worker, jwt.MapClaims{"scope": "api swingdrift:worker"}, http.StatusOK},
		{"carries it in scp", worker, jwt.MapClaims{"scp": []string{"swingdrift:worker"}}, http.StatusOK},
		{"lacks it", worker, jwt.MapClaims{"scope": "api"}, http.StatusForbidden},
		{"no scope claim", worker, nil, http.StatusForbidden},
		{"prefix is not a match", worker, jwt.MapClaims{"scope": "swingdrift:worker2 swingdrift"}, http.StatusForbidden},
		{"malformed scp", worker, jwt.MapClaims{"scope": "swingdrift:worker", "scp": 1}, http.StatusForbidden},
		{"every required scope", two, jwt.MapClaims{"scope": "b", "scp": "a"}, http.StatusOK},
		{"one of two", two, jwt.MapClaims{"scope": "a"}, http.StatusForbidden},
		{"no scope given: fail closed", []jwtauth.Option{jwtauth.RequireScopes()}, jwt.MapClaims{"scope": "a"}, http.StatusForbidden},
		{"only blanks given: fail closed", []jwtauth.Option{jwtauth.RequireScopes("", "  ")}, jwt.MapClaims{"scope": "a"}, http.StatusForbidden},
		{"last option wins", []jwtauth.Option{jwtauth.RequireScopes("x"), jwtauth.RequireScopes("a")}, jwt.MapClaims{"scope": "a"}, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := serveScopes(t, tt.opts, tt.extra)
			if res.code != tt.code {
				t.Fatalf("code = %d, want %d: %s", res.code, tt.code, res.body)
			}
			if tt.code == http.StatusForbidden {
				if res.reachedUp {
					t.Error("a rejected request reached the handler")
				}
				if h := res.header.Get("WWW-Authenticate"); !strings.HasPrefix(h, `Bearer error="insufficient_scope"`) {
					t.Errorf("WWW-Authenticate = %q", h)
				}
				var env struct {
					Error struct{ Code string } `json:"error"`
				}
				if err := json.Unmarshal([]byte(res.body), &env); err != nil || env.Error.Code != "forbidden" {
					t.Errorf("body = %s", res.body)
				}
			}
		})
	}
}

func TestRequireScopes_ProblemWriter(t *testing.T) {
	res := serveScopes(t, []jwtauth.Option{
		jwtauth.RequireScopes("swingdrift:worker"),
		jwtauth.WithErrorWriter(apierror.ProblemWriter),
	}, jwt.MapClaims{"scope": "api"})
	if res.code != http.StatusForbidden || res.header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("code %d, content type %q", res.code, res.header.Get("Content-Type"))
	}
	var p apierror.Problem
	if err := json.Unmarshal([]byte(res.body), &p); err != nil || p.Code != "forbidden" || p.Status != http.StatusForbidden {
		t.Errorf("problem = %+v (%v)", p, err)
	}
	if h := res.header.Get("WWW-Authenticate"); h != `Bearer error="insufficient_scope", scope="swingdrift:worker"` {
		t.Errorf("WWW-Authenticate = %q", h)
	}
}

func TestSocrateClaims_ScopesOutsideValidation(t *testing.T) {
	var nilClaims *jwtauth.SocrateClaims
	if nilClaims.Scopes() != nil || (&jwtauth.SocrateClaims{}).Scopes() != nil {
		t.Error("claims not produced by validation must have no scopes")
	}
}
