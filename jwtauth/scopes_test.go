package jwtauth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/apierror"
	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/jwtauth"
)

func TestSocrateClaims_Scopes(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		scp   jwt.ClaimStrings
		want  []string
	}{
		{"scope string", "openid api  profile", nil, []string{"openid", "api", "profile"}},
		{"scp array", "", jwt.ClaimStrings{"read", "write"}, []string{"read", "write"}},
		{"scp single space-separated string", "", jwt.ClaimStrings{"read write"}, []string{"read", "write"}},
		{"union, scope first, deduplicated", "api read", jwt.ClaimStrings{"write", "read", "api x"}, []string{"api", "read", "write", "x"}},
		{"empty entries dropped", " api ", jwt.ClaimStrings{"", " "}, []string{"api"}},
		{"no claim", "", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := jwtauth.SocrateClaims{Scope: tt.scope, Scp: tt.scp}
			if got := c.Scopes(); !slices.Equal(got, tt.want) || (tt.want == nil && got != nil) {
				t.Errorf("Scopes() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The claims without scope marshal as before: the new fields are omitted.
func TestSocrateClaims_NoScopeMarshalsUnchanged(t *testing.T) {
	b, err := json.Marshal(jwtauth.SocrateClaims{Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"role":"user"}` {
		t.Errorf("marshal = %s", b)
	}
}

// serveScopes signs a token with the extra claims and serves it through
// Handler (and the optional guard); it returns the response and the scopes the
// handler saw.
func serveScopes(t *testing.T, opts []jwtauth.Option, extra jwt.MapClaims, guard []string) (*httptest.ResponseRecorder, []string) {
	t.Helper()
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	claims := jwt.MapClaims{"sub": "app:7", "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	m := jwtauth.New(srv.URL, "", testLogger(), opts...)
	var seen []string
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ctxutil.GetScopes(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	if guard != nil {
		h = m.ScopeGuard(guard...)(h)
	}
	h = m.Handler(h)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+signToken(t, key, "k1", claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w, seen
}

func TestHandler_ScopesInContext(t *testing.T) {
	tests := []struct {
		name  string
		extra jwt.MapClaims
		code  int
		want  []string
	}{
		{"scope string", jwt.MapClaims{"scope": "api swingdrift:worker"}, http.StatusOK, []string{"api", "swingdrift:worker"}},
		{"scp array", jwt.MapClaims{"scp": []string{"read", "write"}}, http.StatusOK, []string{"read", "write"}},
		{"scp single string", jwt.MapClaims{"scp": "read write"}, http.StatusOK, []string{"read", "write"}},
		{"both", jwt.MapClaims{"scope": "api read", "scp": []string{"read", "write"}}, http.StatusOK, []string{"api", "read", "write"}},
		{"none", nil, http.StatusOK, nil},
		{"scope not a string", jwt.MapClaims{"scope": 42}, http.StatusUnauthorized, nil},
		{"scp not strings", jwt.MapClaims{"scp": []any{"a", 1}}, http.StatusUnauthorized, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, seen := serveScopes(t, nil, tt.extra, nil)
			if w.Code != tt.code {
				t.Fatalf("code = %d, want %d", w.Code, tt.code)
			}
			if !slices.Equal(seen, tt.want) || (tt.want == nil && seen != nil) {
				t.Errorf("scopes = %q, want %q", seen, tt.want)
			}
		})
	}
}

const wantChallenge = `Bearer error="insufficient_scope", scope="swingdrift:worker api"`

func TestRequireScopes(t *testing.T) {
	req := []jwtauth.Option{jwtauth.RequireScopes("swingdrift:worker", "api", "", "api")}
	tests := []struct {
		name      string
		opts      []jwtauth.Option
		extra     jwt.MapClaims
		code      int
		challenge string
	}{
		{"all scopes", req, jwt.MapClaims{"scope": "api swingdrift:worker"}, http.StatusOK, ""},
		{"split across scope and scp", req, jwt.MapClaims{"scope": "api", "scp": []string{"swingdrift:worker"}}, http.StatusOK, ""},
		{"one missing", req, jwt.MapClaims{"scope": "api"}, http.StatusForbidden, wantChallenge},
		{"no scope claim", req, nil, http.StatusForbidden, wantChallenge},
		{"last option wins", []jwtauth.Option{jwtauth.RequireScopes("admin"), jwtauth.RequireScopes("api")}, jwt.MapClaims{"scope": "api"}, http.StatusOK, ""},
		{"invalid token is still 401", append([]jwtauth.Option{jwtauth.WithAudience("other")}, req...), jwt.MapClaims{"scope": "api"}, http.StatusUnauthorized, ""},
		// Fail closed: no usable required scope rejects every token.
		{"no scope given", []jwtauth.Option{jwtauth.RequireScopes()}, jwt.MapClaims{"scope": "api"}, http.StatusForbidden, `Bearer error="insufficient_scope"`},
		{"only empty scopes", []jwtauth.Option{jwtauth.RequireScopes("", "")}, jwt.MapClaims{"scope": "api"}, http.StatusForbidden, `Bearer error="insufficient_scope"`},
		{"space in a scope", []jwtauth.Option{jwtauth.RequireScopes("api read")}, jwt.MapClaims{"scope": "api read"}, http.StatusForbidden, `Bearer error="insufficient_scope"`},
		{"quote in a scope", []jwtauth.Option{jwtauth.RequireScopes("api", `x"`)}, jwt.MapClaims{"scope": `api x"`}, http.StatusForbidden, `Bearer error="insufficient_scope"`},
		{"backslash in a scope", []jwtauth.Option{jwtauth.RequireScopes(`a\b`)}, jwt.MapClaims{"scope": `a\b`}, http.StatusForbidden, `Bearer error="insufficient_scope"`},
		{"non-ASCII scope", []jwtauth.Option{jwtauth.RequireScopes("é")}, jwt.MapClaims{"scope": "é"}, http.StatusForbidden, `Bearer error="insufficient_scope"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, _ := serveScopes(t, tt.opts, tt.extra, nil)
			if w.Code != tt.code {
				t.Fatalf("code = %d, want %d (%s)", w.Code, tt.code, w.Body.String())
			}
			if got := w.Header().Get("WWW-Authenticate"); got != tt.challenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.challenge)
			}
		})
	}
}

// The 403 goes through the configured ErrorWriter, like the 401s.
func TestRequireScopes_ErrorWriter(t *testing.T) {
	extra := jwt.MapClaims{"scope": "api"}
	require := jwtauth.RequireScopes("swingdrift:worker")

	// Default: byte-for-byte the apierror envelope.
	want := httptest.NewRecorder()
	apierror.Forbidden("insufficient scope").WriteJSON(want)
	w, _ := serveScopes(t, []jwtauth.Option{require}, extra, nil)
	if w.Code != http.StatusForbidden || w.Body.String() != want.Body.String() || w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("default: %d %q, want %q", w.Code, w.Body.String(), want.Body.String())
	}

	// ProblemWriter: problem+json, code forbidden, and the challenge kept.
	w, _ = serveScopes(t, []jwtauth.Option{require, jwtauth.WithErrorWriter(apierror.ProblemWriter)}, extra, nil)
	var p apierror.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusForbidden || w.Header().Get("Content-Type") != "application/problem+json" ||
		p.Status != http.StatusForbidden || p.Code != "forbidden" || p.Detail != "insufficient scope" {
		t.Errorf("problem: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Bearer error="insufficient_scope", scope="swingdrift:worker"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
}

func TestNew_RequireScopesLogging(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	entry := logrus.NewEntry(l)

	_ = jwtauth.New("http://example/jwks.json", "https://issuer.example", entry,
		jwtauth.WithAudience("app"), jwtauth.RequireScopes("api"))
	if buf.Len() != 0 {
		t.Errorf("expected no log with a valid scope, got: %s", buf.String())
	}

	for _, scopes := range [][]string{nil, {""}, {"api", "bad scope"}} {
		buf.Reset()
		_ = jwtauth.New("http://example/jwks.json", "https://issuer.example", entry,
			jwtauth.WithAudience("app"), jwtauth.RequireScopes(scopes...))
		if !strings.Contains(buf.String(), "every token is rejected") {
			t.Errorf("RequireScopes(%q): expected the fail-closed error, got: %s", scopes, buf.String())
		}
	}
}

func TestScopeGuard(t *testing.T) {
	tests := []struct {
		name      string
		guard     []string
		extra     jwt.MapClaims
		code      int
		challenge string
	}{
		{"scope present", []string{"swingdrift:worker"}, jwt.MapClaims{"scope": "api swingdrift:worker"}, http.StatusOK, ""},
		{"scope in scp", []string{"swingdrift:worker"}, jwt.MapClaims{"scp": []string{"swingdrift:worker"}}, http.StatusOK, ""},
		{"scope missing", []string{"swingdrift:worker", "api"}, jwt.MapClaims{"scope": "api"}, http.StatusForbidden, wantChallenge},
		{"no scope claim", []string{"swingdrift:worker", "api"}, nil, http.StatusForbidden, wantChallenge},
		{"no scope given", []string{}, jwt.MapClaims{"scope": "api"}, http.StatusForbidden, `Bearer error="insufficient_scope"`},
		{"invalid scope given", []string{"api", "a\tb"}, jwt.MapClaims{"scope": "api"}, http.StatusForbidden, `Bearer error="insufficient_scope"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, _ := serveScopes(t, nil, tt.extra, tt.guard)
			if w.Code != tt.code {
				t.Fatalf("code = %d, want %d (%s)", w.Code, tt.code, w.Body.String())
			}
			if got := w.Header().Get("WWW-Authenticate"); got != tt.challenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.challenge)
			}
		})
	}
}

// Without Handler in front, the guard refuses with 401 — even when the context
// claims the scope — and writes through the configured ErrorWriter.
func TestScopeGuard_WithoutHandler(t *testing.T) {
	m := jwtauth.New("http://example/jwks.json", "", testLogger(), jwtauth.WithErrorWriter(apierror.ProblemWriter))
	h := m.ScopeGuard("api")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("handler reached") }))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := ctxutil.WithScopes(r.Context(), []string{"api"})
	ctx = ctxutil.WithRawJWT(ctx, "not-validated")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r.WithContext(ctx))

	var p apierror.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusUnauthorized || p.Code != "unauthorized" || p.Detail != "missing or invalid authorization header" {
		t.Errorf("got %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want none", got)
	}
}

func TestScopeGuard_Logging(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	m := jwtauth.New("http://example/jwks.json", "https://issuer.example", logrus.NewEntry(l), jwtauth.WithAudience("app"))

	_ = m.ScopeGuard("api")
	if buf.Len() != 0 {
		t.Errorf("expected no log with a valid scope, got: %s", buf.String())
	}
	_ = m.ScopeGuard("")
	if !strings.Contains(buf.String(), "every request is rejected") {
		t.Errorf("expected the fail-closed error, got: %s", buf.String())
	}
}
