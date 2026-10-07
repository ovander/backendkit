package jwtauth_test

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/jwtauth"
)

// serveAudience signs a token with aud (omitted when nil) and returns the
// response code and the audiences the handler saw.
func serveAudience(t *testing.T, opts []jwtauth.Option, aud any) (int, []string) {
	t.Helper()
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	claims := jwt.MapClaims{"sub": "42", "exp": time.Now().Add(time.Hour).Unix()}
	if aud != nil {
		claims["aud"] = aud
	}
	m := jwtauth.New(srv.URL, "", testLogger(), opts...)
	var seen []string
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = ctxutil.GetAudiences(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+signToken(t, key, "k1", claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, seen
}

func TestHandler_Audiences(t *testing.T) {
	gw := []jwtauth.Option{jwtauth.WithAudiences("console", "portal")}
	tests := []struct {
		name string
		opts []jwtauth.Option
		aud  any
		code int
		want []string
	}{
		{"one configured audience", gw, []string{"console"}, http.StatusOK, []string{"console"}},
		{"single-string aud", gw, "portal", http.StatusOK, []string{"portal"}},
		{"others are left out", gw, []string{"other", "portal", "api"}, http.StatusOK, []string{"portal"}},
		{"two configured audiences are both kept", gw, []string{"portal", "console"}, http.StatusOK, []string{"portal", "console"}},
		{"duplicates are kept once", gw, []string{"console", "console"}, http.StatusOK, []string{"console"}},
		{"WithAudience", []jwtauth.Option{jwtauth.WithAudience("app")}, []string{"app", "api"}, http.StatusOK, []string{"app"}},
		{"no check: every aud value", nil, []string{"app", "api", "app", ""}, http.StatusOK, []string{"app", "api"}},
		{"no check, no aud: none", nil, nil, http.StatusOK, nil},
		{"no configured audience: refused", gw, []string{"other"}, http.StatusUnauthorized, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, seen := serveAudience(t, tt.opts, tt.aud)
			if code != tt.code {
				t.Fatalf("code = %d, want %d", code, tt.code)
			}
			if code == http.StatusOK && !slices.Equal(seen, tt.want) {
				t.Errorf("audiences = %q, want %q", seen, tt.want)
			}
		})
	}
}
