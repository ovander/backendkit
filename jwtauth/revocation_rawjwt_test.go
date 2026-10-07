package jwtauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/jwtauth"
)

// serveRevocation runs one request with token through a middleware whose
// checker is check, and reports the response code and the raw JWT the handler saw.
func serveRevocation(t *testing.T, check jwtauth.RevocationChecker) (code int, token, handlerRaw string) {
	t.Helper()
	key := generateTestKey(t)
	srv := jwksServer(t, "k1", key)
	defer srv.Close()

	token = signToken(t, key, "k1", jwt.MapClaims{"sub": "42", "exp": time.Now().Add(time.Hour).Unix()})
	m := jwtauth.New(srv.URL, "", testLogger(), jwtauth.WithRevocationCheck(check))
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerRaw = ctxutil.GetRawJWT(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, token, handlerRaw
}

// A checker can read the raw bearer token, e.g. to introspect it at Socrate;
// the identity is not injected until the check has passed.
func TestHandler_RevocationCheck_SeesRawJWT(t *testing.T) {
	var checkerRaw, checkerSub string
	code, token, handlerRaw := serveRevocation(t, func(ctx context.Context, _ *jwtauth.SocrateClaims) error {
		checkerRaw, checkerSub = ctxutil.GetRawJWT(ctx), ctxutil.GetUserSub(ctx)
		return nil
	})
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if checkerRaw != token {
		t.Errorf("checker saw raw JWT %q, want the bearer token", checkerRaw)
	}
	if checkerSub != "" {
		t.Errorf("checker saw sub %q; identity must be injected only after the check", checkerSub)
	}
	if handlerRaw != token {
		t.Errorf("handler saw raw JWT %q, want the bearer token", handlerRaw)
	}
}

// A checker that refuses the token still rejects the request with 401, before
// the handler runs.
func TestHandler_RevocationCheck_RefusalWithRawJWT(t *testing.T) {
	called := false
	code, _, _ := serveRevocation(t, func(ctx context.Context, _ *jwtauth.SocrateClaims) error {
		if ctxutil.GetRawJWT(ctx) == "" {
			t.Error("checker saw no raw JWT")
		}
		called = true
		return errors.New("introspection: inactive")
	})
	if code != http.StatusUnauthorized || !called {
		t.Errorf("code=%d called=%v, want 401 and the checker called", code, called)
	}
}
