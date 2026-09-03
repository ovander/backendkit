package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginBinding_BeginSetsLaxHttpOnlyCookie(t *testing.T) {
	lb := LoginBinding{Cookie: CookieConfig{Name: "admin_login", Secure: true}}
	rec := httptest.NewRecorder()
	nonce := lb.Begin(rec)
	if nonce == "" {
		t.Fatal("Begin returned an empty nonce")
	}
	cks := rec.Result().Cookies()
	if len(cks) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(cks))
	}
	ck := cks[0]
	if ck.Name != "__Host-admin_login" || ck.Value != nonce {
		t.Fatalf("cookie = %s=%s, want __Host-admin_login=<nonce>", ck.Name, ck.Value)
	}
	if !ck.HttpOnly || !ck.Secure || ck.Path != "/" || ck.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie flags wrong: %+v", ck)
	}
	if ck.MaxAge != int(DefaultLoginBindingTTL.Seconds()) {
		t.Fatalf("MaxAge = %d, want %d", ck.MaxAge, int(DefaultLoginBindingTTL.Seconds()))
	}
}

func TestLoginBinding_VerifyMatchesOnlyOriginatingBrowser(t *testing.T) {
	lb := LoginBinding{Cookie: CookieConfig{Name: "login"}}
	rec := httptest.NewRecorder()
	nonce := lb.Begin(rec)
	issued := rec.Result().Cookies()[0]

	verify := func(cookie *http.Cookie, want string) (bool, *httptest.ResponseRecorder) {
		req := httptest.NewRequest(http.MethodGet, "/bff/callback?code=x&state=y", nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rr := httptest.NewRecorder()
		return lb.Verify(rr, req, want), rr
	}

	// The browser that started the login finishes it.
	ok, rr := verify(issued, nonce)
	if !ok {
		t.Fatal("originating browser must verify")
	}
	cleared := false
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == "login" && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("Verify must clear the binding cookie (single use)")
	}

	// A different browser (no cookie) presenting a captured callback URL.
	if ok, _ := verify(nil, nonce); ok {
		t.Fatal("P3-15: a browser without the binding cookie must not complete someone else's login")
	}
	// A browser with a different login in flight.
	if ok, _ := verify(&http.Cookie{Name: "login", Value: RandomToken(32)}, nonce); ok {
		t.Fatal("mismatched nonce must not verify")
	}
	// Pending state without a nonce (legacy row) never verifies.
	if ok, _ := verify(issued, ""); ok {
		t.Fatal("empty expected nonce must never verify")
	}
}
