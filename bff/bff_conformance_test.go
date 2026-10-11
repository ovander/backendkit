//go:build conformance

// Live conformance: a minimal BFF built from this package runs the whole
// session lifecycle against a running Socrate — authorize (hosted sign-in and
// consent), callback and code exchange, proxying with the session's bearer,
// refresh, logout. Run with scripts/conformance-local.sh (see package
// conformance for the environment). Without that environment the tests fail:
// the build tag is the opt-in.

package bff_test

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ovander/backendkit/bff"
	"github.com/ovander/backendkit/socrate"
)

const liveUser = "conf-bff@example.test"

func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: the conformance tests need a running Socrate (scripts/conformance-local.sh)", name)
	}
	return v
}

// liveBFF is the smallest BFF this package supports: /login, /callback,
// /logout and the session→bearer proxy for /oauth/userinfo.
type liveBFF struct {
	issuer, clientID, redirect string
	client                     *socrate.Client
	store                      *bff.MemoryStore
	pending                    *bff.MemoryPendingLoginStore
	binding                    bff.LoginBinding
	gw                         *bff.Gateway
}

func newLiveBFF(t *testing.T) (*liveBFF, *httptest.Server) {
	t.Helper()
	b := &liveBFF{
		issuer:   liveEnv(t, "SOCRATE_ISSUER"),
		clientID: liveEnv(t, "SOCRATE_PLAIN_CLIENT_ID"),
		redirect: liveEnv(t, "SOCRATE_REDIRECT_URI"),
		store:    bff.NewMemoryStore(time.Hour, 8*time.Hour),
		pending:  bff.NewMemoryPendingLoginStore(bff.DefaultPendingLoginTTL, 100),
		binding:  bff.LoginBinding{Cookie: bff.CookieConfig{Name: "conformance_login"}},
	}
	c, err := socrate.NewClient(socrate.ClientConfig{
		BaseURL: b.issuer, AdminBaseURL: liveEnv(t, "SOCRATE_ADMIN_URL"),
		ClientID: b.clientID, ClientSecret: liveEnv(t, "SOCRATE_PLAIN_CLIENT_SECRET"), Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	b.client = c
	b.gw = &bff.Gateway{Store: b.store, Cookie: bff.CookieConfig{Name: "conformance_session"}, Refresher: c}
	upstream, _ := url.Parse(b.issuer)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", b.login)
	mux.HandleFunc("GET /callback", b.callback)
	mux.HandleFunc("POST /logout", b.logout)
	mux.Handle("/oauth/userinfo", b.gw.ProxyWithSession(bff.NewSingleHostProxy(upstream)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return b, srv
}

func (b *liveBFF) login(w http.ResponseWriter, r *http.Request) {
	pkce := bff.NewPKCE()
	state := bff.RandomToken(24)
	nonce := b.binding.Begin(w)
	if err := b.pending.Put(r.Context(), state, bff.PendingLogin{
		Verifier: pkce.Verifier, Nonce: nonce, ReturnTo: bff.SanitizeReturnTo("/"), Created: time.Now(),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	q := url.Values{
		"response_type": {"code"}, "client_id": {b.clientID}, "redirect_uri": {b.redirect},
		"scope": {"openid profile email"}, "state": {state}, "nonce": {bff.RandomToken(16)},
		"code_challenge": {pkce.Challenge}, "code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, b.issuer+"/oauth/authorize?"+q.Encode(), http.StatusFound)
}

func (b *liveBFF) callback(w http.ResponseWriter, r *http.Request) {
	pending, ok := b.pending.Take(r.Context(), r.URL.Query().Get("state"))
	if !ok || !b.binding.Verify(w, r, pending.Nonce) {
		http.Error(w, "unknown login", http.StatusBadRequest)
		return
	}
	if iss := r.URL.Query().Get("iss"); iss != b.issuer {
		http.Error(w, "unexpected issuer", http.StatusBadRequest)
		return
	}
	ts, err := b.client.ExchangeCode(r.Context(), r.URL.Query().Get("code"), b.redirect, pending.Verifier)
	if err != nil {
		http.Error(w, "code exchange: "+err.Error(), http.StatusBadGateway)
		return
	}
	profile, err := b.client.GetCurrentUserProfile(socrate.WithJWT(r.Context(), ts.AccessToken))
	if err != nil || profile == nil {
		http.Error(w, "userinfo", http.StatusBadGateway)
		return
	}
	s := bff.NewSession(bff.RandomToken(32), bff.RandomToken(32), ts,
		bff.UserInfo{Sub: profile.Sub, Email: profile.Email, Name: profile.Name, Roles: ts.Roles}, time.Now())
	b.store.Put(s)
	b.gw.Cookie.SetSession(w, s.ID())
	http.Redirect(w, r, pending.ReturnTo, http.StatusFound)
}

func (b *liveBFF) logout(w http.ResponseWriter, r *http.Request) {
	s, ok := b.gw.SessionFromRequest(r)
	if !ok || !b.gw.CheckCSRF(r, s) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Revoke the refresh token, end the user's Socrate session, drop ours.
	if err := b.client.RevokeToken(r.Context(), s.RefreshToken()); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := b.client.Logout(socrate.WithJWT(r.Context(), s.AccessToken())); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	b.store.Delete(s.ID())
	b.gw.Cookie.ClearSession(w)
	w.WriteHeader(http.StatusNoContent)
}

var (
	liveHidden  = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)
	liveRefresh = regexp.MustCompile(`http-equiv="refresh" content="0;url=([^"]+)"`)
)

// liveBrowser follows the hosted sign-in and consent pages and returns the
// authorization response (the redirect to the client's redirect_uri).
func liveBrowser(t *testing.T, hc *http.Client, authorizeURL string) url.Values {
	t.Helper()
	page := func(method, u string, form url.Values) string {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequestWithContext(context.Background(), method, u, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, req.URL.Path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || strings.Contains(string(b), `class="alert alert-error"`) {
			t.Fatalf("%s %s: HTTP %d or an error on the page", method, req.URL.Path, resp.StatusCode)
		}
		return string(b)
	}
	hidden := func(p string) url.Values {
		v := url.Values{}
		for _, m := range liveHidden.FindAllStringSubmatch(p, -1) {
			v.Set(m[1], html.UnescapeString(m[2]))
		}
		return v
	}
	issuer := liveEnv(t, "SOCRATE_ISSUER")
	form := hidden(page(http.MethodGet, authorizeURL, nil))
	form.Set("email", liveUser)
	form.Set("password", liveEnv(t, "SOCRATE_USER_PASSWORD"))
	form = hidden(page(http.MethodPost, issuer+"/oauth/authorize", form))
	form.Set("authorized", "true")
	m := liveRefresh.FindStringSubmatch(page(http.MethodPost, issuer+"/oauth/authorize", form))
	if m == nil {
		t.Fatal("consent did not redirect to the client")
	}
	cb, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return cb.Query()
}

func TestConformanceSessionLifecycle(t *testing.T) {
	b, srv := newLiveBFF(t)
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// authorize: the BFF sends the browser to Socrate…
	resp, err := browser.Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	authorize := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(authorize, b.issuer+"/oauth/authorize?") {
		t.Fatalf("/login: HTTP %d to %q", resp.StatusCode, authorize)
	}
	// …the user signs in and consents; the redirect_uri reaches our callback.
	authz := liveBrowser(t, browser, authorize)
	resp, err = browser.Get(srv.URL + "/callback?" + authz.Encode())
	if err != nil {
		t.Fatal(err)
	}
	cbBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/callback: HTTP %d: %s", resp.StatusCode, cbBody)
	}
	// A replayed callback is refused: the state was taken.
	resp, _ = browser.Get(srv.URL + "/callback?" + authz.Encode())
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("replayed callback: HTTP %d, want 400", resp.StatusCode)
	}

	srvURL, _ := url.Parse(srv.URL)
	var sess *bff.Session
	for _, ck := range jar.Cookies(srvURL) {
		if ck.Name == b.gw.Cookie.CookieName() {
			sess, _ = b.store.Get(ck.Value)
		}
	}
	if sess == nil {
		t.Fatal("no session after the callback")
	}
	if !strings.Contains(sess.IDToken(), ".") || sess.User().Sub == "" {
		t.Fatalf("session lacks an ID token or a subject")
	}

	userinfo := func(method string, csrf string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+"/oauth/userinfo", nil)
		if csrf != "" {
			req.Header.Set(bff.DefaultCSRFHeader, csrf)
		}
		resp, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		return resp.StatusCode, doc
	}

	// The proxy injects the session's bearer.
	code, doc := userinfo(http.MethodGet, "")
	if code != http.StatusOK || doc["sub"] != sess.User().Sub {
		t.Fatalf("proxied userinfo: HTTP %d, sub %v, want 200 and %s", code, doc["sub"], sess.User().Sub)
	}
	// Unsafe methods need the CSRF token; no session is a 401.
	if code, _ := userinfo(http.MethodPost, ""); code != http.StatusForbidden {
		t.Errorf("POST without CSRF: HTTP %d, want 403", code)
	}
	if code, _ := userinfo(http.MethodPost, sess.CSRF()); code != http.StatusOK {
		t.Errorf("POST with CSRF: HTTP %d, want 200", code)
	}
	anon, _ := http.Get(srv.URL + "/oauth/userinfo")
	anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Errorf("no session: HTTP %d, want 401", anon.StatusCode)
	}

	// refresh: a proactive refresh rotates the tokens and is written through.
	oldAccess, oldRefresh := sess.AccessToken(), sess.RefreshToken()
	eager := &bff.Gateway{Store: b.store, Cookie: b.gw.Cookie, Refresher: b.client, RefreshLeeway: 24 * time.Hour}
	fresh, err := eager.EnsureFresh(context.Background(), sess)
	if err != nil {
		t.Fatalf("EnsureFresh: %v", err)
	}
	if fresh == oldAccess || sess.RefreshToken() == oldRefresh || fresh != sess.AccessToken() {
		t.Fatal("EnsureFresh did not rotate the session's tokens")
	}
	if code, doc := userinfo(http.MethodGet, ""); code != http.StatusOK || doc["sub"] != sess.User().Sub {
		t.Errorf("userinfo after refresh: HTTP %d", code)
	}
	// The spent refresh token is refused as fatal (the session would end).
	if _, err := b.client.RefreshToken(context.Background(), oldRefresh); !bff.IsFatalRefreshError(err) {
		t.Errorf("reusing a rotated refresh token: %v, want a fatal refresh error", err)
	}

	// logout
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/logout", nil)
	req.Header.Set(bff.DefaultCSRFHeader, sess.CSRF())
	resp, err = browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("/logout: HTTP %d", resp.StatusCode)
	}
	if _, ok := b.store.Get(sess.ID()); ok {
		t.Error("the session survived logout")
	}
	if code, _ := userinfo(http.MethodGet, ""); code != http.StatusUnauthorized {
		t.Errorf("userinfo after logout: HTTP %d, want 401", code)
	}
	if p, err := b.client.GetCurrentUserProfile(socrate.WithJWT(context.Background(), sess.AccessToken())); err != nil || p != nil {
		t.Errorf("the access token outlived logout at Socrate: %v, %v", p, err)
	}
	if _, err := b.client.RefreshToken(context.Background(), sess.RefreshToken()); !bff.IsFatalRefreshError(err) {
		t.Errorf("refresh after logout: %v, want a fatal refresh error", err)
	}
}
