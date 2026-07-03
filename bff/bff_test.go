package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ovander/backendkit/socrate"
)

// ---- redirect ----

func TestSanitizeReturnTo(t *testing.T) {
	cases := map[string]string{
		"/dashboard":       "/dashboard",
		"/a/b?x=1#frag":    "/a/b?x=1#frag",
		"":                 "/",
		"relative":         "/",
		"//evil.com":       "/",
		"/\\evil.com":      "/", // backslash → protocol-relative after browser folding
		"/\\/evil.com":     "/",
		"/path\\to":        "/", // backslash anywhere
		"https://evil.com": "/",
		"/x\ny":            "/", // control char
		"/x\x00y":          "/",
	}
	for in, want := range cases {
		if got := SanitizeReturnTo(in); got != want {
			t.Errorf("SanitizeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- crypto ----

func TestPKCES256(t *testing.T) {
	// RFC 7636 Appendix B known vector.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := S256Challenge(verifier); got != want {
		t.Fatalf("S256Challenge = %q, want %q", got, want)
	}
	p := NewPKCE()
	if p.Verifier == "" || p.Challenge != S256Challenge(p.Verifier) {
		t.Fatalf("NewPKCE produced inconsistent pair: %+v", p)
	}
}

func TestRandomTokenUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok := RandomToken(32)
		if seen[tok] {
			t.Fatal("RandomToken collision")
		}
		seen[tok] = true
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("abc", "abc") {
		t.Error("equal strings reported unequal")
	}
	if ConstantTimeEqual("abc", "abd") || ConstantTimeEqual("abc", "ab") {
		t.Error("unequal strings reported equal")
	}
}

// TestMatchCSRFRejectsEmpty proves a session that lost (or never had) its
// CSRF token fails closed instead of accepting an empty token as a match.
func TestMatchCSRFRejectsEmpty(t *testing.T) {
	s := NewSessionFromSnapshot(SessionSnapshot{ID: "sid", CSRF: ""})
	if s.MatchCSRF("") {
		t.Fatal("empty CSRF token must never match, even against an empty stored value")
	}
	if s.MatchCSRF("anything") {
		t.Fatal("empty stored CSRF must not match any token")
	}
}

// ---- session store ----

func tokenSet(access, refresh string, ttl int) *socrate.TokenSet {
	return &socrate.TokenSet{AccessToken: access, RefreshToken: refresh, ExpiresIn: ttl, TokenType: "Bearer"}
}

func TestMemoryStoreExpiry(t *testing.T) {
	base := time.Now()
	now := base
	st := NewMemoryStore(30*time.Minute, 8*time.Hour)
	st.now = func() time.Time { return now }

	s := NewSession("sid", "csrf", tokenSet("at", "rt", 300), UserInfo{Sub: "u1"}, now)
	st.Put(s)

	if _, ok := st.Get("sid"); !ok {
		t.Fatal("session should be present")
	}
	// Idle expiry.
	now = base.Add(31 * time.Minute)
	if _, ok := st.Get("sid"); ok {
		t.Fatal("session should be idle-expired and evicted")
	}
	if _, ok := st.sessions["sid"]; ok {
		t.Fatal("expired session should be deleted from map")
	}
}

func TestMemoryStoreAbsoluteExpiry(t *testing.T) {
	base := time.Now()
	now := base
	st := NewMemoryStore(0, 2*time.Hour) // no idle bound
	st.now = func() time.Time { return now }
	st.Put(NewSession("sid", "csrf", tokenSet("at", "rt", 300), UserInfo{}, now))
	now = base.Add(3 * time.Hour)
	if _, ok := st.Get("sid"); ok {
		t.Fatal("session should be absolute-expired")
	}
}

// TestSessionConcurrency drives concurrent field access through the accessors to
// prove the per-session lock closes the data race (run with -race).
func TestSessionConcurrency(t *testing.T) {
	s := NewSession("sid", "csrf", tokenSet("at", "rt", 300), UserInfo{Roles: []string{"admin"}}, time.Now())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Touch(time.Now())
			s.SetTokens(tokenSet("at2", "rt2", 300), time.Now())
			_ = s.AccessToken()
			_ = s.RefreshToken()
			_ = s.User()
			_ = s.MatchCSRF("csrf")
			_ = s.AccessValid(time.Now(), time.Second)
		}()
	}
	wg.Wait()
}

// ---- gateway ----

type fakeRefresher struct {
	calls int
	err   error
}

func (f *fakeRefresher) RefreshToken(_ context.Context, _ string) (*socrate.TokenSet, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return tokenSet("refreshed-at", "new-rt", 300), nil
}

func newTestGateway(upstream *url.URL, store SessionStore, ref TokenRefresher) *Gateway {
	return &Gateway{
		Store:     store,
		Cookie:    CookieConfig{Name: "sess", Secure: false, MaxAge: 3600},
		Refresher: ref,
	}
}

// upstreamRecorder echoes what it received so tests can assert header handling.
func upstreamRecorder(gotAuth *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
}

func TestProxyFailsClosedWithoutSession(t *testing.T) {
	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	g := newTestGateway(uu, NewMemoryStore(time.Hour, time.Hour), &fakeRefresher{})
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	// No cookie, and a client-supplied bearer that must NOT reach upstream.
	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	req.Header.Set("Authorization", "Bearer attacker-token")
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
	if gotAuth != "" {
		t.Fatalf("upstream must not be reached; saw Authorization %q", gotAuth)
	}
}

// TestGatewayZeroValueFailsClosed proves a Gateway built as a bare struct
// literal, without explicitly setting DisableAuth, still enforces sessions
// (the zero value of DisableAuth is false — auth enabled).
func TestGatewayZeroValueFailsClosed(t *testing.T) {
	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	g := &Gateway{
		Store:     NewMemoryStore(time.Hour, time.Hour),
		Cookie:    CookieConfig{Name: "sess", Secure: false, MaxAge: 3600},
		Refresher: &fakeRefresher{},
	}
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("zero-value Gateway must fail closed: want 401, got %d", rec.Code)
	}
	if gotAuth != "" {
		t.Fatal("upstream must not be reached")
	}
}

func TestGatewayDisableAuthPassesThrough(t *testing.T) {
	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	g := newTestGateway(uu, NewMemoryStore(time.Hour, time.Hour), &fakeRefresher{})
	g.DisableAuth = true
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DisableAuth: want 200, got %d", rec.Code)
	}
}

func TestProxyPassthroughFlag(t *testing.T) {
	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	g := newTestGateway(uu, NewMemoryStore(time.Hour, time.Hour), &fakeRefresher{})
	g.AllowPassthrough = true // explicit legacy opt-in
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("passthrough: want 200, got %d", rec.Code)
	}
}

func TestProxyInjectsBearerAndStripsClientAuth(t *testing.T) {
	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	store := NewMemoryStore(time.Hour, time.Hour)
	g := newTestGateway(uu, store, &fakeRefresher{})
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	s := NewSession("sid", "csrf", tokenSet("session-at", "rt", 300), UserInfo{Sub: "u1"}, time.Now())
	store.Put(s)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	req.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
	req.Header.Set("Authorization", "Bearer attacker-token") // must be stripped
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if gotAuth != "Bearer session-at" {
		t.Fatalf("upstream Authorization = %q, want session bearer", gotAuth)
	}
}

func TestProxyCSRFEnforcedOnMutations(t *testing.T) {
	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	store := NewMemoryStore(time.Hour, time.Hour)
	g := newTestGateway(uu, store, &fakeRefresher{})
	h := g.ProxyWithSession(NewSingleHostProxy(uu))
	store.Put(NewSession("sid", "the-csrf", tokenSet("at", "rt", 300), UserInfo{}, time.Now()))

	// POST without CSRF header → 403, upstream untouched.
	req := httptest.NewRequest(http.MethodPost, "/api/admin/x", nil)
	req.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST w/o CSRF: want 403, got %d", rec.Code)
	}
	if gotAuth != "" {
		t.Fatal("upstream reached despite missing CSRF")
	}

	// POST with correct CSRF → 200.
	req2 := httptest.NewRequest(http.MethodPost, "/api/admin/x", nil)
	req2.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
	req2.Header.Set(DefaultCSRFHeader, "the-csrf")
	rec2 := httptest.NewRecorder()
	h(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("POST w/ CSRF: want 200, got %d", rec2.Code)
	}
}

func TestEnsureFreshRefreshesExpiredToken(t *testing.T) {
	store := NewMemoryStore(time.Hour, time.Hour)
	ref := &fakeRefresher{}
	uu, _ := url.Parse("http://upstream.invalid")
	g := newTestGateway(uu, store, ref)

	// Access token already expired (ExpiresIn 0 → expiry = created).
	s := NewSession("sid", "csrf", tokenSet("old-at", "rt", 0), UserInfo{}, time.Now().Add(-time.Minute))
	access, err := g.EnsureFresh(context.Background(), s)
	if err != nil {
		t.Fatalf("EnsureFresh: %v", err)
	}
	if ref.calls != 1 || access != "refreshed-at" {
		t.Fatalf("want 1 refresh and refreshed token, got calls=%d access=%q", ref.calls, access)
	}

	// Fresh token → no refresh call.
	before := ref.calls
	if _, err := g.EnsureFresh(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if ref.calls != before {
		t.Fatalf("valid token should not trigger refresh")
	}
}

// rotatingRefresher models a single-use rotating refresh token: reusing an
// already-spent token is an error, exactly as a real OAuth server would
// reject it. This is what makes TestEnsureFreshCoalescesConcurrentRefreshes a
// meaningful reproduction of the P2-8 race — without coalescing, every
// concurrent caller past the first would race to spend the same token and
// only one would succeed.
type rotatingRefresher struct {
	mu    sync.Mutex
	used  map[string]bool
	calls int
}

func (r *rotatingRefresher) RefreshToken(_ context.Context, rt string) (*socrate.TokenSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used == nil {
		r.used = make(map[string]bool)
	}
	if r.used[rt] {
		return nil, fmt.Errorf("refresh token %q already used", rt)
	}
	r.used[rt] = true
	r.calls++
	return tokenSet(fmt.Sprintf("at-%d", r.calls), fmt.Sprintf("rt-%d", r.calls), 300), nil
}

// TestEnsureFreshCoalescesConcurrentRefreshes reproduces P2-8: many concurrent
// requests for the same expired session must share a single refresh call
// (via refreshGroup), not race to spend the single-use rotating refresh
// token. Run with -race.
func TestEnsureFreshCoalescesConcurrentRefreshes(t *testing.T) {
	store := NewMemoryStore(time.Hour, time.Hour)
	ref := &rotatingRefresher{}
	uu, _ := url.Parse("http://upstream.invalid")
	g := newTestGateway(uu, store, ref)

	s := NewSession("sid", "csrf", tokenSet("old-at", "rt-0", 0), UserInfo{}, time.Now().Add(-time.Minute))
	store.Put(s)

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	accesses := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			access, err := g.EnsureFresh(context.Background(), s)
			errs[i], accesses[i] = err, access
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: EnsureFresh failed: %v", i, err)
		}
	}
	if ref.calls != 1 {
		t.Fatalf("want exactly 1 refresh call across %d concurrent callers, got %d", n, ref.calls)
	}
	want := accesses[0]
	for i, a := range accesses {
		if a != want {
			t.Fatalf("goroutine %d got access %q, want %q (all concurrent callers must observe the same refreshed token)", i, a, want)
		}
	}
	if _, ok := store.Get("sid"); !ok {
		t.Fatal("session must survive a coalesced refresh")
	}
}

func TestProxyRefreshFailureClearsSession(t *testing.T) {
	uu, _ := url.Parse("http://upstream.invalid")
	store := NewMemoryStore(time.Hour, time.Hour)
	g := newTestGateway(uu, store, &fakeRefresher{err: errors.New("refresh boom")})
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	store.Put(NewSession("sid", "csrf", tokenSet("expired", "rt", 0), UserInfo{}, time.Now().Add(-time.Minute)))
	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	req.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 on refresh failure, got %d", rec.Code)
	}
	if _, ok := store.Get("sid"); ok {
		t.Fatal("session should be deleted after refresh failure")
	}
}

func TestCookieHostPrefix(t *testing.T) {
	secure := CookieConfig{Name: "sess", Secure: true}
	if secure.CookieName() != "__Host-sess" {
		t.Fatalf("secure cookie name = %q", secure.CookieName())
	}
	dev := CookieConfig{Name: "sess", Secure: false}
	if dev.CookieName() != "sess" {
		t.Fatalf("dev cookie name = %q", dev.CookieName())
	}
	rec := httptest.NewRecorder()
	secure.SetSession(rec, "v")
	ck := rec.Result().Cookies()[0]
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
		t.Fatalf("cookie flags wrong: %+v", ck)
	}
}

// ensure the proxy type is what we expect (compile-time guard).
var _ = httputil.ReverseProxy{}

func TestSessionSnapshotRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second) // JSON round-trips to second precision
	orig := NewSession("sid", "csrf-tok", tokenSet("at", "rt", 300), UserInfo{Sub: "u1", Email: "a@b.com", Roles: []string{"admin", "viewer"}}, now)
	orig.SetTokens(tokenSet("at2", "rt2", 600), now.Add(time.Minute))
	orig.Touch(now.Add(2 * time.Minute))

	snap := orig.Snapshot()
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var decoded SessionSnapshot
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}

	rehydrated := NewSessionFromSnapshot(decoded)
	if rehydrated.ID() != orig.ID() {
		t.Errorf("ID mismatch: %q vs %q", rehydrated.ID(), orig.ID())
	}
	if rehydrated.AccessToken() != orig.AccessToken() || rehydrated.RefreshToken() != orig.RefreshToken() {
		t.Errorf("token mismatch: got at=%q rt=%q, want at=%q rt=%q",
			rehydrated.AccessToken(), rehydrated.RefreshToken(), orig.AccessToken(), orig.RefreshToken())
	}
	if !rehydrated.MatchCSRF("csrf-tok") {
		t.Error("CSRF did not survive round-trip")
	}
	if rehydrated.User().Sub != "u1" || len(rehydrated.User().Roles) != 2 {
		t.Errorf("user did not survive round-trip: %+v", rehydrated.User())
	}
	// AccessValid depends on accessExpiry, which was captured in the snapshot.
	if !rehydrated.AccessValid(now.Add(time.Minute+30*time.Second), 0) {
		t.Error("access expiry did not survive round-trip")
	}
	if rehydrated.AccessValid(now.Add(11*time.Minute), 0) {
		t.Error("rehydrated session should be expired well past its access expiry")
	}
}
