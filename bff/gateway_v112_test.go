package bff

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ovander/backendkit/socrate"
)

// snapshotStore behaves like a durable (Postgres) SessionStore: every Get
// rehydrates a brand-new *Session from the stored snapshot, so anything
// mutated on a Session that is not written back with Put is lost. This is
// the exact shape of oauth2-monitoring's PostgresSessionStore.
type snapshotStore struct {
	mu   sync.Mutex
	rows map[string]SessionSnapshot
	puts int
}

func newSnapshotStore() *snapshotStore { return &snapshotStore{rows: map[string]SessionSnapshot{}} }

func (s *snapshotStore) Get(id string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, ok := s.rows[id]
	if !ok {
		return nil, false
	}
	return NewSessionFromSnapshot(snap), true
}

func (s *snapshotStore) Put(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[sess.ID()] = sess.Snapshot()
	s.puts++
}

func (s *snapshotStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
}

func (s *snapshotStore) Sweep() {}

func (s *snapshotStore) snapshot(id string) (SessionSnapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, ok := s.rows[id]
	return snap, ok
}

// TestProxyPersistsRefreshedTokensToDurableStore reproduces P3-10: after a
// proxy-path refresh, the rotated refresh token must be written back to the
// store, otherwise the next request re-reads the spent one and the session
// dies at its first access-token expiry.
func TestProxyPersistsRefreshedTokensToDurableStore(t *testing.T) {
	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	store := newSnapshotStore()
	ref := &rotatingRefresher{}
	g := newTestGateway(uu, store, ref)
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	// Expired access token, refresh token rt-0.
	store.Put(NewSession("sid", "csrf", tokenSet("old-at", "rt-0", 0), UserInfo{Sub: "u1"}, time.Now().Add(-time.Minute)))

	do := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
		req.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code
	}

	if code := do(); code != http.StatusOK {
		t.Fatalf("request 1: got %d, want 200", code)
	}
	snap, ok := store.snapshot("sid")
	if !ok {
		t.Fatal("session vanished after first request")
	}
	if snap.AccessToken != "at-1" || snap.RefreshToken != "rt-1" {
		t.Fatalf("P3-10: refreshed tokens not persisted; store has access=%q refresh=%q, want at-1/rt-1", snap.AccessToken, snap.RefreshToken)
	}

	// Second request must use the persisted fresh token — no second refresh,
	// no session death.
	if code := do(); code != http.StatusOK {
		t.Fatalf("request 2: got %d, want 200 (session died: spent refresh token re-used?)", code)
	}
	if ref.calls != 1 {
		t.Fatalf("want exactly 1 refresh across two requests, got %d", ref.calls)
	}
	if gotAuth != "Bearer at-1" {
		t.Fatalf("upstream saw %q, want Bearer at-1", gotAuth)
	}
}

// blockingRefresher parks until release is closed, honouring ctx cancellation
// the way a real HTTP client would.
type blockingRefresher struct {
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (b *blockingRefresher) RefreshToken(ctx context.Context, _ string) (*socrate.TokenSet, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	select {
	case <-b.release:
		return tokenSet("fresh-at", "fresh-rt", 300), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestEnsureFreshSurvivesLeaderContextCancellation reproduces P3-11: the
// first caller's request context must not govern the shared refresh. The
// leader's request is cancelled mid-refresh; every waiter (and the leader's
// own return) must still receive the refreshed token.
func TestEnsureFreshSurvivesLeaderContextCancellation(t *testing.T) {
	store := NewMemoryStore(time.Hour, time.Hour)
	ref := &blockingRefresher{release: make(chan struct{})}
	uu, _ := url.Parse("http://upstream.invalid")
	g := newTestGateway(uu, store, ref)
	g.RefreshTimeout = 5 * time.Second

	s := NewSession("sid", "csrf", tokenSet("old-at", "rt-0", 0), UserInfo{}, time.Now().Add(-time.Minute))
	store.Put(s)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	type result struct {
		access string
		err    error
	}
	results := make(chan result, 4)

	go func() {
		a, err := g.EnsureFresh(leaderCtx, s)
		results <- result{a, err}
	}()
	// Let the leader enter the refresher before the waiters queue up.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ref.mu.Lock()
		started := ref.calls > 0
		ref.mu.Unlock()
		if started || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		go func() {
			a, err := g.EnsureFresh(context.Background(), s)
			results <- result{a, err}
		}()
	}
	time.Sleep(20 * time.Millisecond)

	cancelLeader() // browser aborted the first request
	time.Sleep(20 * time.Millisecond)
	close(ref.release) // token endpoint answers

	for i := 0; i < 4; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("P3-11: caller failed after leader cancellation: %v", r.err)
			}
			if r.access != "fresh-at" {
				t.Fatalf("caller got %q, want fresh-at", r.access)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for callers")
		}
	}
	if ref.calls != 1 {
		t.Fatalf("want 1 refresh call, got %d", ref.calls)
	}
	if _, ok := store.Get("sid"); !ok {
		t.Fatal("session must survive")
	}
}

func TestIsFatalRefreshError(t *testing.T) {
	cases := []struct {
		err   error
		fatal bool
	}{
		{&socrate.OAuthError{StatusCode: 400, Code: "invalid_grant"}, true},
		{&socrate.OAuthError{StatusCode: 401, Code: "invalid_client"}, true},
		{&socrate.OAuthError{StatusCode: 400, Code: "unauthorized_client"}, true},
		{fmt.Errorf("refresh token: %w", &socrate.OAuthError{Code: "invalid_grant"}), true},
		{&socrate.OAuthError{StatusCode: 503, Description: "upstream down"}, false},
		{&socrate.OAuthError{StatusCode: 400, Code: "temporarily_unavailable"}, false},
		{errors.New("dial tcp 127.0.0.1:8080: i/o timeout"), false},
		{context.DeadlineExceeded, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := IsFatalRefreshError(c.err); got != c.fatal {
			t.Errorf("IsFatalRefreshError(%v) = %v, want %v", c.err, got, c.fatal)
		}
	}
}

// TestProxyTransientRefreshErrorKeepsSession reproduces P3-12: a token
// endpoint blip must not log the user out.
func TestProxyTransientRefreshErrorKeepsSession(t *testing.T) {
	uu, _ := url.Parse("http://upstream.invalid")
	store := NewMemoryStore(time.Hour, time.Hour)
	g := newTestGateway(uu, store, &fakeRefresher{err: errors.New("dial tcp: i/o timeout")})
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	store.Put(NewSession("sid", "csrf", tokenSet("expired", "rt", 0), UserInfo{}, time.Now().Add(-time.Minute)))
	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	req.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("transient refresh failure: got %d, want 502", rec.Code)
	}
	if _, ok := store.Get("sid"); !ok {
		t.Fatal("session must be kept on a transient refresh failure")
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "sess" && ck.MaxAge < 0 {
			t.Fatal("session cookie must not be cleared on a transient refresh failure")
		}
	}
}

func TestProxyFatalRefreshErrorClearsSession(t *testing.T) {
	uu, _ := url.Parse("http://upstream.invalid")
	store := NewMemoryStore(time.Hour, time.Hour)
	g := newTestGateway(uu, store, &fakeRefresher{err: &socrate.OAuthError{StatusCode: 400, Code: "invalid_grant", Description: "refresh token revoked"}})
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	store.Put(NewSession("sid", "csrf", tokenSet("expired", "rt", 0), UserInfo{}, time.Now().Add(-time.Minute)))
	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	req.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("fatal refresh failure: got %d, want 401", rec.Code)
	}
	if _, ok := store.Get("sid"); ok {
		t.Fatal("session must be deleted on invalid_grant")
	}
	cleared := false
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == "sess" && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("session cookie must be cleared on invalid_grant")
	}
}

// TestProxyTouchIsThrottledButPersisted covers the second half of P3-10:
// last_seen must reach a durable store, but not on every request.
func TestProxyTouchIsThrottledButPersisted(t *testing.T) {
	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	base := time.Now()
	now := base
	store := newSnapshotStore()
	g := newTestGateway(uu, store, &fakeRefresher{})
	g.Now = func() time.Time { return now }
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	// Valid access token (expires an hour from now) but a last_seen an hour
	// old, so the first request needs no refresh and only the touch decides
	// whether a Put happens.
	store.Put(NewSessionFromSnapshot(SessionSnapshot{
		ID:           "sid",
		AccessToken:  "at",
		RefreshToken: "rt",
		AccessExpiry: base.Add(time.Hour),
		CSRF:         "csrf",
		Created:      base.Add(-time.Hour),
		LastSeen:     base.Add(-time.Hour),
	}))
	store.puts = 0

	do := func() {
		req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
		req.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("got %d, want 200", rec.Code)
		}
	}

	do() // last_seen is an hour old → persisted
	if store.puts != 1 {
		t.Fatalf("first request: want 1 Put (touch persisted), got %d", store.puts)
	}
	now = base.Add(10 * time.Second)
	do() // inside TouchInterval → no write
	if store.puts != 1 {
		t.Fatalf("request inside TouchInterval must not Put; got %d puts", store.puts)
	}
	now = base.Add(2 * time.Minute)
	do() // past TouchInterval → persisted again
	if store.puts != 2 {
		t.Fatalf("request past TouchInterval must Put; got %d puts", store.puts)
	}
	snap, _ := store.snapshot("sid")
	if !snap.LastSeen.Equal(now) {
		t.Fatalf("persisted last_seen = %v, want %v", snap.LastSeen, now)
	}
}

// TestNewSingleHostProxyStripsClientIPHeaders covers P3-16: a browser must
// not be able to hand the upstream an IP it will attribute the request to.
func TestNewSingleHostProxyStripsClientIPHeaders(t *testing.T) {
	var seen http.Header
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	g := newTestGateway(uu, NewMemoryStore(time.Hour, time.Hour), &fakeRefresher{})
	g.DisableAuth = true
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
	req.RemoteAddr = "127.0.0.1:4242"
	req.Header.Set("X-Real-IP", "198.51.100.1")
	req.Header.Set("True-Client-IP", "198.51.100.2")
	req.Header.Set("Forwarded", "for=198.51.100.3")
	req.Header.Set("X-Forwarded-For", "203.0.113.9") // edge-managed; left alone
	rec := httptest.NewRecorder()
	h(rec, req)

	for _, name := range []string{"X-Real-IP", "True-Client-IP", "Forwarded"} {
		if v := seen.Get(name); v != "" {
			t.Errorf("P3-16: %s reached upstream with %q", name, v)
		}
	}
	if xff := seen.Get("X-Forwarded-For"); !strings.HasPrefix(xff, "203.0.113.9") {
		t.Errorf("X-Forwarded-For should be preserved (edge-managed); upstream saw %q", xff)
	}
}

func TestSessionStringRedactsSecrets(t *testing.T) {
	s := NewSession("sid-123", "csrf-secret", tokenSet("access-secret", "refresh-secret", 300), UserInfo{Sub: "u1"}, time.Now())
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s)} {
		for _, secret := range []string{"csrf-secret", "access-secret", "refresh-secret"} {
			if strings.Contains(out, secret) {
				t.Fatalf("Session formatting leaked %q: %s", secret, out)
			}
		}
		if !strings.Contains(out, "sid-123") {
			t.Fatalf("Session formatting should still identify the session: %s", out)
		}
	}
}
