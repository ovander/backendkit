package socrate_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/socrate"
)

// scopedTokenServer fakes Socrate's /oauth/token for client_credentials. Each
// exchange issues "tok-<n>"; respond, when set, writes the answer instead
// (given the requested scope and the token it would issue). It records the
// scope parameter of every request, and whether it was present.
type scopedTokenServer struct {
	mu        sync.Mutex
	scopes    []string // scope parameter per request; "<none>" when absent
	corrIDs   []string
	n         atomic.Int32
	expiresIn int
	respond   func(w http.ResponseWriter, scope, tok string)
}

func (s *scopedTokenServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.scopes...)
}

func newScopedTokenServer(t *testing.T, s *scopedTokenServer) *socrate.Client {
	t.Helper()
	if s.expiresIn == 0 {
		s.expiresIn = 3600
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" ||
			r.PostForm.Get("client_id") != "cid" || r.PostForm.Get("client_secret") != "s3cret" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		scope := "<none>"
		if vs, ok := r.PostForm["scope"]; ok {
			scope = strings.Join(vs, ",")
		}
		s.mu.Lock()
		s.scopes = append(s.scopes, scope)
		s.corrIDs = append(s.corrIDs, r.Header.Get("X-Correlation-ID"))
		s.mu.Unlock()
		tok := fmt.Sprintf("tok-%d", s.n.Add(1))
		if s.respond != nil {
			s.respond(w, scope, tok)
			return
		}
		body := map[string]any{"access_token": tok, "expires_in": s.expiresIn, "token_type": "Bearer"}
		if scope != "<none>" {
			body["scope"] = scope
		} else {
			body["scope"] = "api"
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	srv, closeFn := newTestServer(mux)
	t.Cleanup(closeFn)
	c, err := socrate.NewClient(socrate.ClientConfig{BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "cid", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServiceTokenWithScopes_SendsNormalisedScopeAndCaches(t *testing.T) {
	s := &scopedTokenServer{}
	c := newScopedTokenServer(t, s)
	ctx := context.Background()

	before := time.Now()
	tok, exp, err := c.ServiceTokenWithScopes(ctx, "swingdrift:worker", "api", "swingdrift:worker")
	if err != nil || tok != "tok-1" {
		t.Fatalf("ServiceTokenWithScopes = %q, %v", tok, err)
	}
	if exp.Before(before.Add(59*time.Minute)) || exp.After(time.Now().Add(time.Hour)) {
		t.Errorf("expiry %v, want about one hour from now", exp)
	}
	if got := s.requests(); len(got) != 1 || got[0] != "api swingdrift:worker" {
		t.Fatalf("scope parameters %q, want one request with \"api swingdrift:worker\"", got)
	}

	// Same set in another order: the cached token, no exchange.
	tok2, exp2, err := c.ServiceTokenWithScopes(ctx, "api", "swingdrift:worker")
	if err != nil || tok2 != tok || !exp2.Equal(exp) || s.n.Load() != 1 {
		t.Errorf("same set reordered: %q %v %v after %d exchanges; want the cached token", tok2, exp2, err, s.n.Load())
	}

	// A different set gets its own token.
	tok3, _, err := c.ServiceTokenWithScopes(ctx, "swingdrift:worker")
	if err != nil || tok3 != "tok-2" {
		t.Errorf("different set: %q, %v; want tok-2", tok3, err)
	}
	if again, _, _ := c.ServiceTokenWithScopes(ctx, "swingdrift:worker"); again != tok3 || s.n.Load() != 2 {
		t.Errorf("different set is cached too: %q after %d exchanges", again, s.n.Load())
	}
	if got := s.requests(); len(got) != 2 || got[1] != "swingdrift:worker" {
		t.Errorf("scope parameters %q", got)
	}
}

func TestServiceTokenWithScopes_SeparateFromServiceToken(t *testing.T) {
	s := &scopedTokenServer{}
	c := newScopedTokenServer(t, s)
	ctx := context.Background()

	scoped, _, err := c.ServiceTokenWithScopes(ctx, "swingdrift:worker")
	if err != nil || scoped != "tok-1" {
		t.Fatalf("ServiceTokenWithScopes = %q, %v", scoped, err)
	}
	plain, _, err := c.ServiceToken(ctx)
	if err != nil || plain != "tok-2" {
		t.Fatalf("ServiceToken = %q, %v; want its own token from a second exchange", plain, err)
	}
	if got := s.requests(); len(got) != 2 || got[1] != "<none>" {
		t.Errorf("ServiceToken sent scope %q, want no scope parameter", got)
	}
	// Each stays cached on its own.
	if again, _, _ := c.ServiceToken(ctx); again != plain {
		t.Errorf("ServiceToken = %q, want the cached %q", again, plain)
	}
	if again, _, _ := c.ServiceTokenWithScopes(ctx, "swingdrift:worker"); again != scoped {
		t.Errorf("ServiceTokenWithScopes = %q, want the cached %q", again, scoped)
	}
	if s.n.Load() != 2 {
		t.Errorf("%d exchanges, want 2", s.n.Load())
	}
}

func TestServiceTokenWithScopes_RenewsNearExpiry(t *testing.T) {
	// A token valid less than 30 s is exchanged again on every call.
	s := &scopedTokenServer{expiresIn: 10}
	c := newScopedTokenServer(t, s)
	for i := range 2 {
		tok, _, err := c.ServiceTokenWithScopes(context.Background(), "a:b")
		if err != nil || tok != fmt.Sprintf("tok-%d", i+1) {
			t.Fatalf("call %d: %q, %v", i, tok, err)
		}
	}
	if s.n.Load() != 2 {
		t.Errorf("%d exchanges, want 2", s.n.Load())
	}
}

func TestServiceTokenWithScopes_ConcurrentCallersShareOneExchange(t *testing.T) {
	s := &scopedTokenServer{respond: func(w http.ResponseWriter, scope, tok string) {
		time.Sleep(50 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "expires_in": 3600, "scope": scope})
	}}
	c := newScopedTokenServer(t, s)
	var wg sync.WaitGroup
	for i := range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scopes := []string{"a:x", "b:y"}
			if i%2 == 1 {
				scopes = []string{"b:y", "a:x"}
			}
			if i%3 == 0 {
				scopes = []string{"c:z"}
			}
			if tok, _, err := c.ServiceTokenWithScopes(context.Background(), scopes...); err != nil || tok == "" {
				t.Errorf("ServiceTokenWithScopes = %q, %v", tok, err)
			}
		}()
	}
	wg.Wait()
	if s.n.Load() != 2 {
		t.Errorf("%d exchanges for two scope sets, want 2", s.n.Load())
	}
}

func TestServiceTokenWithScopes_RejectsInvalidScopesWithoutARequest(t *testing.T) {
	s := &scopedTokenServer{}
	c := newScopedTokenServer(t, s)
	cases := map[string][]string{
		"no scope":        nil,
		"empty scope":     {""},
		"one empty":       {"a:b", ""},
		"space":           {"a:b c:d"},
		"leading space":   {" a:b"},
		"double quote":    {`a"b`},
		"backslash":       {`a\b`},
		"control":         {"a\tb"},
		"non-ASCII":       {"a:é"},
		"DEL":             {"a\x7f"},
		"newline":         {"a\nb"},
		"valid then soft": {"a:b", "x y"},
	}
	for name, scopes := range cases {
		t.Run(name, func(t *testing.T) {
			tok, exp, err := c.ServiceTokenWithScopes(context.Background(), scopes...)
			if err == nil || tok != "" || !exp.IsZero() {
				t.Errorf("ServiceTokenWithScopes(%q) = %q %v %v, want an error", scopes, tok, exp, err)
			}
		})
	}
	if s.n.Load() != 0 {
		t.Errorf("%d requests made, want none", s.n.Load())
	}

	noSecret, err := socrate.NewClient(socrate.ClientConfig{BaseURL: "http://127.0.0.1:1", ClientID: "cid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := noSecret.ServiceTokenWithScopes(context.Background(), "a:b"); err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("no secret: %v", err)
	}
}

func TestServiceTokenWithScopes_InvalidScopeIsRecognisable(t *testing.T) {
	s := &scopedTokenServer{respond: func(w http.ResponseWriter, _, _ string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_scope","error_description":"requested scope is not allowed for this client"}`))
	}}
	c := newScopedTokenServer(t, s)
	tok, exp, err := c.ServiceTokenWithScopes(context.Background(), "swingdrift:worker")
	if err == nil || tok != "" || !exp.IsZero() {
		t.Fatalf("invalid_scope: %q %v %v, want an error", tok, exp, err)
	}
	if !errors.Is(err, socrate.ErrScopeNotGranted) {
		t.Errorf("errors.Is(%v, ErrScopeNotGranted) = false", err)
	}
	var oe *socrate.OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_scope" || oe.StatusCode != http.StatusBadRequest {
		t.Errorf("errors.As OAuthError: %+v from %v", oe, err)
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error leaks the secret: %v", err)
	}
	// Nothing is cached: the next call asks again.
	_, _, _ = c.ServiceTokenWithScopes(context.Background(), "swingdrift:worker")
	if s.n.Load() != 2 {
		t.Errorf("%d exchanges, want 2 (a failure is not cached)", s.n.Load())
	}
}

func TestServiceTokenWithScopes_OtherRefusalIsAnOAuthError(t *testing.T) {
	s := &scopedTokenServer{respond: func(w http.ResponseWriter, _, _ string) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}}
	c := newScopedTokenServer(t, s)
	_, _, err := c.ServiceTokenWithScopes(context.Background(), "a:b")
	var oe *socrate.OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_client" || oe.StatusCode != http.StatusUnauthorized {
		t.Errorf("errors.As OAuthError: %+v from %v", oe, err)
	}
	if errors.Is(err, socrate.ErrScopeNotGranted) {
		t.Errorf("invalid_client must not match ErrScopeNotGranted: %v", err)
	}
}

func TestServiceTokenWithScopes_ResponseScope(t *testing.T) {
	const secretTok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhcHA6MSJ9.super-secret-signature"
	tests := []struct {
		name    string
		body    map[string]any
		wantErr bool
	}{
		{"scope missing a requested one", map[string]any{"scope": "api a:b"}, true},
		{"empty scope", map[string]any{"scope": ""}, true},
		{"non-string scope", map[string]any{"scope": []string{"a:b", "c:d"}}, true},
		{"null scope", map[string]any{"scope": nil}, false},
		{"no scope field", map[string]any{}, false},
		{"exact scope", map[string]any{"scope": "c:d a:b"}, false},
		{"wider scope", map[string]any{"scope": "a:b api c:d"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &scopedTokenServer{respond: func(w http.ResponseWriter, _, _ string) {
				body := map[string]any{"access_token": secretTok, "expires_in": 3600, "token_type": "Bearer"}
				for k, v := range tt.body {
					body[k] = v
				}
				_ = json.NewEncoder(w).Encode(body)
			}}
			c := newScopedTokenServer(t, s)
			tok, exp, err := c.ServiceTokenWithScopes(context.Background(), "a:b", "c:d")
			if !tt.wantErr {
				if err != nil || tok != secretTok {
					t.Fatalf("ServiceTokenWithScopes = %q, %v; want the token", tok, err)
				}
				return
			}
			if err == nil || tok != "" || !exp.IsZero() {
				t.Fatalf("ServiceTokenWithScopes = %q %v %v, want an error", tok, exp, err)
			}
			if !errors.Is(err, socrate.ErrScopeNotGranted) {
				t.Errorf("errors.Is(%v, ErrScopeNotGranted) = false", err)
			}
			if _, isString := tt.body["scope"].(string); isString && !strings.Contains(err.Error(), "c:d") {
				t.Errorf("error %q does not name the missing scope", err)
			}
			if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), "eyJ") {
				t.Errorf("error leaks the token: %v", err)
			}
			// Not cached: the next call exchanges again.
			_, _, _ = c.ServiceTokenWithScopes(context.Background(), "a:b", "c:d")
			if s.n.Load() != 2 {
				t.Errorf("%d exchanges, want 2", s.n.Load())
			}
		})
	}
}

func TestServiceTokenWithScopes_NoTokenInErrors(t *testing.T) {
	const secretTok = "tok-must-not-leak"
	for name, respond := range map[string]func(w http.ResponseWriter, scope, tok string){
		"bad json": func(w http.ResponseWriter, _, _ string) {
			_, _ = w.Write([]byte(`{"access_token":"` + secretTok + `","expires_in":"soon"}`))
		},
		"scope not granted": func(w http.ResponseWriter, _, _ string) {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": secretTok, "scope": "api"})
		},
		"no access_token": func(w http.ResponseWriter, _, _ string) {
			_ = json.NewEncoder(w).Encode(map[string]any{"scope": "a:b"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newScopedTokenServer(t, &scopedTokenServer{respond: respond})
			_, _, err := c.ServiceTokenWithScopes(context.Background(), "a:b")
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), secretTok) || strings.Contains(err.Error(), "s3cret") {
				t.Errorf("error leaks a credential: %v", err)
			}
		})
	}
}

func TestServiceTokenWithScopes_CacheIsBoundedLRU(t *testing.T) {
	s := &scopedTokenServer{}
	c := newScopedTokenServer(t, s)
	ctx := context.Background()
	get := func(i int) string {
		t.Helper()
		tok, _, err := c.ServiceTokenWithScopes(ctx, fmt.Sprintf("set:s%d", i))
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	first := make([]string, 17)
	for i := range 16 {
		first[i] = get(i)
	}
	if s.n.Load() != 16 {
		t.Fatalf("%d exchanges, want 16", s.n.Load())
	}
	// Touch s0 so s1 becomes the least recently used, then add a 17th set.
	if get(0) != first[0] {
		t.Fatal("s0 not cached")
	}
	first[16] = get(16)
	if s.n.Load() != 17 {
		t.Fatalf("%d exchanges, want 17", s.n.Load())
	}
	// s0 and s2..s16 are still cached; s1 was evicted.
	for _, i := range []int{0, 2, 15, 16} {
		if got := get(i); got != first[i] {
			t.Errorf("s%d: %q, want the cached %q", i, got, first[i])
		}
	}
	if s.n.Load() != 17 {
		t.Fatalf("%d exchanges after cache hits, want 17", s.n.Load())
	}
	if got := get(1); got == first[1] || s.n.Load() != 18 {
		t.Errorf("s1 after eviction: %q after %d exchanges; want a new token from an 18th exchange", got, s.n.Load())
	}
}

func TestServiceTokenWithScopes_InvalidateServiceTokenClearsScopedCaches(t *testing.T) {
	s := &scopedTokenServer{}
	c := newScopedTokenServer(t, s)
	ctx := context.Background()

	a, _, _ := c.ServiceTokenWithScopes(ctx, "a:b")
	plain, _, _ := c.ServiceToken(ctx)
	if a != "tok-1" || plain != "tok-2" {
		t.Fatalf("tokens %q %q", a, plain)
	}
	c.InvalidateServiceToken()
	a2, _, err := c.ServiceTokenWithScopes(ctx, "a:b")
	if err != nil || a2 == a {
		t.Errorf("after invalidation the scoped token is exchanged again: %q, %v", a2, err)
	}
	plain2, _, err := c.ServiceToken(ctx)
	if err != nil || plain2 == plain {
		t.Errorf("after invalidation ServiceToken exchanges again: %q, %v", plain2, err)
	}
	if s.n.Load() != 4 {
		t.Errorf("%d exchanges, want 4", s.n.Load())
	}
	if again, _, _ := c.ServiceTokenWithScopes(ctx, "a:b"); again != a2 || s.n.Load() != 4 {
		t.Errorf("the new scoped token is cached: %q after %d exchanges", again, s.n.Load())
	}
}

func TestServiceTokenWithScopes_InvalidateConcurrent(t *testing.T) {
	c := newScopedTokenServer(t, &scopedTokenServer{})
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%4 == 0 {
				c.InvalidateServiceToken()
				return
			}
			if tok, _, err := c.ServiceTokenWithScopes(context.Background(), fmt.Sprintf("set:s%d", i%3)); err != nil || tok == "" {
				t.Errorf("ServiceTokenWithScopes = %q, %v", tok, err)
			}
		}()
	}
	wg.Wait()
}

func TestServiceTokenWithScopes_ForwardsCorrelationID(t *testing.T) {
	s := &scopedTokenServer{}
	c := newScopedTokenServer(t, s)
	ctx := ctxutil.WithRequestID(context.Background(), "req-123")
	if _, _, err := c.ServiceTokenWithScopes(ctx, "a:b"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.corrIDs) != 1 || s.corrIDs[0] != "req-123" {
		t.Errorf("X-Correlation-ID %q, want req-123", s.corrIDs)
	}
}
