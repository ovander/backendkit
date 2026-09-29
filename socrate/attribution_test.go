package socrate_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/ovander/backendkit/socrate"
)

func TestClientAttributionFrom(t *testing.T) {
	if _, ok := socrate.ClientAttributionFrom(context.Background()); ok {
		t.Fatal("empty context reported an attribution")
	}
	want := socrate.ClientAttribution{IP: "203.0.113.7", UserAgent: "Mozilla/5.0"}
	got, ok := socrate.ClientAttributionFrom(socrate.WithClientAttribution(context.Background(), want))
	if !ok || got != want {
		t.Fatalf("got %+v, %v; want %+v, true", got, ok, want)
	}
}

func newAttributedRequest(t *testing.T, a *socrate.ClientAttribution) *http.Request {
	t.Helper()
	ctx := context.Background()
	if a != nil {
		ctx = socrate.WithClientAttribution(ctx, *a)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://socrate.invalid/oauth/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Headers a browser (or a careless caller) could have put there.
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 1.2.3.4")
	req.Header.Set("X-Real-IP", "6.6.6.6")
	req.Header.Set("User-Agent", "existing-ua")
	return req
}

func TestApplyClientAttribution(t *testing.T) {
	longUA := strings.Repeat("é", 300) // 600 bytes of 2-byte runes
	tests := []struct {
		name        string
		attr        *socrate.ClientAttribution
		wantXFF     string
		wantRealIP  string
		wantUA      string
		checkUASize bool
	}{
		{
			name:    "replaces XFF, drops X-Real-IP, sets UA",
			attr:    &socrate.ClientAttribution{IP: " 203.0.113.7 ", UserAgent: "Mozilla/5.0 (X11)"},
			wantXFF: "203.0.113.7", wantUA: "Mozilla/5.0 (X11)",
		},
		{
			name:    "IPv6 in canonical form",
			attr:    &socrate.ClientAttribution{IP: "2001:DB8:0:0::1"},
			wantXFF: "2001:db8::1", wantUA: "existing-ua",
		},
		{
			name:    "invalid IP sets no XFF",
			attr:    &socrate.ClientAttribution{IP: "6.6.6.6, 1.2.3.4", UserAgent: "ua"},
			wantXFF: "6.6.6.6, 1.2.3.4", wantRealIP: "6.6.6.6", wantUA: "ua",
		},
		{
			name:    "empty IP sets no XFF",
			attr:    &socrate.ClientAttribution{UserAgent: "ua"},
			wantXFF: "6.6.6.6, 1.2.3.4", wantRealIP: "6.6.6.6", wantUA: "ua",
		},
		{
			name:    "UA control characters and invalid UTF-8 stripped",
			attr:    &socrate.ClientAttribution{IP: "198.51.100.1", UserAgent: "evil\r\nX-Injected: 1\x00\x7f\u0085\xff ua"},
			wantXFF: "198.51.100.1", wantUA: "evilX-Injected: 1 ua",
		},
		{
			name:    "UA truncated on a rune boundary",
			attr:    &socrate.ClientAttribution{IP: "198.51.100.1", UserAgent: longUA},
			wantXFF: "198.51.100.1", wantUA: strings.Repeat("é", 256), checkUASize: true,
		},
		{
			name:    "UA made only of control characters leaves UA alone",
			attr:    &socrate.ClientAttribution{IP: "198.51.100.1", UserAgent: "\r\n\t"},
			wantXFF: "198.51.100.1", wantUA: "existing-ua",
		},
		{
			name:    "no attribution leaves headers untouched",
			attr:    nil,
			wantXFF: "6.6.6.6, 1.2.3.4", wantRealIP: "6.6.6.6", wantUA: "existing-ua",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newAttributedRequest(t, tt.attr)
			socrate.ApplyClientAttribution(req)
			if got := req.Header.Values("X-Forwarded-For"); len(got) != 1 || got[0] != tt.wantXFF {
				t.Errorf("X-Forwarded-For = %q, want exactly [%q]", got, tt.wantXFF)
			}
			if got := req.Header.Get("X-Real-IP"); got != tt.wantRealIP {
				t.Errorf("X-Real-IP = %q, want %q", got, tt.wantRealIP)
			}
			got := req.Header.Get("User-Agent")
			if got != tt.wantUA {
				t.Errorf("User-Agent = %q, want %q", got, tt.wantUA)
			}
			if tt.checkUASize && (len(got) > 512 || !utf8.ValidString(got)) {
				t.Errorf("User-Agent is %d bytes (valid UTF-8: %v), want <= 512 and valid", len(got), utf8.ValidString(got))
			}
		})
	}
}

func TestApplyClientAttributionNilRequest(_ *testing.T) {
	socrate.ApplyClientAttribution(nil) // must not panic
}

// seenRequest is what the fake Socrate observed for one request.
type seenRequest struct {
	xff, realIP, ua string
	hasXFF          bool
}

// attributionServer is a fake Socrate recording the attribution headers of
// every request, per path.
type attributionServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen map[string][]seenRequest
}

func newAttributionServer(t *testing.T) *attributionServer {
	t.Helper()
	s := &attributionServer{seen: map[string][]seenRequest{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		key := r.URL.Path
		if gt := r.PostForm.Get("grant_type"); gt != "" {
			key += "#" + gt
		}
		_, hasXFF := r.Header["X-Forwarded-For"]
		s.mu.Lock()
		s.seen[key] = append(s.seen[key], seenRequest{
			xff: r.Header.Get("X-Forwarded-For"), realIP: r.Header.Get("X-Real-IP"),
			ua: r.Header.Get("User-Agent"), hasXFF: hasXFF,
		})
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "refresh_token": "rt", "token_type": "Bearer", "expires_in": 3600})
		case "/oauth/revoke", "/api/auth/logout":
			w.WriteHeader(http.StatusOK)
		case "/api/auth/magic-link/verify", "/api/admin/login":
			_ = json.NewEncoder(w).Encode(socrate.LoginResult{AccessToken: "at", UserID: 7})
		case "/oauth/userinfo":
			_ = json.NewEncoder(w).Encode(socrate.ProfileInfo{Sub: "7"})
		case "/oauth/introspect":
			_ = json.NewEncoder(w).Encode(socrate.IntrospectResponse{Active: true})
		case "/api/apps/42/users/7":
			_ = json.NewEncoder(w).Encode(socrate.User{ID: 7})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *attributionServer) last(t *testing.T, key string) seenRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	reqs := s.seen[key]
	if len(reqs) == 0 {
		t.Fatalf("fake Socrate saw no request for %s", key)
	}
	return reqs[len(reqs)-1]
}

func (s *attributionServer) client(t *testing.T) *socrate.Client {
	t.Helper()
	c, err := socrate.NewClient(socrate.ClientConfig{
		BaseURL: s.URL, AdminBaseURL: s.URL, ClientID: "bff", ClientSecret: "test-secret", AppID: "42",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var browser = socrate.ClientAttribution{IP: "203.0.113.7", UserAgent: "Mozilla/5.0 (Browser)"}

// onBehalfCalls are the Client calls made on a user's behalf; each must carry
// the attribution when the context has one.
var onBehalfCalls = []struct {
	name, key string
	call      func(ctx context.Context, c *socrate.Client) error
}{
	{"ExchangeCode", "/oauth/token#authorization_code", func(ctx context.Context, c *socrate.Client) error {
		_, err := c.ExchangeCode(ctx, "code", "https://bff.example/cb", "verifier")
		return err
	}},
	{"RefreshToken", "/oauth/token#refresh_token", func(ctx context.Context, c *socrate.Client) error {
		_, err := c.RefreshToken(ctx, "rt")
		return err
	}},
	{"RevokeToken", "/oauth/revoke", func(ctx context.Context, c *socrate.Client) error {
		return c.RevokeToken(ctx, "rt")
	}},
	{"VerifyMagicLink", "/api/auth/magic-link/verify", func(ctx context.Context, c *socrate.Client) error {
		_, err := c.VerifyMagicLink(ctx, "ml-token")
		return err
	}},
	{"AdminLogin", "/api/admin/login", func(ctx context.Context, c *socrate.Client) error {
		_, err := c.AdminLogin(ctx, "admin@example.com", "pw")
		return err
	}},
	{"Logout", "/api/auth/logout", func(ctx context.Context, c *socrate.Client) error {
		return c.Logout(socrate.WithJWT(ctx, "user-jwt"))
	}},
}

func TestOnBehalfCallsSendAttribution(t *testing.T) {
	for _, tc := range onBehalfCalls {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAttributionServer(t)
			ctx := socrate.WithClientAttribution(context.Background(), browser)
			if err := tc.call(ctx, srv.client(t)); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			got := srv.last(t, tc.key)
			if got.xff != browser.IP {
				t.Errorf("X-Forwarded-For = %q, want %q", got.xff, browser.IP)
			}
			if got.ua != browser.UserAgent {
				t.Errorf("User-Agent = %q, want %q", got.ua, browser.UserAgent)
			}
		})
	}
}

func TestOnBehalfCallsUnchangedWithoutAttribution(t *testing.T) {
	for _, tc := range onBehalfCalls {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAttributionServer(t)
			if err := tc.call(context.Background(), srv.client(t)); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			got := srv.last(t, tc.key)
			if got.hasXFF {
				t.Errorf("X-Forwarded-For sent without attribution: %q", got.xff)
			}
			if got.ua != "Go-http-client/1.1" {
				t.Errorf("User-Agent = %q, want Go's default", got.ua)
			}
		})
	}
}

// TestNonUserCallsNeverSendAttribution: the client_credentials grant (no
// browser; the token is cached and shared), token introspection and userinfo
// (the backend checking a token, not a browser action) never carry it, even
// when the context does.
func TestNonUserCallsNeverSendAttribution(t *testing.T) {
	srv := newAttributionServer(t)
	c := srv.client(t)
	ctx := socrate.WithClientAttribution(socrate.WithJWT(context.Background(), "user-jwt"), browser)

	if _, err := c.GetUserAsService(ctx, "7"); err != nil {
		t.Fatalf("GetUserAsService: %v", err)
	}
	if _, err := c.IntrospectToken(ctx, "at"); err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if _, err := c.GetCurrentUserProfile(ctx); err != nil {
		t.Fatalf("GetCurrentUserProfile: %v", err)
	}
	for _, key := range []string{"/oauth/token#client_credentials", "/api/apps/42/users/7", "/oauth/introspect", "/oauth/userinfo"} {
		got := srv.last(t, key)
		if got.hasXFF || got.ua != "Go-http-client/1.1" {
			t.Errorf("%s carried attribution: XFF=%q UA=%q", key, got.xff, got.ua)
		}
	}
}
