package socrate_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/socrate"
)

// correlationServer answers every Socrate route the client calls and records
// the X-Correlation-ID each request carried, by method and path.
func correlationServer(t *testing.T) (*socrate.Client, func() map[string]string) {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]string{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Method+" "+r.URL.Path] = r.Header.Get("X-Correlation-ID")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "refresh_token": "rt", "expires_in": 3600, "token_type": "Bearer"})
		case r.URL.Path == "/oauth/introspect":
			_, _ = w.Write([]byte(`{"active":true}`))
		case strings.HasSuffix(r.URL.Path, "/policy/decide"):
			_, _ = w.Write([]byte(`{"decision":{"allow":true},"mode":"enforce"}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	})
	srv, closeFn := newTestServer(http.NewServeMux())
	srv.Config.Handler = h
	t.Cleanup(closeFn)
	c, err := socrate.NewClient(socrate.ClientConfig{BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "cid", ClientSecret: "s3cret", AppID: "7"})
	if err != nil {
		t.Fatal(err)
	}
	return c, func() map[string]string {
		mu.Lock()
		defer mu.Unlock()
		out := make(map[string]string, len(seen))
		for k, v := range seen {
			out[k] = v
		}
		return out
	}
}

// callEverything makes one call down every request path of the client.
// Responses are minimal, so decoding errors are ignored: only the requests matter.
func callEverything(ctx context.Context, c *socrate.Client) {
	ctx = socrate.WithJWT(ctx, "user-jwt")
	_, _ = c.ExchangeCode(ctx, "code", "https://app.example/cb", "verifier") // postForm
	_, _ = c.RefreshToken(ctx, "rt")                                         // postForm
	_, _ = c.VerifyMagicLink(ctx, "ml")                                      // doHTTPNoAuth
	_ = c.Logout(ctx)                                                        // its own request
	_, _ = c.GetCurrentUserProfile(ctx)                                      // doHTTP with the user JWT
	_, _ = c.GetUserAsService(ctx, "42")                                     // ServiceToken, then doHTTP
	_ = c.RevokeToken(ctx, "tok")                                            // its own request
	_, _ = c.IntrospectToken(ctx, "tok")                                     // its own request
	_, _ = c.Decide(ctx, socrate.DecideRequest{Action: "read"})              // its own request
}

func TestCorrelationID_ForwardedOnEveryPath(t *testing.T) {
	c, seen := correlationServer(t)
	callEverything(ctxutil.WithRequestID(context.Background(), "req-123"), c)

	got := seen()
	for _, path := range []string{
		"POST /oauth/token", "POST /api/auth/magic-link/verify", "POST /api/auth/logout",
		"POST /oauth/revoke", "POST /oauth/introspect", "POST /api/apps/7/service/policy/decide",
	} {
		if v, ok := got[path]; !ok {
			t.Errorf("%s was not called", path)
		} else if v != "req-123" {
			t.Errorf("%s carried X-Correlation-ID %q, want req-123", path, v)
		}
	}
	if len(got) < 8 {
		t.Errorf("only %d distinct requests seen, want every path: %v", len(got), got)
	}
	for path, v := range got {
		if v != "req-123" {
			t.Errorf("%s carried X-Correlation-ID %q, want req-123", path, v)
		}
	}
}

func TestCorrelationID_NotSentWithoutAValidID(t *testing.T) {
	for name, id := range map[string]string{
		"absent":    "",
		"too long":  strings.Repeat("a", 129),
		"space":     "a b",
		"non-ASCII": "é",
	} {
		t.Run(name, func(t *testing.T) {
			c, seen := correlationServer(t)
			ctx := context.Background()
			if id != "" {
				ctx = ctxutil.WithRequestID(ctx, id)
			}
			callEverything(ctx, c)
			got := seen()
			if len(got) == 0 {
				t.Fatal("no request reached the server: an unusable id must not fail the call")
			}
			for path, v := range got {
				if v != "" {
					t.Errorf("%s carried X-Correlation-ID %q, want none", path, v)
				}
			}
		})
	}
}
