package socrate_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ovander/backendkit/socrate"
)

// tokenServer answers /oauth/token with tok and expiresIn, counting exchanges.
func tokenServer(t *testing.T, tok string, expiresIn int, status int) (*socrate.Client, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" ||
			r.PostForm.Get("client_id") != "cid" || r.PostForm.Get("client_secret") != "s3cret" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "expires_in": expiresIn, "token_type": "Bearer"})
	})
	srv, closeFn := newTestServer(mux)
	t.Cleanup(closeFn)
	c, err := socrate.NewClient(socrate.ClientConfig{BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "cid", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	return c, &n
}

func TestServiceToken_ReturnsTokenAndExpiry(t *testing.T) {
	c, n := tokenServer(t, "svc-tok", 3600, http.StatusOK)
	before := time.Now()
	tok, exp, err := c.ServiceToken(context.Background())
	if err != nil || tok != "svc-tok" {
		t.Fatalf("ServiceToken = %q, %v", tok, err)
	}
	if exp.Before(before.Add(59*time.Minute)) || exp.After(time.Now().Add(time.Hour)) {
		t.Errorf("expiry %v, want about one hour from now", exp)
	}
	// Cached: a second call makes no exchange and returns the same expiry.
	tok2, exp2, err := c.ServiceToken(context.Background())
	if err != nil || tok2 != tok || !exp2.Equal(exp) || n.Load() != 1 {
		t.Errorf("second call: %q %v %v, %d exchanges", tok2, exp2, err, n.Load())
	}
}

func TestServiceToken_ConcurrentCallersShareOneExchange(t *testing.T) {
	c, n := tokenServer(t, "svc-tok", 3600, http.StatusOK)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tok, _, err := c.ServiceToken(context.Background()); err != nil || tok != "svc-tok" {
				t.Errorf("ServiceToken = %q, %v", tok, err)
			}
		}()
	}
	wg.Wait()
	if n.Load() != 1 {
		t.Errorf("%d exchanges, want 1", n.Load())
	}
}

func TestServiceToken_RefreshesNearExpiry(t *testing.T) {
	// A token valid less than 30 s is exchanged again on every call.
	c, n := tokenServer(t, "short", 10, http.StatusOK)
	for range 2 {
		if _, _, err := c.ServiceToken(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n.Load() != 2 {
		t.Errorf("%d exchanges, want 2", n.Load())
	}
}

func TestServiceToken_Errors(t *testing.T) {
	c, _ := tokenServer(t, "svc-tok", 3600, http.StatusUnauthorized)
	tok, exp, err := c.ServiceToken(context.Background())
	if err == nil || tok != "" || !exp.IsZero() || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("rejected exchange: %q %v %v", tok, exp, err)
	}

	c, _ = tokenServer(t, "", 3600, http.StatusOK)
	if tok, _, err := c.ServiceToken(context.Background()); err == nil || tok != "" {
		t.Errorf("empty access_token accepted: %q %v", tok, err)
	}

	noSecret, err := socrate.NewClient(socrate.ClientConfig{BaseURL: "http://127.0.0.1:1", ClientID: "cid"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := noSecret.ServiceToken(context.Background()); err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("no secret: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, _ = tokenServer(t, "svc-tok", 3600, http.StatusOK)
	if _, _, err := c.ServiceToken(ctx); err == nil {
		t.Error("cancelled context: no error")
	}
}
