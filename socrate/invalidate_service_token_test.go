package socrate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ovander/backendkit/socrate"
)

// rotatingTokenServer issues tok-1, tok-2, … on successive exchanges.
func rotatingTokenServer(t *testing.T) (*socrate.Client, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		i := n.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("tok-%d", i), "expires_in": 3600, "token_type": "Bearer"})
	})
	srv, closeFn := newTestServer(mux)
	t.Cleanup(closeFn)
	c, err := socrate.NewClient(socrate.ClientConfig{BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "cid", ClientSecret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	return c, &n
}

func TestInvalidateServiceToken_NextCallExchangesANewToken(t *testing.T) {
	c, n := rotatingTokenServer(t)
	ctx := context.Background()

	first, _, err := c.ServiceToken(ctx)
	if err != nil || first != "tok-1" {
		t.Fatalf("ServiceToken = %q, %v", first, err)
	}
	if again, _, _ := c.ServiceToken(ctx); again != first || n.Load() != 1 {
		t.Fatalf("before invalidation the cached token is returned: got %q after %d exchanges", again, n.Load())
	}

	c.InvalidateServiceToken()
	second, _, err := c.ServiceToken(ctx)
	if err != nil || second != "tok-2" || n.Load() != 2 {
		t.Fatalf("after invalidation: %q, %v, %d exchanges; want tok-2 from a second exchange", second, err, n.Load())
	}
	if again, _, _ := c.ServiceToken(ctx); again != second || n.Load() != 2 {
		t.Errorf("the new token is cached: got %q after %d exchanges", again, n.Load())
	}
}

func TestInvalidateServiceToken_NothingCached(t *testing.T) {
	c, n := rotatingTokenServer(t)
	c.InvalidateServiceToken()
	if tok, _, err := c.ServiceToken(context.Background()); err != nil || tok != "tok-1" || n.Load() != 1 {
		t.Errorf("ServiceToken = %q, %v after %d exchanges; want tok-1 from one exchange", tok, err, n.Load())
	}
}

func TestInvalidateServiceToken_ConcurrentWithServiceToken(t *testing.T) {
	c, _ := rotatingTokenServer(t)
	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%4 == 0 {
				c.InvalidateServiceToken()
				return
			}
			if tok, _, err := c.ServiceToken(context.Background()); err != nil || tok == "" {
				t.Errorf("ServiceToken = %q, %v", tok, err)
			}
		}()
	}
	wg.Wait()
}
