package socrate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/backendkit/socrate"
)

// TestRevokeUserTokens_EscapesUserIDInPath verifies that admin.go now percent-
// encodes the caller-supplied userID segment (audit M-1 / F-7), so a value like
// "42/revoke-tokens" cannot inject an extra path segment.
func TestRevokeUserTokens_EscapesUserIDInPath(t *testing.T) {
	var gotURI string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      srv.URL,
		AdminBaseURL: srv.URL,
		ClientID:     "cid",
	})
	ctx := socrate.WithJWT(context.Background(), "admin-tok")

	if err := c.RevokeUserTokens(ctx, "42/revoke-tokens"); err != nil {
		t.Fatalf("RevokeUserTokens: %v", err)
	}
	if !strings.Contains(gotURI, "42%2Frevoke-tokens") {
		t.Errorf("userID not path-escaped; request URI = %q", gotURI)
	}
	if strings.Contains(gotURI, "users/42/revoke-tokens/revoke-tokens") {
		t.Errorf("path-segment injection not prevented; request URI = %q", gotURI)
	}
}
