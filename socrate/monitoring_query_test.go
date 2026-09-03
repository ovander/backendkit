package socrate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ovander/backendkit/socrate"
)

// P2-10: query-string values must be encoded, not concatenated. A
// caller-supplied period of "24h&period=9999d&x=1" previously reached the
// server as three parameters, and "7d#frag" silently truncated the query.
func TestMonitoringQueryStringsAreEncoded(t *testing.T) {
	var gotQuery url.Values
	mux := http.NewServeMux()
	record := func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}
	mux.HandleFunc("/api/admin/security/geo", record)
	mux.HandleFunc("/api/admin/tokens/stats", record)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      srv.URL,
		AdminBaseURL: srv.URL,
		ClientID:     "test-client",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := socrate.WithJWT(context.Background(), "admin-tok")

	if _, err := c.GetGeoAnalytics(ctx, "24h&period=9999d&injected=1"); err != nil {
		t.Fatalf("GetGeoAnalytics: %v", err)
	}
	if got := gotQuery["period"]; len(got) != 1 || got[0] != "24h&period=9999d&injected=1" {
		t.Fatalf("period reached server as %v; injection not neutralised", got)
	}
	if _, ok := gotQuery["injected"]; ok {
		t.Fatal("injected parameter reached the server")
	}

	if _, err := c.GetTokenStats(ctx, "7d#frag"); err != nil {
		t.Fatalf("GetTokenStats: %v", err)
	}
	if got := gotQuery.Get("period"); got != "7d#frag" {
		t.Fatalf("period with '#' reached server as %q (truncated?)", got)
	}
}
