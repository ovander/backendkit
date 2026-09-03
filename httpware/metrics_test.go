package httpware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics_LabelsByPatternNotPath(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/users/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := Metrics("admin-bff")(mux)
	for _, id := range []string{"1", "2", "secret-token-value"} {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/admin/users/"+id, nil))
	}
	if got := testutil.ToFloat64(httpRequests.WithLabelValues("admin-bff", "GET /api/admin/users/{id}", "GET", "4xx")); got != 3 {
		t.Fatalf("pattern counter = %v, want 3", got)
	}
	rr := httptest.NewRecorder()
	MetricsHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(rr.Body.String(), "secret-token-value") {
		t.Fatal("raw path leaked into the exposition")
	}
	// A 404 is "unmatched".
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/nope", nil))
	if got := testutil.ToFloat64(httpRequests.WithLabelValues("admin-bff", "unmatched", "GET", "4xx")); got < 1 {
		t.Fatalf("unmatched counter = %v", got)
	}
}

func TestMetrics_PreservesFlusher(t *testing.T) {
	var flushed bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("Flusher lost through the metrics wrapper")
		}
		fl.Flush()
		flushed = true
	})
	Metrics("x")(inner).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !flushed {
		t.Fatal("flush not called")
	}
}
