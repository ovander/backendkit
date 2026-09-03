package httpware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RED metrics for every backendkit-based service (BFFs, apps), aligned with
// Socrate's own catalogue so one Grafana dashboard covers the suite. Labels are
// bounded: the matched route PATTERN (Go 1.22 ServeMux `r.Pattern`, e.g.
// "GET /api/admin/", or "unmatched"), the method and the status class. Never
// the raw path — it carries ids, emails and tokens.
var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "backendkit", Subsystem: "http", Name: "requests_total",
		Help: "HTTP requests by service, route pattern, method and status class.",
	}, []string{"service", "route", "method", "status"})
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "backendkit", Subsystem: "http", Name: "request_duration_seconds",
		Help:    "HTTP request latency by service, route pattern and method.",
		Buckets: []float64{.005, .01, .025, .05, .1, .15, .25, .5, 1, 2.5, 5},
	}, []string{"service", "route", "method"})
)

// Metrics returns the RED middleware for the named service. Mount it first
// (before auth, CSRF and rate limiting) so refused requests are counted too.
// Streaming responses (SSE) keep working: the wrapper forwards Flush.
func Metrics(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sr := &flushRecorder{statusRecorder: statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}}
			next.ServeHTTP(sr, r)
			route := RoutePattern(r)
			httpRequests.WithLabelValues(service, route, r.Method, strconv.Itoa(sr.statusCode/100)+"xx").Inc()
			httpDuration.WithLabelValues(service, route, r.Method).Observe(time.Since(start).Seconds())
		})
	}
}

// MetricsHandler serves the Prometheus exposition. Mount it on a loopback
// listener or an admin-only route — never on a public host.
func MetricsHandler() http.Handler { return promhttp.Handler() }

// RoutePattern returns the ServeMux pattern that matched r (Go 1.22+), or
// "unmatched" when the request fell through to a 404 or no mux set it.
func RoutePattern(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return "unmatched"
}

// flushRecorder keeps http.Flusher available through the status recorder so
// SSE and other streaming handlers are unaffected by instrumentation.
type flushRecorder struct {
	statusRecorder
}

func (f *flushRecorder) Flush() {
	if fl, ok := f.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}
