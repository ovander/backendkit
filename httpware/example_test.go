package httpware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/httpware"
)

// ExampleTimeout demonstrates wrapping a handler with a per-route deadline.
// Inner routes can safely declare a longer timeout than the global default
// because Timeout uses context.WithoutCancel to strip any existing deadline
// before applying the new one.
func ExampleTimeout() {
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(50 * time.Millisecond):
			fmt.Fprintln(w, "done")
		case <-r.Context().Done():
			http.Error(w, "timeout", http.StatusGatewayTimeout)
		}
	})

	handler := httpware.Timeout(200 * time.Millisecond)(slow)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	fmt.Println(rec.Code)
	// Output:
	// 200
}

// ExampleNewRateLimiter demonstrates per-tenant rate limiting.
// The middleware passes requests through when no tenant is in context
// (e.g., during unauthenticated health-check endpoints).
func ExampleNewRateLimiter() {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rl := httpware.NewRateLimiter(10, 20) // 10 rps, burst 20
	defer rl.Stop()

	handler := rl.Handler(next)

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	// No tenant in context → middleware passes through unconditionally.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	fmt.Println(rec.Code)
	// Output:
	// 200
}

// ExampleNewRBAC demonstrates defining application-level permissions and
// wiring them into the RBAC middleware.
func ExampleNewRBAC() {
	const (
		PermRead  httpware.Permission = "read:report"
		PermWrite httpware.Permission = "write:report"
	)

	logger := logrus.NewEntry(logrus.New())

	rbac := httpware.NewRBAC(httpware.RoleMap{
		"viewer": {PermRead},
		"editor": {PermRead, PermWrite},
	}, logger)

	protected := rbac.Require(PermWrite)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))

	// Simulate a viewer (no write permission).
	req := httptest.NewRequest(http.MethodPost, "/report", nil)
	req = req.WithContext(ctxutil.WithUserRole(req.Context(), "viewer"))
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)
	fmt.Println(rec.Code)

	// Simulate an editor (has write permission).
	req2 := httptest.NewRequest(http.MethodPost, "/report", nil)
	req2 = req2.WithContext(ctxutil.WithUserRole(req2.Context(), "editor"))
	rec2 := httptest.NewRecorder()
	protected.ServeHTTP(rec2, req2)
	fmt.Println(rec2.Code)

	// Output:
	// 403
	// 200
}

// ExampleRequestID demonstrates the RequestID middleware generating a
// UUID when no X-Request-ID header is present in the incoming request.
func ExampleRequestID() {
	var capturedID string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = ctxutil.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := httpware.RequestID(next)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	fmt.Println(len(capturedID) > 0)
	// Output:
	// true
}

// ExampleSecurityHeaders demonstrates the security headers middleware setting
// standard defensive headers on every response.
func ExampleSecurityHeaders() {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := httpware.SecurityHeaders(next)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	fmt.Println(rec.Header().Get("X-Content-Type-Options"))
	fmt.Println(rec.Header().Get("X-Frame-Options"))
	// Output:
	// nosniff
	// DENY
}
