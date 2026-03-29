package httpware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/httpware"
)

func tenantRequest(tenantID uuid.UUID) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := ctxutil.WithTenantID(r.Context(), tenantID)
	return r.WithContext(ctx)
}

func TestRateLimiter_AllowsWithinBurst(t *testing.T) {
	rl := httpware.NewRateLimiter(10, 5)
	defer rl.Stop()

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := rl.Handler(ok)

	tid := uuid.New()
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, tenantRequest(tid))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, w.Code)
		}
	}
}

func TestRateLimiter_RejectsWhenExhausted(t *testing.T) {
	// burst=1 means a second immediate request should be rejected.
	rl := httpware.NewRateLimiter(0.001, 1)
	defer rl.Stop()

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := rl.Handler(ok)

	tid := uuid.New()
	// First request drains the single token.
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, tenantRequest(tid))

	// Second request should be rate-limited.
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, tenantRequest(tid))
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w2.Code)
	}
}

func TestRateLimiter_PassthroughWithNoTenant(t *testing.T) {
	rl := httpware.NewRateLimiter(0.001, 1)
	defer rl.Stop()

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := rl.Handler(ok)

	// No tenant in context — must be let through.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for request without tenant, got %d", w.Code)
	}
}

func TestRateLimiter_IsolatesTenantsPerBucket(t *testing.T) {
	rl := httpware.NewRateLimiter(0.001, 1)
	defer rl.Stop()

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := rl.Handler(ok)

	t1, t2 := uuid.New(), uuid.New()

	// Drain t1's bucket.
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, tenantRequest(t1))

	// t2 should still have a full bucket.
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, tenantRequest(t2))
	if w2.Code != http.StatusOK {
		t.Errorf("t2 should not be rate-limited, got %d", w2.Code)
	}
}
