package httpware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/httpware"
)

// keyedLimiter builds a limiter whose buckets never refill during a test
// (a tiny rate), so the burst alone decides how many requests pass.
func keyedLimiter(t *testing.T, cfg httpware.KeyedRateLimiterConfig) http.Handler {
	t.Helper()
	if cfg.RPS == 0 {
		cfg.RPS = 0.001
	}
	rl, err := httpware.NewKeyedRateLimiter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rl.Stop)
	return rl.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
}

type reqOpt func(*http.Request) *http.Request

func withTenant(id uuid.UUID) reqOpt {
	return func(r *http.Request) *http.Request { return r.WithContext(ctxutil.WithTenantID(r.Context(), id)) }
}

func withSub(sub string) reqOpt {
	return func(r *http.Request) *http.Request { return r.WithContext(ctxutil.WithUserSub(r.Context(), sub)) }
}

func fromAddr(addr string) reqOpt {
	return func(r *http.Request) *http.Request { r.RemoteAddr = addr; return r }
}

// passes sends n requests and returns how many got 200.
func passes(h http.Handler, n int, opts ...reqOpt) int {
	ok := 0
	for range n {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, o := range opts {
			r = o(r)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == http.StatusOK {
			ok++
		}
	}
	return ok
}

func TestKeyedRateLimiter_TenantThenSubjectThenAddress(t *testing.T) {
	h := keyedLimiter(t, httpware.KeyedRateLimiterConfig{Burst: 3, AnonymousBurst: 1})
	a, b := uuid.New(), uuid.New()

	if got := passes(h, 5, withTenant(a)); got != 3 {
		t.Errorf("tenant a: %d passed, want 3", got)
	}
	if got := passes(h, 5, withTenant(b)); got != 3 {
		t.Errorf("tenant b has its own bucket: %d passed, want 3", got)
	}
	// A tenant wins over the subject: same tenant, other subjects, still exhausted.
	if got := passes(h, 2, withTenant(a), withSub("42")); got != 0 {
		t.Errorf("tenant a with a subject: %d passed, want 0", got)
	}
	// No tenant: the subject is the key (a service account is no longer unlimited).
	if got := passes(h, 5, withSub("app:7")); got != 3 {
		t.Errorf("subject app:7: %d passed, want 3", got)
	}
	// Neither: the smaller anonymous bucket of the client address.
	if got := passes(h, 5, fromAddr("198.51.100.1:5000")); got != 1 {
		t.Errorf("anonymous 198.51.100.1: %d passed, want 1", got)
	}
	if got := passes(h, 5, fromAddr("198.51.100.2:5000")); got != 1 {
		t.Errorf("anonymous 198.51.100.2 has its own bucket: %d passed, want 1", got)
	}
}

// The tier prefixes keep keys apart: a subject spelled like a tenant id does
// not share the tenant's bucket.
func TestKeyedRateLimiter_TiersDoNotShareBuckets(t *testing.T) {
	h := keyedLimiter(t, httpware.KeyedRateLimiterConfig{Burst: 1})
	id := uuid.New()
	if got := passes(h, 1, withTenant(id)); got != 1 {
		t.Fatalf("tenant: %d", got)
	}
	if got := passes(h, 1, withSub(id.String())); got != 1 {
		t.Errorf("a subject equal to the tenant id shared its bucket")
	}
}

func TestKeyedRateLimiter_IPv6GroupedBy64(t *testing.T) {
	h := keyedLimiter(t, httpware.KeyedRateLimiterConfig{Burst: 10, AnonymousBurst: 2})
	if got := passes(h, 1, fromAddr("[2001:db8:1:2::1]:443")) + passes(h, 3, fromAddr("[2001:db8:1:2:ffff::9]:443")); got != 2 {
		t.Errorf("same /64: %d passed in total, want 2 (one shared bucket)", got)
	}
	if got := passes(h, 3, fromAddr("[2001:db8:1:3::1]:443")); got != 2 {
		t.Errorf("another /64: %d passed, want its own 2", got)
	}
}

func TestKeyedRateLimiter_ClientIPFunc(t *testing.T) {
	h := keyedLimiter(t, httpware.KeyedRateLimiterConfig{Burst: 10, AnonymousBurst: 1,
		ClientIP: func(r *http.Request) string { return r.Header.Get("X-Test-Client") }})
	ip := func(v string) reqOpt {
		return func(r *http.Request) *http.Request { r.Header.Set("X-Test-Client", v); return r }
	}
	// All from the same proxy peer, but distinct clients per the trusted function.
	if got := passes(h, 2, fromAddr("127.0.0.1:1"), ip("203.0.113.1")) + passes(h, 2, fromAddr("127.0.0.1:1"), ip("203.0.113.2")); got != 2 {
		t.Errorf("%d passed, want one per client", got)
	}
}

func TestKeyedRateLimiter_AnonymousCap(t *testing.T) {
	h := keyedLimiter(t, httpware.KeyedRateLimiterConfig{Burst: 5, AnonymousBurst: 5, MaxAnonymousKeys: 2})
	passes(h, 1, fromAddr("192.0.2.1:1"))
	passes(h, 1, fromAddr("192.0.2.2:1"))
	if got := passes(h, 1, fromAddr("192.0.2.3:1")); got != 0 {
		t.Errorf("a third address beyond the cap passed")
	}
	if got := passes(h, 1, fromAddr("192.0.2.1:1")); got != 1 {
		t.Errorf("a known address must still be served")
	}
	if got := passes(h, 1, withSub("app:9")); got != 1 {
		t.Errorf("authenticated keys must never be refused for the anonymous cap")
	}
}

func TestKeyedRateLimiter_RetryAfter(t *testing.T) {
	for _, c := range []struct {
		rps  float64
		want string
	}{{1, "1"}, {0.1, "10"}, {0.5, "2"}} {
		h := keyedLimiter(t, httpware.KeyedRateLimiterConfig{RPS: c.rps, Burst: 1})
		r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctxutil.WithUserSub(t.Context(), "s"))
		h.ServeHTTP(httptest.NewRecorder(), r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != c.want {
			t.Errorf("rps %v: %d Retry-After %q, want 429 and %q", c.rps, w.Code, w.Header().Get("Retry-After"), c.want)
		}
	}
}

func TestNewKeyedRateLimiter_Validation(t *testing.T) {
	for _, cfg := range []httpware.KeyedRateLimiterConfig{
		{RPS: 0, Burst: 1},
		{RPS: 1, Burst: 0},
		{RPS: 1, Burst: 1, AnonymousRPS: -1},
		{RPS: 1, Burst: 1, MaxAnonymousKeys: -1},
	} {
		if rl, err := httpware.NewKeyedRateLimiter(cfg); err == nil {
			rl.Stop()
			t.Errorf("%+v: want an error", cfg)
		}
	}
}

// Idle address buckets expire and free their place under the cap.
func TestKeyedRateLimiter_IdleBucketsFreeTheCap(t *testing.T) {
	h := keyedLimiter(t, httpware.KeyedRateLimiterConfig{Burst: 1, AnonymousBurst: 1, MaxAnonymousKeys: 1, IdleTTL: 20 * time.Millisecond})
	if got := passes(h, 1, fromAddr("192.0.2.1:1")); got != 1 {
		t.Fatal("first address refused")
	}
	if got := passes(h, 1, fromAddr("192.0.2.2:1")); got != 0 {
		t.Fatal("second address passed while the cap is full")
	}
	deadline := time.Now().Add(2 * time.Second)
	for passes(h, 1, fromAddr("192.0.2.2:1")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the idle bucket never expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
