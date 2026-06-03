package httpware

import (
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/ovander/backendkit/apierror"
	"github.com/ovander/backendkit/ctxutil"
)

const (
	// rateLimiterTTL is the idle duration after which a per-tenant limiter entry
	// is evicted from the in-memory map. A tenant that has been quiet for this
	// long will have its bucket removed, reclaiming memory. The next request
	// from that tenant starts a fresh, full bucket.
	rateLimiterTTL = 10 * time.Minute

	// rateLimiterCleanupInterval controls how often the background goroutine
	// sweeps the map for stale entries. Must be shorter than rateLimiterTTL.
	rateLimiterCleanupInterval = 2 * time.Minute
)

// tenantLimiter pairs a token-bucket limiter with the last-seen timestamp
// used for TTL-based eviction.
type tenantLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter provides per-tenant token-bucket rate limiting with automatic
// memory reclamation for idle tenants. Peak memory is bounded to roughly
// (active-tenant-count × 200 bytes) because entries are evicted after
// rateLimiterTTL of inactivity.
//
// Must be placed after the auth middleware so that the tenant UUID is
// already present in the request context.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[uuid.UUID]*tenantLimiter
	rps      rate.Limit
	burst    int
	stop     chan struct{}
}

// NewRateLimiter creates a RateLimiter for rps requests/second with the given
// burst size and starts the background cleanup goroutine.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[uuid.UUID]*tenantLimiter),
		rps:      rate.Limit(rps),
		burst:    burst,
		stop:     make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Stop shuts down the background cleanup goroutine. Call during graceful
// shutdown when the limiter outlives individual requests.
func (rl *RateLimiter) Stop() {
	close(rl.stop)
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rateLimiterCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.evictStale()
		case <-rl.stop:
			return
		}
	}
}

func (rl *RateLimiter) evictStale() {
	cutoff := time.Now().Add(-rateLimiterTTL)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for id, tl := range rl.limiters {
		if tl.lastSeen.Before(cutoff) {
			delete(rl.limiters, id)
		}
	}
}

func (rl *RateLimiter) getLimiter(tenantID uuid.UUID) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	tl, ok := rl.limiters[tenantID]
	if !ok {
		tl = &tenantLimiter{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.limiters[tenantID] = tl
	}
	tl.lastSeen = time.Now()
	return tl.limiter
}

// Handler returns the http.Handler middleware. Requests without a tenant ID in
// context are let through; auth middleware is expected to reject them upstream.
func (rl *RateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := ctxutil.GetTenantID(r.Context())
		if tenantID == uuid.Nil {
			next.ServeHTTP(w, r)
			return
		}

		if !rl.getLimiter(tenantID).Allow() {
			w.Header().Set("Retry-After", "1")
			// "rate_limited" is a deliberately specific code (kept stable for
			// wire compatibility); routed through apierror so the JSON envelope
			// stays single-sourced with the rest of the library.
			(&apierror.AppError{
				Code:       "rate_limited",
				StatusCode: http.StatusTooManyRequests,
				Message:    "too many requests",
			}).WriteJSON(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}
