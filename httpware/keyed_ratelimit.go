package httpware

import (
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/ovander/backendkit/apierror"
	"github.com/ovander/backendkit/ctxutil"
)

// DefaultMaxAnonymousKeys bounds the number of client-address buckets a
// KeyedRateLimiter keeps when KeyedRateLimiterConfig.MaxAnonymousKeys is zero.
const DefaultMaxAnonymousKeys = 10000

// KeyedRateLimiterConfig configures NewKeyedRateLimiter.
type KeyedRateLimiterConfig struct {
	// RPS and Burst are the token bucket of each authenticated key: a tenant,
	// or a subject when the request has no tenant. Both are required.
	RPS   float64
	Burst int
	// AnonymousRPS and AnonymousBurst are the bucket of each client address,
	// used when the request has neither a tenant nor a subject. Keep them
	// smaller than RPS and Burst, so an unauthenticated flood never competes
	// with real traffic. Zero defaults to a tenth of RPS and of Burst (at
	// least one request).
	AnonymousRPS   float64
	AnonymousBurst int
	// ClientIP returns the address of the client behind a request. Behind a
	// reverse proxy, pass a function that honours X-Forwarded-For only from
	// the trusted proxies: trusting it blindly lets a client pick a new
	// bucket for every request. Nil uses the connection's peer address,
	// which behind a proxy puts every anonymous request in one bucket.
	ClientIP func(*http.Request) string
	// MaxAnonymousKeys bounds the number of client-address buckets. When it
	// is reached, a request from a new address is refused (429) until idle
	// buckets expire; tenant and subject buckets are never refused for it.
	// Zero uses DefaultMaxAnonymousKeys.
	MaxAnonymousKeys int
	// IdleTTL is how long an unused bucket is kept. Zero uses ten minutes.
	IdleTTL time.Duration
}

// KeyedRateLimiter is a token-bucket rate limiter that never lets a request
// through unlimited. Each request is counted against the first key it has:
//
//	t:<tenant>   the tenant in context (ctxutil.GetTenantID)
//	s:<subject>  else the subject (ctxutil.GetUserSub), e.g. a service account "app:7"
//	a:<address>  else the client address, in a smaller anonymous bucket;
//	             IPv6 addresses are grouped by /64
//
// The prefixes keep the tiers apart: a subject never shares a bucket with a
// tenant of the same spelling. A refused request gets 429 rate_limited with
// a Retry-After header computed from the bucket.
//
// Place it after jwtauth for the tenant and subject tiers. After jwtauth an
// unauthenticated request has already been refused, so the address tier
// matters on public routes (sign-in, webhooks) or with optional
// authentication; mount the same limiter there to bound them too.
type KeyedRateLimiter struct {
	cfg  KeyedRateLimiterConfig
	mu   sync.Mutex
	keys map[string]*tenantLimiter
	anon int // client-address buckets in keys
	stop chan struct{}
	once sync.Once
}

// NewKeyedRateLimiter returns a KeyedRateLimiter and starts its cleanup
// goroutine; call Stop on shutdown. RPS and Burst must be positive.
func NewKeyedRateLimiter(cfg KeyedRateLimiterConfig) (*KeyedRateLimiter, error) {
	if cfg.RPS <= 0 || cfg.Burst <= 0 {
		return nil, errors.New("httpware: KeyedRateLimiter needs a positive RPS and Burst")
	}
	if cfg.AnonymousRPS < 0 || cfg.AnonymousBurst < 0 || cfg.MaxAnonymousKeys < 0 || cfg.IdleTTL < 0 {
		return nil, errors.New("httpware: KeyedRateLimiter limits must not be negative")
	}
	if cfg.AnonymousRPS == 0 {
		cfg.AnonymousRPS = cfg.RPS / 10
	}
	if cfg.AnonymousBurst == 0 {
		cfg.AnonymousBurst = max(cfg.Burst/10, 1)
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = peerAddress
	}
	if cfg.MaxAnonymousKeys == 0 {
		cfg.MaxAnonymousKeys = DefaultMaxAnonymousKeys
	}
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = rateLimiterTTL
	}
	rl := &KeyedRateLimiter{cfg: cfg, keys: map[string]*tenantLimiter{}, stop: make(chan struct{})}
	go rl.cleanupLoop()
	return rl, nil
}

// Stop shuts down the cleanup goroutine. It is safe to call more than once.
func (rl *KeyedRateLimiter) Stop() {
	rl.once.Do(func() { close(rl.stop) })
}

// Handler returns the middleware.
func (rl *KeyedRateLimiter) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, anonymous := rl.key(r)
		lim := rl.limiter(key, anonymous)
		if lim == nil {
			// The address tier is full: refuse a new address rather than
			// grow without bound.
			writeRateLimited(w, rl.cfg.IdleTTL)
			return
		}
		res := lim.Reserve()
		if delay := res.Delay(); !res.OK() || delay > 0 {
			res.Cancel()
			if !res.OK() {
				delay = time.Second
			}
			writeRateLimited(w, delay)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// key returns the bucket key of r and whether it is a client-address key.
func (rl *KeyedRateLimiter) key(r *http.Request) (string, bool) {
	ctx := r.Context()
	if id := ctxutil.GetTenantID(ctx); id != uuid.Nil {
		return "t:" + id.String(), false
	}
	if sub := ctxutil.GetUserSub(ctx); sub != "" {
		return "s:" + sub, false
	}
	return "a:" + addressKey(rl.cfg.ClientIP(r)), true
}

func (rl *KeyedRateLimiter) limiter(key string, anonymous bool) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if kl, ok := rl.keys[key]; ok {
		kl.lastSeen = time.Now()
		return kl.limiter
	}
	rps, burst := rl.cfg.RPS, rl.cfg.Burst
	if anonymous {
		if rl.anon >= rl.cfg.MaxAnonymousKeys {
			return nil
		}
		rl.anon++
		rps, burst = rl.cfg.AnonymousRPS, rl.cfg.AnonymousBurst
	}
	kl := &tenantLimiter{limiter: rate.NewLimiter(rate.Limit(rps), burst), lastSeen: time.Now()}
	rl.keys[key] = kl
	return kl.limiter
}

func (rl *KeyedRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(min(rateLimiterCleanupInterval, rl.cfg.IdleTTL))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.evictIdle(time.Now().Add(-rl.cfg.IdleTTL))
		case <-rl.stop:
			return
		}
	}
}

func (rl *KeyedRateLimiter) evictIdle(cutoff time.Time) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, kl := range rl.keys {
		if kl.lastSeen.Before(cutoff) {
			delete(rl.keys, k)
			if k[0] == 'a' {
				rl.anon--
			}
		}
	}
}

// addressKey normalises a client address for bucketing: an IPv4 address as
// is, an IPv6 address by its /64 (one subscriber's allocation), anything else
// verbatim, capped in length. An empty address shares one "unknown" bucket.
func addressKey(addr string) string {
	if addr == "" {
		return "unknown"
	}
	ip := net.ParseIP(addr)
	switch {
	case ip == nil:
		if len(addr) > 64 {
			addr = addr[:64]
		}
		return addr
	case ip.To4() != nil:
		return ip.To4().String()
	default:
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
}

// peerAddress is the connection's peer address, without its port.
func peerAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeRateLimited(w http.ResponseWriter, delay time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(int(math.Ceil(delay.Seconds())), 1)))
	(&apierror.AppError{
		Code:       "rate_limited",
		StatusCode: http.StatusTooManyRequests,
		Message:    "too many requests",
	}).WriteJSON(w)
}
