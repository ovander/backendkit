package bff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/ovander/backendkit/socrate"
)

// TokenRefresher exchanges a refresh token for a fresh token set. *socrate.Client
// satisfies it via its RefreshToken method, so a BFF passes its socrate client
// here rather than re-implementing the token call.
type TokenRefresher interface {
	RefreshToken(ctx context.Context, refreshToken string) (*socrate.TokenSet, error)
}

// DefaultCSRFHeader is the request header carrying the double-submit CSRF token.
const DefaultCSRFHeader = "X-CSRF-Token"

// DefaultRefreshLeeway is how far ahead of expiry the access token is proactively
// refreshed.
const DefaultRefreshLeeway = 30 * time.Second

// DefaultRefreshTimeout bounds a single (coalesced) token-refresh call. The
// refresh runs under a context detached from the triggering request so that
// one browser aborting its request cannot fail the refresh for every other
// request waiting on it; this timeout is what bounds it instead.
const DefaultRefreshTimeout = 10 * time.Second

// DefaultTouchInterval is how often ProxyWithSession persists the session's
// idle timestamp back to the store. Sliding the window on every request would
// be a write per request on a durable (Postgres) store; once a minute is
// plenty for an idle timeout measured in tens of minutes.
const DefaultTouchInterval = time.Minute

// Gateway ties a session store, cookie policy and token refresher into the
// fail-closed session→bearer proxy that is the heart of a BFF.
//
// A Gateway must be used by pointer and must not be copied after first use:
// it embeds a singleflight.Group (which holds a mutex). go vet's copylocks
// check reports any by-value copy.
type Gateway struct {
	Store     SessionStore
	Cookie    CookieConfig
	Refresher TokenRefresher

	// DisableAuth turns the whole session model off, reducing the gateway to a
	// pure pass-through (Phase-1 deploy before the SPA switches to cookies).
	// The zero value (false) is the safe, fail-closed default: a Gateway built
	// as a bare struct literal without setting this field still enforces
	// sessions rather than silently proxying everything through.
	DisableAuth bool

	// AllowPassthrough, only meaningful when auth is enabled, restores the
	// legacy behaviour of forwarding a request that carries no valid session.
	// It defaults to false: the safe, fail-closed default is to reject such
	// requests with 401 rather than proxy them (and any client-supplied
	// Authorization header) upstream.
	AllowPassthrough bool

	// CSRFHeader overrides DefaultCSRFHeader.
	CSRFHeader string
	// RefreshLeeway overrides DefaultRefreshLeeway.
	RefreshLeeway time.Duration
	// RefreshTimeout overrides DefaultRefreshTimeout.
	RefreshTimeout time.Duration
	// TouchInterval overrides DefaultTouchInterval. Negative persists the idle
	// timestamp on every request.
	TouchInterval time.Duration
	// Now overrides time.Now (tests).
	Now func() time.Time

	// refreshGroup coalesces concurrent EnsureFresh calls for the same
	// session so a rotating refresh token is only spent once. Zero value is
	// ready to use.
	refreshGroup singleflight.Group
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gateway) csrfHeader() string {
	if g.CSRFHeader != "" {
		return g.CSRFHeader
	}
	return DefaultCSRFHeader
}

func (g *Gateway) refreshLeeway() time.Duration {
	if g.RefreshLeeway > 0 {
		return g.RefreshLeeway
	}
	return DefaultRefreshLeeway
}

func (g *Gateway) refreshTimeout() time.Duration {
	if g.RefreshTimeout > 0 {
		return g.RefreshTimeout
	}
	return DefaultRefreshTimeout
}

func (g *Gateway) touchInterval() time.Duration {
	if g.TouchInterval != 0 {
		return g.TouchInterval
	}
	return DefaultTouchInterval
}

// SessionFromRequest resolves the session referenced by the request cookie.
func (g *Gateway) SessionFromRequest(r *http.Request) (*Session, bool) {
	id, ok := g.Cookie.SessionID(r)
	if !ok {
		return nil, false
	}
	return g.Store.Get(id)
}

// EnsureFresh returns a valid access token for the session, refreshing it via
// the TokenRefresher if it is within RefreshLeeway of expiry. The refreshed
// token set is stored back on the session under its lock AND written through
// to the Store, so a durable store (which rehydrates a fresh *Session per
// Get) keeps the rotated refresh token rather than the spent one.
//
// Concurrent calls for the same session are coalesced via refreshGroup: a
// rotating refresh token is single-use, so if two requests raced to refresh
// independently, the loser's call would fail and its session would be torn
// down even though the winner just refreshed it successfully. Every waiter on
// a coalesced call re-checks AccessValid against the same RefreshLeeway
// before spending a refresh, so a session freshened by a sibling goroutine
// while this one waited never issues a redundant refresh — and a session
// that is merely inside the proactive-refresh window (not yet expired) still
// gets refreshed rather than being handed back its stale token.
//
// The refresh itself runs under a context detached from ctx's cancellation
// (context.WithoutCancel) and bounded by RefreshTimeout: the refresh is a
// shared resource, and binding it to whichever request happened to arrive
// first meant a browser aborting that one request (tab close, navigation,
// EventSource teardown) failed the refresh for every coalesced waiter and
// logged all of them out. Values on ctx (tracing, logging) are preserved.
//
// Errors are returned as-is; use IsFatalRefreshError to decide whether the
// session should be torn down (the token was rejected) or kept (the token
// endpoint was merely unreachable).
func (g *Gateway) EnsureFresh(ctx context.Context, s *Session) (string, error) {
	now := g.now()
	if s.AccessValid(now, g.refreshLeeway()) {
		return s.AccessToken(), nil
	}
	v, err, _ := g.refreshGroup.Do(s.ID(), func() (any, error) {
		if s.AccessValid(g.now(), g.refreshLeeway()) {
			return s.AccessToken(), nil
		}
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), g.refreshTimeout())
		defer cancel()
		ts, err := g.Refresher.RefreshToken(rctx, s.RefreshToken())
		if err != nil {
			return "", err
		}
		s.SetTokens(ts, g.now())
		g.Store.Put(s)
		return s.AccessToken(), nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// IsFatalRefreshError reports whether a refresh failure means the session's
// refresh token has been rejected by the authorization server (invalid,
// expired, revoked, reused, or the client is no longer authorised) — in which
// case the session is dead and should be deleted — as opposed to a transient
// failure (network error, timeout, 5xx) where the session should be kept and
// the request answered with 502/503 instead of logging the user out.
//
// Only a typed *socrate.OAuthError carrying an RFC 6749 error code that
// denotes rejection is fatal; every other error is treated as transient. That
// is the safe direction: a mis-classified transient error costs one failed
// request, a mis-classified fatal one costs every admin their session during
// a token-endpoint blip.
func IsFatalRefreshError(err error) bool {
	var oe *socrate.OAuthError
	if !errors.As(err, &oe) {
		return false
	}
	switch oe.Code {
	case "invalid_grant", "invalid_client", "unauthorized_client", "invalid_scope":
		return true
	default:
		return false
	}
}

// IsUnsafeMethod reports whether the HTTP method mutates state and therefore
// requires a CSRF token.
func IsUnsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// CheckCSRF validates the double-submit CSRF token on the request against the
// session, in constant time. Safe methods always pass.
func (g *Gateway) CheckCSRF(r *http.Request, s *Session) bool {
	if !IsUnsafeMethod(r.Method) {
		return true
	}
	return s.MatchCSRF(r.Header.Get(g.csrfHeader()))
}

// ProxyWithSession returns a handler that injects the session's bearer onto the
// request and forwards it upstream, stripping the session cookie and any
// client-supplied Authorization header first. It is fail-closed: unless
// DisableAuth is explicitly set, a request with no valid session gets a 401
// rather than being proxied (unless AllowPassthrough is also explicitly set).
// Mutating methods must carry a matching CSRF token.
//
// A refresh failure that rejects the token (IsFatalRefreshError) deletes the
// session, clears the cookie and answers 401. A transient failure keeps the
// session and answers 502 so the browser can simply retry.
//
// The session's idle timestamp is slid and persisted (Store.Put) at most once
// per TouchInterval, so a durable store sees real activity without a write
// per request.
func (g *Gateway) ProxyWithSession(proxy *httputil.ReverseProxy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Phase 1: sessions disabled entirely — pure pass-through.
		if g.DisableAuth {
			proxy.ServeHTTP(w, r)
			return
		}

		s, ok := g.SessionFromRequest(r)
		if !ok {
			if g.AllowPassthrough {
				proxy.ServeHTTP(w, r)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		if !g.CheckCSRF(r, s) {
			http.Error(w, "missing or invalid CSRF token", http.StatusForbidden)
			return
		}

		access, err := g.EnsureFresh(r.Context(), s)
		if err != nil {
			if IsFatalRefreshError(err) {
				g.Store.Delete(s.ID())
				g.Cookie.ClearSession(w)
				http.Error(w, "session expired", http.StatusUnauthorized)
				return
			}
			http.Error(w, "token refresh unavailable", http.StatusBadGateway)
			return
		}
		now := g.now()
		if ti := g.touchInterval(); ti < 0 || now.Sub(s.LastSeen()) >= ti {
			s.Touch(now)
			g.Store.Put(s)
		}

		// Never let a client-supplied Authorization survive, and never leak the
		// session cookie upstream.
		r.Header.Del("Authorization")
		r.Header.Del("Cookie")
		r.Header.Set("Authorization", "Bearer "+access)
		proxy.ServeHTTP(w, r)
	}
}

// clientIPHeaders are request headers a client can set to claim an origin IP
// and that upstreams commonly trust. The BFF's own edge proxy manages
// X-Forwarded-For (replacing any client-supplied value for untrusted peers),
// so that one is left alone; these are not managed by the edge and would
// otherwise reach the upstream verbatim.
var clientIPHeaders = []string{"X-Real-IP", "True-Client-IP", "Forwarded"}

// NewSingleHostProxy builds an SSE-aware reverse proxy to a fixed upstream.
// FlushInterval = -1 flushes each write immediately so Server-Sent Events are
// not buffered. Callers must mount it behind a path allowlist (a ServeMux with
// explicit prefixes) so no unexpected path reaches the upstream.
//
// The proxy's Director strips client-supplied IP-attribution headers
// (X-Real-IP, True-Client-IP, Forwarded) so a browser cannot choose the IP
// the upstream rate-limits, blocks or audits it as. Callers that wrap
// Director (e.g. to rewrite Host) keep this behaviour by calling the
// original Director first, as usual.
func NewSingleHostProxy(upstream *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(upstream)
	p.FlushInterval = -1
	director := p.Director
	p.Director = func(r *http.Request) {
		director(r)
		for _, h := range clientIPHeaders {
			r.Header.Del(h)
		}
	}
	return p
}
