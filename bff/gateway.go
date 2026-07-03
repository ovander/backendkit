package bff

import (
	"context"
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

// Gateway ties a session store, cookie policy and token refresher into the
// fail-closed session→bearer proxy that is the heart of a BFF.
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
// token set is stored back on the session under its lock.
//
// Concurrent calls for the same session are coalesced via refreshGroup: a
// rotating refresh token is single-use, so if two requests raced to refresh
// independently, the loser's call would fail and its session would be torn
// down even though the winner just refreshed it successfully. Every waiter on
// a coalesced call re-checks AccessValid first (with no leeway) so a session
// freshened by a sibling goroutine while this one waited never issues a
// redundant refresh.
func (g *Gateway) EnsureFresh(ctx context.Context, s *Session) (string, error) {
	now := g.now()
	if s.AccessValid(now, g.refreshLeeway()) {
		return s.AccessToken(), nil
	}
	v, err, _ := g.refreshGroup.Do(s.ID(), func() (any, error) {
		if s.AccessValid(g.now(), 0) {
			return s.AccessToken(), nil
		}
		ts, err := g.Refresher.RefreshToken(ctx, s.RefreshToken())
		if err != nil {
			return "", err
		}
		s.SetTokens(ts, g.now())
		return s.AccessToken(), nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
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
			g.Store.Delete(s.ID())
			g.Cookie.ClearSession(w)
			http.Error(w, "session expired", http.StatusUnauthorized)
			return
		}
		s.Touch(g.now())

		// Never let a client-supplied Authorization survive, and never leak the
		// session cookie upstream.
		r.Header.Del("Authorization")
		r.Header.Del("Cookie")
		r.Header.Set("Authorization", "Bearer "+access)
		proxy.ServeHTTP(w, r)
	}
}

// NewSingleHostProxy builds an SSE-aware reverse proxy to a fixed upstream.
// FlushInterval = -1 flushes each write immediately so Server-Sent Events are
// not buffered. Callers must mount it behind a path allowlist (a ServeMux with
// explicit prefixes) so no unexpected path reaches the upstream.
func NewSingleHostProxy(upstream *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(upstream)
	p.FlushInterval = -1
	return p
}
