package bff

import (
	"net/http"

	"github.com/ovander/backendkit/socrate"
)

// WithClientAttribution returns a shallow copy of r whose context carries a
// socrate.ClientAttribution for the browser that sent r: IP is clientIP and
// UserAgent is r.UserAgent(). The socrate.Client calls made with that context
// (ExchangeCode in the callback, RefreshToken in Gateway.EnsureFresh and
// Gateway.ProxyWithSession, RevokeToken at logout) then tell Socrate who the
// browser is instead of appearing as the BFF itself.
//
// clientIP MUST be the address the BFF resolved with its own trusted-proxy
// rules (typically: honour X-Forwarded-For only from the local edge proxy,
// else RemoteAddr), never a raw request header. This package does not resolve
// it. An empty or unparsable clientIP sends no address; the User-Agent is
// still sent.
//
// Install it as early as possible, in a middleware in front of the login,
// callback, logout and proxy handlers:
//
//	next.ServeHTTP(w, bff.WithClientAttribution(r, resolvedIP))
func WithClientAttribution(r *http.Request, clientIP string) *http.Request {
	return r.WithContext(socrate.WithClientAttribution(r.Context(), socrate.ClientAttribution{
		IP:        clientIP,
		UserAgent: r.UserAgent(),
	}))
}
