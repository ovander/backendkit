// Package httpware provides reusable HTTP middleware for chi-based services.
// Each middleware is a pure function or a lightweight struct with no shared
// mutable state between requests, making the package safe to use concurrently.
package httpware

import (
	"context"
	"net/http"
	"time"
)

// Timeout returns a middleware that cancels the request context after the given
// duration. Handlers should respect ctx.Done() to abort long-running work.
//
// The new deadline replaces any deadline already on the parent context
// (e.g. from an outer Timeout middleware). This lets inner route-groups declare
// a longer timeout than the global default without the shorter parent winning.
// Client-disconnect cancellation is intentionally dropped: the configured
// timeout is the sole cancel source, which is the right trade-off for slow
// AI / report endpoints.
func Timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip any existing deadline so this middleware is authoritative.
			base := context.WithoutCancel(r.Context())
			ctx, cancel := context.WithTimeout(base, d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
