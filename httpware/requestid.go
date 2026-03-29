package httpware

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/ctxutil"
)

// RequestID is a middleware that reads the X-Request-ID header from the
// incoming request (or generates a new UUID v4 when absent), stores it in the
// request context via ctxutil, and echoes it back in the response header.
//
// Place this early in the middleware chain so that all downstream middleware
// and handlers can call ctxutil.GetRequestID(ctx).
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = uuid.New().String()
		}
		ctx := ctxutil.WithRequestID(r.Context(), reqID)
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
