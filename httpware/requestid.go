package httpware

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/ctxutil"
)

// MaxRequestIDLength is the longest incoming X-Request-ID that RequestID keeps.
const MaxRequestIDLength = 128

// RequestID is a middleware that reads the X-Request-ID header from the
// incoming request, stores it in the request context via ctxutil, and echoes
// it back in the response header.
//
// An incoming id is kept only when it is a valid request id: 1 to
// MaxRequestIDLength characters of A-Z, a-z, 0-9, '.', '_', ':' and '-' (UUIDs,
// ULIDs and similar). Otherwise, or when the header is absent, a new UUID v4
// is generated. The request is never rejected. The id ends up in logs, audit
// fields and outbound calls, so a client cannot inject line breaks, control
// characters or unbounded text through it.
//
// Place this early in the middleware chain so that all downstream middleware
// and handlers can call ctxutil.GetRequestID(ctx).
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if !ValidRequestID(reqID) {
			reqID = uuid.New().String()
		}
		ctx := ctxutil.WithRequestID(r.Context(), reqID)
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ValidRequestID reports whether id is acceptable as a request id: 1 to
// MaxRequestIDLength characters of A-Z, a-z, 0-9, '.', '_', ':' and '-'.
func ValidRequestID(id string) bool {
	if id == "" || len(id) > MaxRequestIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		switch c := id[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}
