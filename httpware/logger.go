package httpware

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
)

// statusRecorder wraps http.ResponseWriter to capture the written status code.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.statusCode = code
	sr.ResponseWriter.WriteHeader(code)
}

// Logger returns a middleware that:
//  1. Creates a request-scoped logrus.Entry enriched with request_id, method,
//     and path, then stores it in the context via ctxutil.WithLogger.
//  2. After the handler returns, logs a "request completed" line with status
//     code, duration_ms, and tenant_id.
//
// RequestID middleware should run before Logger so that request_id is already
// in the context when Logger reads it.
func Logger(base *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := ctxutil.GetRequestID(r.Context())

			entry := base.WithField("request_id", reqID).
				WithField("method", r.Method).
				WithField("path", r.URL.Path)

			sr := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
			ctx := ctxutil.WithLogger(r.Context(), entry)
			start := time.Now()

			next.ServeHTTP(sr, r.WithContext(ctx))

			entry.WithField("status", sr.statusCode).
				WithField("duration_ms", time.Since(start).Milliseconds()).
				WithField("tenant_id", ctxutil.GetTenantIDStr(r.Context())).
				Info("request completed")
		})
	}
}
