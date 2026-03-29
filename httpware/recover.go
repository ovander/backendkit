package httpware

import (
	"net/http"
	"runtime/debug"

	"github.com/sirupsen/logrus"
)

// Recover returns a middleware that catches panics in downstream handlers,
// logs the panic value and full stack trace, and responds with 500.
func Recover(logger *logrus.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.WithField("panic", err).
						WithField("stack", string(debug.Stack())).
						Error("panic recovered")
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
