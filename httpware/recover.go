package httpware

import (
	"net/http"
	"runtime/debug"

	"github.com/sirupsen/logrus"
)

// Recover returns a middleware that catches panics in downstream handlers,
// logs the panic value and full stack trace, and responds with 500.
// Pass a *logrus.Entry (not *logrus.Logger) so pre-attached fields such as
// "service" and "env" appear in the panic log line.
func Recover(logger *logrus.Entry) func(http.Handler) http.Handler {
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
