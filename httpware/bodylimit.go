package httpware

import "net/http"

// BodyLimit caps the size of incoming request bodies to protect against
// memory-exhaustion attacks. Requests that exceed the limit receive 413
// before the body is fully read.
//
// Apply globally as a default, then override per-route for endpoints that
// legitimately accept large payloads:
//
//	r.Use(httpware.BodyLimit(1 << 20))                        // 1 MiB default
//	r.With(httpware.BodyLimit(50 << 20)).Post("/upload", h)   // 50 MiB upload
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
