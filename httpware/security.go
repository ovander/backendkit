package httpware

import "net/http"

// SecurityHeaders adds a standard set of security-related HTTP response
// headers. It is safe to use on all routes.
//
// Headers set:
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - X-XSS-Protection: 0  (disabled; rely on CSP instead)
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
//   - Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
//   - Cache-Control: no-store
//   - Permissions-Policy: camera=(), microphone=(), geolocation=()
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "0")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("Cache-Control", "no-store")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
