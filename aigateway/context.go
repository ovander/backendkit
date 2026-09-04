package aigateway

import "context"

// ─────────────────────────────────────────────────────────────────────────────
// Context keys — unexported structs avoid collisions with third-party packages.
// ─────────────────────────────────────────────────────────────────────────────

type localeCtxKey struct{}
type moduleCtxKey struct{}

// ─────────────────────────────────────────────────────────────────────────────
// Locale helpers
// ─────────────────────────────────────────────────────────────────────────────

// WithLocale attaches locale to ctx so that SafeClient can enforce the correct
// output language without requiring callers to change their Generate signature.
//
// Call this at the request boundary — typically in an HTTP middleware that reads
// Accept-Language or the user's stored language preference:
//
//	func LangMiddleware(next http.Handler) http.Handler {
//	    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//	        locale := resolveLocale(r)  // "fr" or "en"
//	        ctx := aigateway.WithLocale(r.Context(), locale)
//	        next.ServeHTTP(w, r.WithContext(ctx))
//	    })
//	}
func WithLocale(ctx context.Context, locale string) context.Context {
	return context.WithValue(ctx, localeCtxKey{}, locale)
}

// LocaleFromContext returns the locale attached by WithLocale, or "fr" (the
// system default) when none is present.
func LocaleFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(localeCtxKey{}).(string); ok && v != "" {
		return v
	}
	return "fr"
}

// ─────────────────────────────────────────────────────────────────────────────
// Module helpers
// ─────────────────────────────────────────────────────────────────────────────

// WithModule attaches a module identifier to ctx.  The SafeClient forwards it
// as a Sentry tag so language-mismatch events can be filtered per feature
// (e.g. "insight", "suggest", "narration").
func WithModule(ctx context.Context, module string) context.Context {
	return context.WithValue(ctx, moduleCtxKey{}, module)
}

// moduleFromContext returns the module tag or "unknown".
// Unexported — used internally by SafeClient; not part of the public API.
func moduleFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(moduleCtxKey{}).(string); ok && v != "" {
		return v
	}
	return "unknown"
}
