package httpware

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/apierror"
	"github.com/ovander/backendkit/ctxutil"
)

// RequireTenant returns middleware that rejects any request without a tenant ID
// in its context with 401 Unauthorized, so a tenant-scoped handler can never run
// against the nil tenant.
//
// The auth middleware (jwtauth) only populates the tenant when the token carries
// a tenant_id claim; when it does not, ctxutil.GetTenantID returns uuid.Nil with
// no error. Mounting RequireTenant on tenant-scoped route groups turns that
// silent gap into an explicit, fail-closed rejection.
//
// Place it after the auth middleware:
//
//	r.Group(func(r chi.Router) {
//	    r.Use(auth.Handler)
//	    r.Use(httpware.RequireTenant)
//	    r.Mount("/orders", ordersRouter) // every handler is guaranteed a tenant
//	})
//
// It is a plain func(http.Handler) http.Handler — like RequestID and
// SecurityHeaders — and needs no constructor: rejections are logged through the
// request-scoped logger from ctxutil.GetLogger.
func RequireTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ctxutil.GetTenantID(r.Context()) == uuid.Nil {
			ctxutil.GetLogger(r.Context()).Warn("request rejected: no tenant in context")
			apierror.Unauthorized("tenant context required").WriteJSON(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}
