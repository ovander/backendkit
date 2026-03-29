package httpware

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
)

// Permission is a string token representing an action a role may perform.
// Define your application's permission constants as Permission values.
type Permission string

// RoleMap maps role names to the set of permissions they grant.
// Build one at startup and pass it to NewRBAC.
//
// Example:
//
//	rbac := httpware.NewRBAC(httpware.RoleMap{
//	    "viewer": {"read:resource"},
//	    "editor": {"read:resource", "write:resource"},
//	    "admin":  {"read:resource", "write:resource", "delete:resource"},
//	}, logger)
type RoleMap map[string][]Permission

// RBAC provides role-based access control middleware backed by a caller-supplied
// role → permission map.
type RBAC struct {
	roles  RoleMap
	logger *logrus.Entry
}

// NewRBAC creates an RBAC instance. roles must not be modified after this call.
func NewRBAC(roles RoleMap, logger *logrus.Entry) *RBAC {
	return &RBAC{roles: roles, logger: logger}
}

// Require returns middleware that allows the request only when the caller's
// role (from context) has perm. Denied requests receive 403 Forbidden.
func (rb *RBAC) Require(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := ctxutil.GetUserRole(r.Context())
			if !rb.hasPermission(role, perm) {
				rb.logger.WithField("role", role).
					WithField("required_permission", perm).
					Warn("permission denied")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (rb *RBAC) hasPermission(role string, perm Permission) bool {
	perms, ok := rb.roles[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}
