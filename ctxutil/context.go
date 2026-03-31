// Package ctxutil provides typed context keys and helpers for propagating
// request-scoped values (tenant ID, user identity, logger, request ID) through
// the standard context.Context mechanism.
//
// All backends sharing Socrate as their OAuth2 provider use the same JWT claim
// field names; these helpers give a single authoritative definition of the keys.
//
// Context keys are intentionally unexported. Callers must use the With*/Get*
// functions — never context.WithValue or ctx.Value directly — to prevent
// cross-package key collisions.
package ctxutil

import (
	"context"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// contextKey is the unexported type used for all keys in this package.
// Using a named type (rather than a plain string) prevents collisions with any
// other package that stores string-keyed values in the same context.
type contextKey string

// Unexported key constants. Callers interact exclusively through With*/Get* helpers.
const (
	tenantIDKey     contextKey = "tenant_id"
	userPlanKey     contextKey = "user_plan"
	userIDKey       contextKey = "user_id"
	userRoleKey     contextKey = "user_role"
	userEmailKey    contextKey = "user_email"
	userNameKey     contextKey = "user_name"
	userSubKey      contextKey = "user_sub"
	appRolesKey     contextKey = "app_roles"
	tokenVersionKey contextKey = "token_version"
	loggerKey       contextKey = "logger"
	requestIDKey    contextKey = "request_id"
	rawJWTKey       contextKey = "raw_jwt"
)

// ─── Tenant ───────────────────────────────────────────────────────────────────

// WithTenantID returns a new context with the tenant UUID set.
func WithTenantID(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantIDKey, tenantID)
}

// GetTenantID extracts the tenant UUID from context. Returns uuid.Nil when absent.
func GetTenantID(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(tenantIDKey).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

// GetTenantIDStr returns the tenant UUID as a string, useful for logging.
// Returns "" when absent.
func GetTenantIDStr(ctx context.Context) string {
	id := GetTenantID(ctx)
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// ─── User ─────────────────────────────────────────────────────────────────────

// WithUserID returns a new context with the user UUID set.
func WithUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// GetUserID extracts the user UUID from context. Returns uuid.Nil when absent.
func GetUserID(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(userIDKey).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

// WithUserRole returns a new context with the user role set.
func WithUserRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, userRoleKey, role)
}

// GetUserRole extracts the user role string from context. Returns "" when absent.
func GetUserRole(ctx context.Context) string {
	if v, ok := ctx.Value(userRoleKey).(string); ok {
		return v
	}
	return ""
}

// WithUserPlan returns a new context with the commercial plan set.
func WithUserPlan(ctx context.Context, plan string) context.Context {
	return context.WithValue(ctx, userPlanKey, plan)
}

// GetUserPlan extracts the commercial plan string from context.
// Returns "freemium" when absent — safe to call in any handler without a nil check.
func GetUserPlan(ctx context.Context) string {
	if v, ok := ctx.Value(userPlanKey).(string); ok && v != "" {
		return v
	}
	return "freemium"
}

// WithUserEmail returns a new context with the user email set.
func WithUserEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, userEmailKey, email)
}

// GetUserEmail extracts the user email from context. Returns "" when absent.
func GetUserEmail(ctx context.Context) string {
	if v, ok := ctx.Value(userEmailKey).(string); ok {
		return v
	}
	return ""
}

// WithUserName returns a new context with the user display name set.
func WithUserName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, userNameKey, name)
}

// GetUserName extracts the user display name from context. Returns "" when absent.
func GetUserName(ctx context.Context) string {
	if v, ok := ctx.Value(userNameKey).(string); ok {
		return v
	}
	return ""
}

// WithUserSub returns a new context with the raw OAuth subject identifier set.
func WithUserSub(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, userSubKey, sub)
}

// GetUserSub extracts the raw OAuth subject identifier from context. Returns "" when absent.
func GetUserSub(ctx context.Context) string {
	if v, ok := ctx.Value(userSubKey).(string); ok {
		return v
	}
	return ""
}

// ─── App roles & token version ───────────────────────────────────────────────

// WithAppRoles stores the app_roles map (appClientID → role) from the JWT.
func WithAppRoles(ctx context.Context, roles map[string]string) context.Context {
	return context.WithValue(ctx, appRolesKey, roles)
}

// GetAppRoles returns the app_roles map injected by jwtauth.Middleware.
// Returns nil when absent (e.g. when the token has no app roles or in tests).
func GetAppRoles(ctx context.Context) map[string]string {
	if v, ok := ctx.Value(appRolesKey).(map[string]string); ok {
		return v
	}
	return nil
}

// GetAppRole returns the role the current user holds in the specified app
// (identified by its client_id). Returns "" when the user has no role in that app.
func GetAppRole(ctx context.Context, clientID string) string {
	roles := GetAppRoles(ctx)
	if roles == nil {
		return ""
	}
	return roles[clientID]
}

// WithTokenVersion stores the token_version claim from the JWT.
func WithTokenVersion(ctx context.Context, v int) context.Context {
	return context.WithValue(ctx, tokenVersionKey, v)
}

// GetTokenVersion returns the token_version claim. Returns 0 when absent.
func GetTokenVersion(ctx context.Context) int {
	if v, ok := ctx.Value(tokenVersionKey).(int); ok {
		return v
	}
	return 0
}

// ─── JWT ──────────────────────────────────────────────────────────────────────

// WithRawJWT stores the raw bearer token string in ctx so downstream service
// clients (e.g. socrate.Client) can forward it without re-parsing the JWT.
// Called by jwtauth.Middleware after successful token validation.
func WithRawJWT(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, rawJWTKey, token)
}

// GetRawJWT retrieves the raw bearer token stored by WithRawJWT.
// Returns "" when absent (e.g. in tests that bypass the auth middleware).
func GetRawJWT(ctx context.Context) string {
	if v, ok := ctx.Value(rawJWTKey).(string); ok {
		return v
	}
	return ""
}

// ─── Logger ───────────────────────────────────────────────────────────────────

// WithLogger returns a new context with the request-scoped logger set.
func WithLogger(ctx context.Context, logger *log.Entry) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// GetLogger extracts the request-scoped logger from context.
// Falls back to a new entry on the standard logger when none is set.
func GetLogger(ctx context.Context) *log.Entry {
	if v, ok := ctx.Value(loggerKey).(*log.Entry); ok {
		return v
	}
	return log.NewEntry(log.StandardLogger())
}

// ─── Request ID ───────────────────────────────────────────────────────────────

// WithRequestID returns a new context with the request trace ID set.
func WithRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, requestIDKey, reqID)
}

// GetRequestID extracts the request trace ID from context. Returns "" when absent.
func GetRequestID(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// ─── Deprecated aliases ───────────────────────────────────────────────────────

// GetTenantTier is a deprecated alias for GetUserPlan.
//
// Deprecated: Use GetUserPlan instead.
func GetTenantTier(ctx context.Context) string { return GetUserPlan(ctx) }

// WithTenantTier is a deprecated alias for WithUserPlan.
//
// Deprecated: Use WithUserPlan instead.
func WithTenantTier(ctx context.Context, tier string) context.Context {
	return WithUserPlan(ctx, tier)
}
