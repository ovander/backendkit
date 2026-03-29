// Package ctxutil provides typed context keys and helpers for propagating
// request-scoped values (tenant ID, user identity, logger, request ID) through
// the standard context.Context mechanism.
//
// All backends sharing Socrate as their OAuth2 provider use the same JWT claim
// field names; these helpers give a single authoritative definition of the keys.
package ctxutil

import (
	"context"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type contextKey string

const (
	TenantIDKey  contextKey = "tenant_id"
	UserPlanKey  contextKey = "user_plan" // commercial plan: "freemium", "pro", "enterprise"
	UserIDKey    contextKey = "user_id"
	UserRoleKey  contextKey = "user_role"
	UserEmailKey contextKey = "user_email"
	UserNameKey  contextKey = "user_name"
	UserSubKey   contextKey = "user_sub"
	LoggerKey    contextKey = "logger"
	ClaimsKey    contextKey = "claims"
	RequestIDKey contextKey = "request_id"

	// TenantTierKey is a deprecated alias for UserPlanKey kept for backward compatibility.
	TenantTierKey = UserPlanKey
)

// GetTenantID extracts the tenant UUID from context.
func GetTenantID(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(TenantIDKey).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

// GetUserID extracts the user UUID from context.
func GetUserID(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(UserIDKey).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}

// GetUserRole extracts the user role string from context.
func GetUserRole(ctx context.Context) string {
	if v, ok := ctx.Value(UserRoleKey).(string); ok {
		return v
	}
	return ""
}

// GetLogger extracts the request-scoped logger from context.
// Falls back to a new entry on the standard logger if none is set.
func GetLogger(ctx context.Context) *log.Entry {
	if v, ok := ctx.Value(LoggerKey).(*log.Entry); ok {
		return v
	}
	return log.NewEntry(log.StandardLogger())
}

// GetRequestID extracts the request ID from context.
func GetRequestID(ctx context.Context) string {
	if v, ok := ctx.Value(RequestIDKey).(string); ok {
		return v
	}
	return ""
}

// GetTenantIDStr returns the tenant_id as a string (for logging).
func GetTenantIDStr(ctx context.Context) string {
	id := GetTenantID(ctx)
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// WithTenantID returns a new context with the tenant_id set.
func WithTenantID(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, TenantIDKey, tenantID)
}

// GetUserPlan extracts the commercial plan string from context.
// Returns "freemium" if not set.
func GetUserPlan(ctx context.Context) string {
	if v, ok := ctx.Value(UserPlanKey).(string); ok && v != "" {
		return v
	}
	return "freemium"
}

// WithUserPlan returns a new context with the commercial plan set.
func WithUserPlan(ctx context.Context, plan string) context.Context {
	return context.WithValue(ctx, UserPlanKey, plan)
}

// GetTenantTier is a deprecated alias for GetUserPlan.
func GetTenantTier(ctx context.Context) string {
	return GetUserPlan(ctx)
}

// WithTenantTier is a deprecated alias for WithUserPlan.
func WithTenantTier(ctx context.Context, tier string) context.Context {
	return WithUserPlan(ctx, tier)
}

// WithUserID returns a new context with the user_id set.
func WithUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// WithUserRole returns a new context with the user role set.
func WithUserRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, UserRoleKey, role)
}

// GetUserEmail extracts the user email from context.
func GetUserEmail(ctx context.Context) string {
	if v, ok := ctx.Value(UserEmailKey).(string); ok {
		return v
	}
	return ""
}

// GetUserName extracts the user display name from context.
func GetUserName(ctx context.Context) string {
	if v, ok := ctx.Value(UserNameKey).(string); ok {
		return v
	}
	return ""
}

// GetUserSub extracts the raw subject identifier from context.
func GetUserSub(ctx context.Context) string {
	if v, ok := ctx.Value(UserSubKey).(string); ok {
		return v
	}
	return ""
}

// WithUserEmail returns a new context with the user email set.
func WithUserEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, UserEmailKey, email)
}

// WithUserName returns a new context with the user name set.
func WithUserName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, UserNameKey, name)
}

// WithUserSub returns a new context with the raw subject identifier set.
func WithUserSub(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, UserSubKey, sub)
}

// WithLogger returns a new context with the logger set.
func WithLogger(ctx context.Context, logger *log.Entry) context.Context {
	return context.WithValue(ctx, LoggerKey, logger)
}

// WithRequestID returns a new context with the request_id set.
func WithRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, reqID)
}
