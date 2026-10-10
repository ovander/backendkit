package ctxutil_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
)

func TestGetTenantID_RoundTrip(t *testing.T) {
	id := uuid.New()
	ctx := ctxutil.WithTenantID(context.Background(), id)
	if got := ctxutil.GetTenantID(ctx); got != id {
		t.Errorf("GetTenantID = %v, want %v", got, id)
	}
}

func TestGetTenantID_Missing(t *testing.T) {
	if got := ctxutil.GetTenantID(context.Background()); got != uuid.Nil {
		t.Errorf("expected uuid.Nil, got %v", got)
	}
}

func TestGetTenantIDStr(t *testing.T) {
	id := uuid.New()
	ctx := ctxutil.WithTenantID(context.Background(), id)
	if got := ctxutil.GetTenantIDStr(ctx); got != id.String() {
		t.Errorf("GetTenantIDStr = %q, want %q", got, id.String())
	}
}

func TestGetTenantIDStr_Missing(t *testing.T) {
	if got := ctxutil.GetTenantIDStr(context.Background()); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestGetUserID_RoundTrip(t *testing.T) {
	id := uuid.New()
	ctx := ctxutil.WithUserID(context.Background(), id)
	if got := ctxutil.GetUserID(ctx); got != id {
		t.Errorf("GetUserID = %v, want %v", got, id)
	}
}

func TestGetUserRole_RoundTrip(t *testing.T) {
	ctx := ctxutil.WithUserRole(context.Background(), "admin")
	if got := ctxutil.GetUserRole(ctx); got != "admin" {
		t.Errorf("GetUserRole = %q, want \"admin\"", got)
	}
}

func TestGetUserRole_Missing(t *testing.T) {
	if got := ctxutil.GetUserRole(context.Background()); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestGetUserPlan_Default(t *testing.T) {
	if got := ctxutil.GetUserPlan(context.Background()); got != "freemium" {
		t.Errorf("expected freemium, got %q", got)
	}
}

func TestGetUserPlan_RoundTrip(t *testing.T) {
	ctx := ctxutil.WithUserPlan(context.Background(), "pro")
	if got := ctxutil.GetUserPlan(ctx); got != "pro" {
		t.Errorf("GetUserPlan = %q, want \"pro\"", got)
	}
}

func TestDeprecatedTierAliases(t *testing.T) {
	ctx := ctxutil.WithTenantTier(context.Background(), "enterprise")
	if got := ctxutil.GetTenantTier(ctx); got != "enterprise" {
		t.Errorf("GetTenantTier = %q, want \"enterprise\"", got)
	}
}

func TestGetUserEmail_RoundTrip(t *testing.T) {
	ctx := ctxutil.WithUserEmail(context.Background(), "test@example.com")
	if got := ctxutil.GetUserEmail(ctx); got != "test@example.com" {
		t.Errorf("GetUserEmail = %q, want test@example.com", got)
	}
}

func TestGetUserName_RoundTrip(t *testing.T) {
	ctx := ctxutil.WithUserName(context.Background(), "Alice")
	if got := ctxutil.GetUserName(ctx); got != "Alice" {
		t.Errorf("GetUserName = %q, want Alice", got)
	}
}

func TestGetUserSub_RoundTrip(t *testing.T) {
	ctx := ctxutil.WithUserSub(context.Background(), "sub-123")
	if got := ctxutil.GetUserSub(ctx); got != "sub-123" {
		t.Errorf("GetUserSub = %q, want sub-123", got)
	}
}

func TestGetRequestID_RoundTrip(t *testing.T) {
	ctx := ctxutil.WithRequestID(context.Background(), "req-abc")
	if got := ctxutil.GetRequestID(ctx); got != "req-abc" {
		t.Errorf("GetRequestID = %q, want req-abc", got)
	}
}

func TestGetRequestID_Missing(t *testing.T) {
	if got := ctxutil.GetRequestID(context.Background()); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestGetLogger_FallbackToStandard(t *testing.T) {
	logger := ctxutil.GetLogger(context.Background())
	if logger == nil {
		t.Error("expected non-nil logger fallback")
	}
}

func TestGetLogger_RoundTrip(t *testing.T) {
	entry := log.WithField("test", true)
	ctx := ctxutil.WithLogger(context.Background(), entry)
	if got := ctxutil.GetLogger(ctx); got != entry {
		t.Error("GetLogger did not return the stored entry")
	}
}

func TestGetAudiences_RoundTripIsCopied(t *testing.T) {
	in := []string{"console", "portal"}
	ctx := ctxutil.WithAudiences(context.Background(), in)
	in[0] = "changed"
	got := ctxutil.GetAudiences(ctx)
	if len(got) != 2 || got[0] != "console" || got[1] != "portal" {
		t.Fatalf("GetAudiences = %q, want [console portal]", got)
	}
	got[1] = "changed"
	if again := ctxutil.GetAudiences(ctx); again[1] != "portal" {
		t.Errorf("changing the result changed the context: %q", again)
	}
}

func TestGetAudiences_Missing(t *testing.T) {
	if got := ctxutil.GetAudiences(context.Background()); got != nil {
		t.Errorf("expected nil, got %q", got)
	}
	if got := ctxutil.GetAudiences(ctxutil.WithAudiences(context.Background(), nil)); got != nil {
		t.Errorf("expected nil for an empty set, got %q", got)
	}
}

func TestGetScopes_RoundTripIsCopied(t *testing.T) {
	in := []string{"api", "swingdrift:worker"}
	ctx := ctxutil.WithScopes(context.Background(), in)
	in[0] = "changed"
	got := ctxutil.GetScopes(ctx)
	if len(got) != 2 || got[0] != "api" || got[1] != "swingdrift:worker" {
		t.Fatalf("GetScopes = %q, want [api swingdrift:worker]", got)
	}
	got[1] = "changed"
	if again := ctxutil.GetScopes(ctx); again[1] != "swingdrift:worker" {
		t.Errorf("changing the result changed the context: %q", again)
	}
}

func TestGetScopes_Missing(t *testing.T) {
	if got := ctxutil.GetScopes(context.Background()); got != nil {
		t.Errorf("expected nil, got %q", got)
	}
	if got := ctxutil.GetScopes(ctxutil.WithScopes(context.Background(), nil)); got != nil {
		t.Errorf("expected nil for an empty set, got %q", got)
	}
}
