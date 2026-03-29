package ctxutil_test

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/ctxutil"
)

// ExampleWithTenantID demonstrates storing and retrieving a tenant UUID.
func ExampleWithTenantID() {
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	ctx := ctxutil.WithTenantID(context.Background(), tenantID)

	got := ctxutil.GetTenantID(ctx)
	fmt.Println(got)
	fmt.Println(got != uuid.Nil)
	// Output:
	// 00000000-0000-0000-0000-000000000001
	// true
}

// ExampleGetUserPlan_default shows that GetUserPlan returns "freemium" when no
// plan was injected — safe to call in any handler without a nil check.
func ExampleGetUserPlan_default() {
	plan := ctxutil.GetUserPlan(context.Background())
	fmt.Println(plan)
	// Output:
	// freemium
}

// ExampleGetUserRole shows zero-value behaviour when role is absent.
func ExampleGetUserRole() {
	role := ctxutil.GetUserRole(context.Background())
	fmt.Println(role == "")
	// Output:
	// true
}

// ExampleWithRequestID demonstrates injecting and reading a trace ID.
func ExampleWithRequestID() {
	ctx := ctxutil.WithRequestID(context.Background(), "req-abc-123")
	fmt.Println(ctxutil.GetRequestID(ctx))
	// Output:
	// req-abc-123
}

// ExampleWithRawJWT demonstrates storing the raw bearer token so downstream
// service clients (e.g. socrate.Client) can forward it without re-parsing.
// In production this is called automatically by jwtauth.Middleware.
func ExampleWithRawJWT() {
	ctx := ctxutil.WithRawJWT(context.Background(), "eyJhbGciOiJSUzI1NiJ9.test.sig")
	token := ctxutil.GetRawJWT(ctx)
	fmt.Println(len(token) > 0)
	// Output:
	// true
}
