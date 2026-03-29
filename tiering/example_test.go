package tiering_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/tiering"
)

// ExamplePlanRegistry demonstrates building a custom plan hierarchy and
// using TierAtLeast to check whether a user's plan meets a minimum.
// Note: TierAtLeast returns false for plans not present in the registry;
// use Normalise first when the input may be an unknown string.
func ExamplePlanRegistry() {
	reg := tiering.NewPlanRegistry("starter", "growth", "enterprise")

	fmt.Println(reg.TierAtLeast("growth", "starter"))              // growth >= starter → true
	fmt.Println(reg.TierAtLeast("starter", "growth"))              // starter < growth  → false
	fmt.Println(reg.TierAtLeast("unknown", "starter"))             // not in registry   → false
	fmt.Println(reg.TierAtLeast(reg.Normalise("unknown"), "starter")) // normalise first → true
	// Output:
	// true
	// false
	// false
	// true
}

// ExampleDefaultRegistry demonstrates the built-in freemium/pro/enterprise
// registry and the Normalise helper.
func ExampleDefaultRegistry() {
	reg := tiering.DefaultRegistry()

	fmt.Println(reg.Normalise("pro"))       // known → unchanged
	fmt.Println(reg.Normalise("PREMIUM"))   // unknown → lowest tier
	// Output:
	// pro
	// freemium
}

// ExampleGate_Require demonstrates the tier gate middleware denying a request
// when the user's plan is below the required minimum.
func ExampleGate_Require() {
	logger := logrus.NewEntry(logrus.New())
	gate := tiering.NewGate(tiering.DefaultRegistry(), logger, "/billing")

	handler := gate.Require(tiering.PlanPro)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "premium feature")
	}))

	// Freemium user → 403.
	req := httptest.NewRequest(http.MethodGet, "/ai/narrate", nil)
	req = req.WithContext(ctxutil.WithUserPlan(req.Context(), tiering.PlanFreemium))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	fmt.Println(rec.Code)

	// Pro user → 200.
	req2 := httptest.NewRequest(http.MethodGet, "/ai/narrate", nil)
	req2 = req2.WithContext(ctxutil.WithUserPlan(req2.Context(), tiering.PlanPro))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	fmt.Println(rec2.Code)

	// Output:
	// 403
	// 200
}

// ExampleMarshalAccess demonstrates encoding per-tier rules into the JSONB
// format expected by FeaturePolicy.
func ExampleMarshalAccess() {
	cell := tiering.MarshalAccess(true)
	var rule tiering.TierRule
	_ = json.Unmarshal(cell, &rule)
	fmt.Println(*rule.Allowed)
	// Output:
	// true
}

// ExampleMarshalLimit demonstrates encoding a numeric per-tier ceiling.
// -1 is the conventional "unlimited" sentinel.
func ExampleMarshalLimit() {
	cell := tiering.MarshalLimit(50)
	var rule tiering.TierRule
	_ = json.Unmarshal(cell, &rule)
	fmt.Println(*rule.Limit)
	// Output:
	// 50
}
