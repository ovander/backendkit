// Package tiering provides plan-based feature gating for multi-tier SaaS
// applications that use Socrate as their OAuth2 provider.
//
// It has three components:
//
//  1. PlanRegistry — an ordered list of plan names that defines the tier
//     hierarchy used by TierAtLeast and the Gate middleware.
//  2. Gate — an HTTP middleware that enforces a minimum plan on route groups.
//  3. PolicyService — a DB-backed, in-memory-cached store of per-feature
//     access rules, one JSON column per tier.
//
// Applications typically create a single PlanRegistry at startup and share it
// with both Gate and PolicyService.
package tiering

// PlanRegistry holds an ordered list of plan names, lowest to highest tier.
// Pass it to Gate and PolicyService so both use the same ordering.
type PlanRegistry struct {
	plans []string          // ordered: index 0 = lowest tier
	index map[string]int    // plan name → position
}

// NewPlanRegistry creates a PlanRegistry from the given ordered plan names.
// The first element is the lowest tier (e.g. "freemium"); the last is the
// highest (e.g. "enterprise"). Duplicate names are ignored.
func NewPlanRegistry(plans ...string) *PlanRegistry {
	r := &PlanRegistry{index: make(map[string]int)}
	for _, p := range plans {
		if _, dup := r.index[p]; !dup {
			r.index[p] = len(r.plans)
			r.plans = append(r.plans, p)
		}
	}
	return r
}

// DefaultRegistry returns the standard Socrate plan hierarchy used by Kerplan
// and sister projects: freemium < pro < enterprise.
func DefaultRegistry() *PlanRegistry {
	return NewPlanRegistry(PlanFreemium, PlanPro, PlanEnterprise)
}

// Standard plan names matching Socrate's JWT "plan" claim values.
const (
	PlanFreemium   = "freemium"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

// Plans returns the ordered slice of plan names.
func (r *PlanRegistry) Plans() []string {
	cp := make([]string, len(r.plans))
	copy(cp, r.plans)
	return cp
}

// Lowest returns the name of the lowest-tier plan.
func (r *PlanRegistry) Lowest() string {
	if len(r.plans) == 0 {
		return ""
	}
	return r.plans[0]
}

// TierAtLeast returns true when current is at least as high as required in the
// registry's ordering. Unknown plan names return false.
func (r *PlanRegistry) TierAtLeast(current, required string) bool {
	cur, okC := r.index[current]
	req, okR := r.index[required]
	if !okC || !okR {
		return false
	}
	return cur >= req
}

// Normalise maps an arbitrary plan string to one present in the registry.
// Unknown values are mapped to the lowest tier.
func (r *PlanRegistry) Normalise(plan string) string {
	if _, ok := r.index[plan]; ok {
		return plan
	}
	return r.Lowest()
}
