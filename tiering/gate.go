package tiering

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/apierror"
	"github.com/ovander/backendkit/ctxutil"
)

// UpgradeDetails carries the plan-upgrade context attached to a 403 response
// from Gate. It is embedded in apierror.AppError.Details so the outer JSON
// shape is consistent with all other error responses in the library:
//
//	{"error": {"code":"upgrade_required","message":"...","details":{...}}}
type UpgradeDetails struct {
	Plan         string `json:"plan"`
	RequiredPlan string `json:"requiredPlan"`
	UpgradeURL   string `json:"upgradeUrl,omitempty"`
}

// Gate is an HTTP middleware that enforces plan requirements on route groups.
// The user's commercial plan is read from the request context (set by the auth
// middleware via ctxutil.WithUserPlan). No extra DB lookup is performed.
type Gate struct {
	registry   *PlanRegistry
	logger     *logrus.Entry
	upgradeURL string
}

// NewGate creates a Gate backed by registry. upgradeURL is embedded in the 403
// response body so clients can redirect the user; pass "" to omit it.
func NewGate(registry *PlanRegistry, logger *logrus.Entry, upgradeURL string) *Gate {
	return &Gate{registry: registry, logger: logger, upgradeURL: upgradeURL}
}

// Require returns an HTTP middleware that allows only users whose plan is >=
// minPlan according to the PlanRegistry. Unknown / missing plans are treated as
// the lowest tier.
//
//	r.Group(func(r chi.Router) {
//	    r.Use(gate.Require(tiering.PlanEnterprise))
//	    r.Mount("/cap-table", capTableRouter)
//	})
func (g *Gate) Require(minPlan string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			userPlan := g.registry.Normalise(ctxutil.GetUserPlan(ctx))

			if !g.registry.TierAtLeast(userPlan, minPlan) {
				g.logger.WithFields(logrus.Fields{
					"user_plan":     userPlan,
					"required_plan": minPlan,
				}).Warn("plan gate: upgrade required")

				(&apierror.AppError{
					Code:       "upgrade_required",
					StatusCode: http.StatusForbidden,
					Message:    "This feature requires the " + minPlan + " plan or above",
					Details: UpgradeDetails{
						Plan:         userPlan,
						RequiredPlan: minPlan,
						UpgradeURL:   g.upgradeURL,
					},
				}).WriteJSON(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
