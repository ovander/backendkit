package tiering

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const defaultCacheTTL = 5 * time.Minute

// PolicyService manages feature-to-tier access rules.
//
// Policies are stored in the database and cached in-process for CacheTTL
// (default 5 min) so that every plan check never hits the DB under load.
// The cache is invalidated immediately on every admin write (UpdatePolicy).
type PolicyService struct {
	repo     PolicyRepository
	registry *PlanRegistry
	selector PlanSelector
	logger   *logrus.Entry

	mu          sync.RWMutex
	cached      []*FeaturePolicy
	cacheExpiry time.Time
	cacheTTL    time.Duration
}

// NewPolicyService creates a PolicyService.
//   - registry is used to normalise plan strings before calling selector.
//   - selector picks the right JSON column from a FeaturePolicy for a given
//     normalised plan. Pass DefaultPlanSelector for freemium/pro/enterprise.
func NewPolicyService(repo PolicyRepository, registry *PlanRegistry, selector PlanSelector, logger *logrus.Entry) *PolicyService {
	if selector == nil {
		selector = DefaultPlanSelector
	}
	return &PolicyService{
		repo:     repo,
		registry: registry,
		selector: selector,
		logger:   logger,
		cacheTTL: defaultCacheTTL,
	}
}

// SetCacheTTL overrides the default 5-minute cache TTL. Must be called before
// the service is used.
func (s *PolicyService) SetCacheTTL(d time.Duration) { s.cacheTTL = d }

// SeedDefaults inserts the supplied baseline policies with ON CONFLICT DO
// NOTHING and invalidates the cache. Call once at startup.
func (s *PolicyService) SeedDefaults(policies []FeaturePolicy) error {
	if err := s.repo.SeedDefaults(policies); err != nil {
		return fmt.Errorf("feature policy seed: %w", err)
	}
	s.bust()
	s.logger.WithField("count", len(policies)).Info("feature policies seeded")
	return nil
}

// List returns all feature policies (from cache if fresh).
func (s *PolicyService) List() ([]*FeaturePolicy, error) {
	return s.all()
}

// UpdatePolicyRequest is the body for updating a single policy row.
type UpdatePolicyRequest struct {
	Feature    string
	Freemium   json.RawMessage
	Pro        json.RawMessage
	Enterprise json.RawMessage
}

// UpdatePolicy lets an admin change a single policy row and immediately busts
// the cache.
func (s *PolicyService) UpdatePolicy(req UpdatePolicyRequest) (*FeaturePolicy, error) {
	existing, err := s.repo.GetByFeature(req.Feature)
	if err != nil || existing == nil {
		return nil, fmt.Errorf("feature_policy %q not found", req.Feature)
	}

	if err := validateTierRules(existing.FeatureType, req.Freemium, req.Pro, req.Enterprise); err != nil {
		return nil, fmt.Errorf("invalid tier rules: %w", err)
	}

	existing.Freemium = req.Freemium
	existing.Pro = req.Pro
	existing.Enterprise = req.Enterprise

	if err := s.repo.Upsert(existing); err != nil {
		return nil, fmt.Errorf("save feature policy: %w", err)
	}

	s.bust()
	s.logger.WithField("feature", req.Feature).Info("feature policy updated")
	return existing, nil
}

// IsAllowed returns true when userPlan has access to the named feature.
// Falls back to false (deny) on any error.
func (s *PolicyService) IsAllowed(feature, userPlan string) bool {
	rule, err := s.ruleFor(feature, userPlan)
	if err != nil || rule.Allowed == nil {
		return false
	}
	return *rule.Allowed
}

// NumericLimit returns the ceiling for the named feature under userPlan.
// Returns -1 for unlimited, 0 when not found or on error.
func (s *PolicyService) NumericLimit(feature, userPlan string) int {
	rule, err := s.ruleFor(feature, userPlan)
	if err != nil || rule.Limit == nil {
		return 0
	}
	return *rule.Limit
}

// ────────────────────────────────────────────────────────────────────────────
// Internals
// ────────────────────────────────────────────────────────────────────────────

func (s *PolicyService) ruleFor(feature, userPlan string) (TierRule, error) {
	policies, err := s.all()
	if err != nil {
		return TierRule{}, err
	}

	normalised := s.registry.Normalise(userPlan)

	for _, p := range policies {
		if p.Feature != feature {
			continue
		}
		raw := s.selector(normalised, p)
		var rule TierRule
		if err := json.Unmarshal(raw, &rule); err != nil {
			return TierRule{}, fmt.Errorf("unmarshal rule for %q/%q: %w", feature, userPlan, err)
		}
		return rule, nil
	}
	return TierRule{}, fmt.Errorf("feature policy %q not found", feature)
}

// all returns the cached policy list, refreshing from DB when stale.
func (s *PolicyService) all() ([]*FeaturePolicy, error) {
	// Fast path: read-lock check.
	s.mu.RLock()
	if time.Now().Before(s.cacheExpiry) && s.cached != nil {
		defer s.mu.RUnlock()
		return s.cached, nil
	}
	s.mu.RUnlock()

	// Slow path: promote to write-lock and double-check.
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().Before(s.cacheExpiry) && s.cached != nil {
		return s.cached, nil
	}

	policies, err := s.repo.List()
	if err != nil {
		s.logger.WithError(err).Error("failed to refresh feature policy cache")
		if s.cached != nil {
			return s.cached, nil // serve stale rather than failing hard
		}
		return nil, fmt.Errorf("feature policies unavailable: %w", err)
	}

	s.cached = policies
	s.cacheExpiry = time.Now().Add(s.cacheTTL)
	return policies, nil
}

func (s *PolicyService) bust() {
	s.mu.Lock()
	s.cached = nil
	s.cacheExpiry = time.Time{}
	s.mu.Unlock()
}

// validateTierRules checks that each rule contains the right fields for ft.
func validateTierRules(ft FeatureType, tiers ...json.RawMessage) error {
	for _, raw := range tiers {
		var rule TierRule
		if err := json.Unmarshal(raw, &rule); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		switch ft {
		case FeatureTypeAccess:
			if rule.Allowed == nil {
				return fmt.Errorf("access feature requires {\"allowed\": bool}")
			}
		case FeatureTypeNumericLimit:
			if rule.Limit == nil {
				return fmt.Errorf("numeric_limit feature requires {\"limit\": int}")
			}
		}
	}
	return nil
}
