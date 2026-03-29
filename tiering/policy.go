package tiering

import (
	"context"
	"encoding/json"
	"time"
)

// FeatureType distinguishes how a policy rule is evaluated.
type FeatureType string

const (
	// FeatureTypeAccess gates a boolean yes/no capability per tier.
	FeatureTypeAccess FeatureType = "access"
	// FeatureTypeNumericLimit gates a countable resource with a per-tier ceiling.
	FeatureTypeNumericLimit FeatureType = "numeric_limit"
)

// FeaturePolicy stores the access rules for a named platform feature across all
// commercial tiers. One row per feature; the primary key is the feature slug.
//
// Each tier column holds a small JSONB object whose shape depends on FeatureType:
//
//	access:        {"allowed": true}  or {"allowed": false}
//	numeric_limit: {"limit": 3}       or {"limit": -1}  (-1 = unlimited)
//
// The column names (Freemium, Pro, Enterprise) match the default Socrate plans.
// When using a custom PlanRegistry you may extend this struct or implement your
// own model; PolicyService selects the column via a caller-supplied Selector.
type FeaturePolicy struct {
	Feature     string          `gorm:"primaryKey"                   json:"feature"`
	Category    string          `gorm:"not null;index"               json:"category"`
	Label       string          `gorm:"not null"                     json:"label"`
	FeatureType FeatureType     `gorm:"column:feature_type;not null" json:"featureType"`
	Freemium    json.RawMessage `gorm:"type:jsonb;not null"          json:"freemium"`
	Pro         json.RawMessage `gorm:"type:jsonb;not null"          json:"pro"`
	Enterprise  json.RawMessage `gorm:"type:jsonb;not null"          json:"enterprise"`
	UpdatedAt   time.Time       `json:"updatedAt"`
}

// TierRule is the unmarshalled form of one per-tier policy cell.
type TierRule struct {
	// Allowed is populated for FeatureTypeAccess rows.
	Allowed *bool `json:"allowed,omitempty"`
	// Limit is populated for FeatureTypeNumericLimit rows (-1 = unlimited).
	Limit *int `json:"limit,omitempty"`
}

// MarshalAccess encodes a boolean access rule into a JSON policy cell.
func MarshalAccess(allowed bool) json.RawMessage {
	b, _ := json.Marshal(TierRule{Allowed: &allowed})
	return b
}

// MarshalLimit encodes a numeric limit rule into a JSON policy cell.
// Use -1 for unlimited.
func MarshalLimit(n int) json.RawMessage {
	b, _ := json.Marshal(TierRule{Limit: &n})
	return b
}

// PolicyRepository is the data-access interface that PolicyService depends on.
// Implement it with your GORM/SQL repository.
//
// All methods accept a context.Context so implementations can propagate
// cancellation, deadlines, and distributed tracing spans to the database.
type PolicyRepository interface {
	// List returns all feature policies.
	List(ctx context.Context) ([]*FeaturePolicy, error)
	// GetByFeature returns a single policy by its slug.
	GetByFeature(ctx context.Context, feature string) (*FeaturePolicy, error)
	// Upsert inserts or updates a policy row.
	Upsert(ctx context.Context, policy *FeaturePolicy) error
	// SeedDefaults inserts the supplied rows with ON CONFLICT DO NOTHING.
	SeedDefaults(ctx context.Context, policies []FeaturePolicy) error
}

// PlanSelector is a function that picks the right JSON column from a
// FeaturePolicy for a given (normalised) plan name.
//
// The default selector handles "freemium", "pro", "enterprise". Supply a
// custom one when using a different plan hierarchy.
//
//	func MySelector(plan string, p *tiering.FeaturePolicy) json.RawMessage {
//	    switch plan {
//	    case "starter": return p.Freemium
//	    case "growth":  return p.Pro
//	    default:        return p.Enterprise
//	    }
//	}
type PlanSelector func(plan string, p *FeaturePolicy) json.RawMessage

// DefaultPlanSelector maps freemium→Freemium, pro→Pro, else→Enterprise.
func DefaultPlanSelector(plan string, p *FeaturePolicy) json.RawMessage {
	switch plan {
	case PlanPro:
		return p.Pro
	case PlanEnterprise:
		return p.Enterprise
	default:
		return p.Freemium
	}
}
