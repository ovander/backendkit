package tiering_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/tiering"
)

// ────────────────────────────────────────────────────────────────────────────
// PlanRegistry
// ────────────────────────────────────────────────────────────────────────────

func TestPlanRegistry_TierAtLeast(t *testing.T) {
	r := tiering.DefaultRegistry()
	tests := []struct {
		current, required string
		want              bool
	}{
		{tiering.PlanFreemium, tiering.PlanFreemium, true},
		{tiering.PlanPro, tiering.PlanFreemium, true},
		{tiering.PlanEnterprise, tiering.PlanPro, true},
		{tiering.PlanFreemium, tiering.PlanPro, false},
		{tiering.PlanPro, tiering.PlanEnterprise, false},
		{"unknown", tiering.PlanFreemium, false},
	}
	for _, tt := range tests {
		got := r.TierAtLeast(tt.current, tt.required)
		if got != tt.want {
			t.Errorf("TierAtLeast(%q, %q) = %v, want %v", tt.current, tt.required, got, tt.want)
		}
	}
}

func TestPlanRegistry_Normalise(t *testing.T) {
	r := tiering.DefaultRegistry()
	if got := r.Normalise("unknown"); got != tiering.PlanFreemium {
		t.Errorf("Normalise(unknown) = %q, want freemium", got)
	}
	if got := r.Normalise(tiering.PlanPro); got != tiering.PlanPro {
		t.Errorf("Normalise(pro) = %q, want pro", got)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Gate middleware
// ────────────────────────────────────────────────────────────────────────────

func newTestLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(nopWriter{})
	return logrus.NewEntry(l)
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

func requestWithPlan(plan string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return r.WithContext(ctxutil.WithUserPlan(r.Context(), plan))
}

func TestGate_AllowsWhenPlanMeetsRequirement(t *testing.T) {
	g := tiering.NewGate(tiering.DefaultRegistry(), newTestLogger(), "")
	h := g.Require(tiering.PlanPro)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithPlan(tiering.PlanPro))
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestGate_DeniesWhenPlanBelowRequirement(t *testing.T) {
	g := tiering.NewGate(tiering.DefaultRegistry(), newTestLogger(), "/upgrade")
	h := g.Require(tiering.PlanEnterprise)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithPlan(tiering.PlanPro))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestGate_UnknownPlanTreatedAsLowest(t *testing.T) {
	g := tiering.NewGate(tiering.DefaultRegistry(), newTestLogger(), "")
	h := g.Require(tiering.PlanPro)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithPlan("mystery"))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for unknown plan, got %d", w.Code)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// PolicyService
// ────────────────────────────────────────────────────────────────────────────

// fakeRepo is an in-memory PolicyRepository for tests.
type fakeRepo struct {
	policies []*tiering.FeaturePolicy
}

func (r *fakeRepo) List() ([]*tiering.FeaturePolicy, error) { return r.policies, nil }
func (r *fakeRepo) GetByFeature(feature string) (*tiering.FeaturePolicy, error) {
	for _, p := range r.policies {
		if p.Feature == feature {
			return p, nil
		}
	}
	return nil, errors.New("not found")
}
func (r *fakeRepo) Upsert(p *tiering.FeaturePolicy) error {
	for i, existing := range r.policies {
		if existing.Feature == p.Feature {
			r.policies[i] = p
			return nil
		}
	}
	r.policies = append(r.policies, p)
	return nil
}
func (r *fakeRepo) SeedDefaults(policies []tiering.FeaturePolicy) error {
	for i := range policies {
		_ = r.Upsert(&policies[i])
	}
	return nil
}

func newPolicyService(policies []*tiering.FeaturePolicy) *tiering.PolicyService {
	repo := &fakeRepo{policies: policies}
	reg := tiering.DefaultRegistry()
	return tiering.NewPolicyService(repo, reg, tiering.DefaultPlanSelector, logrus.NewEntry(logrus.New()))
}

func TestPolicyService_IsAllowed_AccessFeature(t *testing.T) {
	yes := tiering.MarshalAccess(true)
	no := tiering.MarshalAccess(false)

	svc := newPolicyService([]*tiering.FeaturePolicy{
		{Feature: "my_feature", FeatureType: tiering.FeatureTypeAccess, Freemium: no, Pro: yes, Enterprise: yes},
	})

	if svc.IsAllowed("my_feature", tiering.PlanFreemium) {
		t.Error("freemium should not have access")
	}
	if !svc.IsAllowed("my_feature", tiering.PlanPro) {
		t.Error("pro should have access")
	}
}

func TestPolicyService_NumericLimit(t *testing.T) {
	svc := newPolicyService([]*tiering.FeaturePolicy{
		{
			Feature: "max_items", FeatureType: tiering.FeatureTypeNumericLimit,
			Freemium: tiering.MarshalLimit(1), Pro: tiering.MarshalLimit(5), Enterprise: tiering.MarshalLimit(-1),
		},
	})

	if got := svc.NumericLimit("max_items", tiering.PlanFreemium); got != 1 {
		t.Errorf("freemium limit = %d, want 1", got)
	}
	if got := svc.NumericLimit("max_items", tiering.PlanPro); got != 5 {
		t.Errorf("pro limit = %d, want 5", got)
	}
	if got := svc.NumericLimit("max_items", tiering.PlanEnterprise); got != -1 {
		t.Errorf("enterprise limit = %d, want -1 (unlimited)", got)
	}
}

func TestPolicyService_UnknownFeatureReturnsZero(t *testing.T) {
	svc := newPolicyService(nil)
	if svc.IsAllowed("no_such_feature", tiering.PlanPro) {
		t.Error("unknown feature should return false")
	}
}

func TestMarshalHelpers(t *testing.T) {
	yes := tiering.MarshalAccess(true)
	var r tiering.TierRule
	if err := json.Unmarshal(yes, &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.Allowed == nil || !*r.Allowed {
		t.Error("MarshalAccess(true) should produce allowed=true")
	}

	lim := tiering.MarshalLimit(42)
	var r2 tiering.TierRule
	json.Unmarshal(lim, &r2)
	if r2.Limit == nil || *r2.Limit != 42 {
		t.Error("MarshalLimit(42) should produce limit=42")
	}
}
