//go:build conformance

// Live conformance: the enforcement point against Socrate's real decision
// point. Run with scripts/conformance-local.sh (see package conformance for the
// environment; SOCRATE_POLICY_MODE is the server's POLICY_MODE). Without that
// environment the tests fail: the build tag is the opt-in.

package pep_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/pep"
	"github.com/ovander/backendkit/socrate"
)

const liveUser = "conf-pep@example.test"

func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: the conformance tests need a running Socrate (scripts/conformance-local.sh)", name)
	}
	return v
}

// liveClient returns a client for the plain conformance client, with the app
// id taken from its service token's sub ("app:<id>").
func liveClient(t *testing.T) *socrate.Client {
	t.Helper()
	cfg := socrate.ClientConfig{
		BaseURL:      liveEnv(t, "SOCRATE_ISSUER"),
		AdminBaseURL: liveEnv(t, "SOCRATE_ADMIN_URL"),
		ClientID:     liveEnv(t, "SOCRATE_PLAIN_CLIENT_ID"),
		ClientSecret: liveEnv(t, "SOCRATE_PLAIN_CLIENT_SECRET"),
		Timeout:      30 * time.Second,
	}
	c, err := socrate.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := c.ServiceToken(context.Background())
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	in, err := c.IntrospectToken(context.Background(), tok)
	if err != nil || !strings.HasPrefix(in.Sub, "app:") {
		t.Fatalf("introspect the service token: %+v, %v", in, err)
	}
	cfg.AppID = strings.TrimPrefix(in.Sub, "app:")
	if c, err = socrate.NewClient(cfg); err != nil {
		t.Fatal(err)
	}
	return c
}

// liveUserToken signs the test user in through the direct login API.
func liveUserToken(t *testing.T) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"email": liveUser, "password": liveEnv(t, "SOCRATE_USER_PASSWORD"),
		"app_client_id": liveEnv(t, "SOCRATE_PLAIN_CLIENT_ID"),
	})
	resp, err := http.Post(liveEnv(t, "SOCRATE_ISSUER")+"/api/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &out) != nil || out.AccessToken == "" {
		t.Fatalf("login: HTTP %d", resp.StatusCode)
	}
	return out.AccessToken
}

// No rule in Socrate's baseline covers an application action, so every
// decision below is a deny with reason no_applicable_rule — a real decision,
// reported with the server's mode.
const (
	liveAction   = "conformance.read"
	liveNoRule   = "no_applicable_rule"
	liveResource = "conformance"
)

func TestConformanceDecide(t *testing.T) {
	c := liveClient(t)
	mode := liveEnv(t, "SOCRATE_POLICY_MODE")
	tok := liveUserToken(t)
	ctx := context.Background()

	for name, subject := range map[string]*socrate.PolicySubject{
		"user token":  {Token: tok},
		"application": nil,
	} {
		t.Run(name, func(t *testing.T) {
			d, err := c.Decide(ctx, socrate.DecideRequest{
				Subject: subject, Action: liveAction,
				Resource: socrate.PolicyResource{Type: liveResource, ID: "1"},
				Context:  socrate.PolicyContext{IP: "203.0.113.7"},
			})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if d.Mode != mode || d.Allow || d.Reason != liveNoRule || d.PolicyVersion < 1 || !d.PEPModeAccepted {
				t.Errorf("decision = %+v, want mode %s, deny %s, a policy version, pep_mode_accepted", d, mode, liveNoRule)
			}
		})
	}

	// pep_mode is accepted (v1.13.0+), and the admin namespace is refused.
	if _, err := c.Decide(ctx, socrate.DecideRequest{Action: liveAction, PEPMode: socrate.PolicyModeEnforce}); err != nil {
		t.Errorf("Decide with pep_mode: %v", err)
	}
	if _, err := c.Decide(ctx, socrate.DecideRequest{Action: "GET /api/admin/apps"}); !errors.Is(err, socrate.ErrPolicyRequestRejected) {
		t.Errorf("Decide on an admin action: %v, want ErrPolicyRequestRejected", err)
	}
}

func TestConformanceEnforcer(t *testing.T) {
	c := liveClient(t)
	if mode := liveEnv(t, "SOCRATE_POLICY_MODE"); mode != socrate.PolicyModeOff {
		t.Fatalf("this test expects POLICY_MODE=off on the server, got %s", mode)
	}
	userCtx := ctxutil.WithRawJWT(context.Background(), liveUserToken(t))
	res := socrate.PolicyResource{Type: liveResource, ID: "1"}

	// Following the server (off), the deny is ignored.
	follow, err := pep.New(pep.Config{Decider: c})
	if err != nil {
		t.Fatal(err)
	}
	if err := follow.Check(userCtx, liveAction, res, socrate.PolicyContext{}); err != nil {
		t.Errorf("Check in off mode: %v, want nil", err)
	}
	if err := follow.CheckAsApp(context.Background(), liveAction, res); err != nil {
		t.Errorf("CheckAsApp in off mode: %v, want nil", err)
	}

	// An enforcement point stricter than the server enforces the same deny.
	var decisions int
	strict, err := pep.New(pep.Config{Decider: c, MinimumMode: socrate.PolicyModeEnforce,
		OnDecision: func(context.Context, string, *socrate.Decision, bool, error) { decisions++ }})
	if err != nil {
		t.Fatal(err)
	}
	err = strict.Check(userCtx, liveAction, res, socrate.PolicyContext{})
	var denial *pep.Denial
	if !errors.As(err, &denial) || denial.Code != pep.CodeDenied || denial.Status != http.StatusForbidden ||
		denial.Decision == nil || denial.Decision.Reason != liveNoRule {
		t.Fatalf("strict Check = %v, want a 403 policy_denied for %s", err, liveNoRule)
	}

	// The middleware refuses the request before the handler.
	reached := false
	h := strict.Middleware(func(*http.Request) (string, socrate.PolicyResource, bool) {
		return liveAction, res, true
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(userCtx))
	if w.Code != http.StatusForbidden || reached {
		t.Errorf("strict middleware: HTTP %d, handler reached %v, want 403 and not reached", w.Code, reached)
	}
	if decisions != 2 {
		t.Errorf("OnDecision called %d times, want 2", decisions)
	}
}
