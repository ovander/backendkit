package bff

import (
	"context"
	"testing"
	"time"

	"github.com/ovander/backendkit/ctxutil"
)

func TestStepUp_AuthorizeParams(t *testing.T) {
	p := StepUp{}.AuthorizeParams()
	if p.Get("prompt") != "login" || p.Get("max_age") != "0" || p.Has("acr_values") {
		t.Errorf("StepUp{} params = %v, want prompt=login max_age=0 and no acr_values", p)
	}
	if got := (StepUp{RequireMFA: true}).AuthorizeParams().Get("acr_values"); got != "mfa" {
		t.Errorf("RequireMFA acr_values = %q, want mfa", got)
	}
}

func TestStepUp_Satisfied(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	mfa := []string{"pwd", "otp", "mfa"}
	pwd := []string{"pwd"}
	five := 5 * time.Minute
	for _, tc := range []struct {
		name     string
		s        StepUp
		authTime int64
		amr      []string
		maxAge   time.Duration
		want     bool
	}{
		{"recent", StepUp{}, now.Add(-time.Minute).Unix(), pwd, five, true},
		{"at the limit", StepUp{}, now.Add(-five).Unix(), pwd, five, true},
		{"too old", StepUp{}, now.Add(-five - time.Second).Unix(), pwd, five, false},
		{"unknown auth_time", StepUp{}, 0, mfa, five, false},
		// 0 is unknown, not 1970: refused even with a very long max age.
		{"unknown auth_time, long max age", StepUp{}, 0, mfa, 100 * 365 * 24 * time.Hour, false},
		{"negative max age", StepUp{}, now.Unix(), mfa, -time.Second, false},
		{"slightly in the future", StepUp{}, now.Add(30 * time.Second).Unix(), pwd, five, true},
		{"far in the future", StepUp{}, now.Add(2 * time.Minute).Unix(), pwd, five, false},
		{"mfa required and present", StepUp{RequireMFA: true}, now.Unix(), mfa, five, true},
		{"mfa required, password only", StepUp{RequireMFA: true}, now.Unix(), pwd, five, false},
		{"mfa required, no amr", StepUp{RequireMFA: true}, now.Unix(), nil, five, false},
	} {
		if got := tc.s.Satisfied(tc.authTime, tc.amr, tc.maxAge, now); got != tc.want {
			t.Errorf("%s: Satisfied = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestStepUp_SatisfiedByContext(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := StepUp{RequireMFA: true}
	if s.SatisfiedByContext(context.Background(), time.Hour, now) {
		t.Error("a request without auth_time satisfied the step-up")
	}
	ctx := ctxutil.WithAMR(ctxutil.WithAuthTime(context.Background(), now.Add(-time.Minute).Unix()), []string{"pwd", "otp", "mfa"})
	if !s.SatisfiedByContext(ctx, 5*time.Minute, now) {
		t.Error("a recent second-factor sign-in did not satisfy the step-up")
	}
}
