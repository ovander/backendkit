package pep_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/pep"
	"github.com/ovander/backendkit/socrate"
)

func TestMinimumMode_Table(t *testing.T) {
	const (
		allow   = "allow"
		deny    = "deny"
		unmet   = "unmet_mfa"
		outage  = "outage"
		proceed = ""
	)
	decision := func(kind, mode string) (*socrate.Decision, error) {
		switch kind {
		case allow:
			return &socrate.Decision{Allow: true, Mode: mode}, nil
		case deny:
			return &socrate.Decision{Allow: false, Rule: "r", Reason: "denied_by_rule", Mode: mode}, nil
		case unmet:
			return &socrate.Decision{Allow: true, Obligations: []string{socrate.ObligationMFA}, Mode: mode}, nil
		default: // outage: Socrate answered 503 with its mode
			return &socrate.Decision{Mode: mode}, errors.New("policy_unavailable")
		}
	}
	cases := []struct {
		server, floor, kind, want string
	}{
		// No floor: Socrate's mode, unchanged behaviour.
		{"off", "", deny, proceed},
		{"shadow", "", deny, proceed},
		{"enforce", "", deny, pep.CodeDenied},
		{"off", "off", unmet, proceed},
		{"shadow", "", outage, proceed},
		{"enforce", "", outage, pep.CodeUnavailable},
		// Floor enforce: enforced in every server mode.
		{"off", "enforce", allow, proceed},
		{"off", "enforce", deny, pep.CodeDenied},
		{"shadow", "enforce", deny, pep.CodeDenied},
		{"enforce", "enforce", deny, pep.CodeDenied},
		{"off", "enforce", unmet, pep.CodeMFARequired},
		{"shadow", "enforce", unmet, pep.CodeMFARequired},
		{"off", "enforce", outage, pep.CodeUnavailable},
		{"shadow", "enforce", outage, pep.CodeUnavailable},
		// Floor shadow: off becomes shadow (logged, proceeds); enforce stays enforce.
		{"off", "shadow", deny, proceed},
		{"off", "shadow", unmet, proceed},
		{"enforce", "shadow", deny, pep.CodeDenied},
		{"off", "shadow", outage, proceed},
		// A server mode this version does not know still fails closed.
		{"audit", "shadow", deny, pep.CodeDenied},
	}
	for _, c := range cases {
		d, err := decision(c.kind, c.server)
		e := newEnforcer(t, &fakeDecider{d: d, err: err}, func(cfg *pep.Config) { cfg.MinimumMode = c.floor })
		ctx := ctxutil.WithAMR(userCtx(), []string{"pwd"})
		if got := denialCode(e.Check(ctx, "a", socrate.PolicyResource{}, socrate.PolicyContext{})); got != c.want {
			t.Errorf("server=%s floor=%q %s: got %q, want %q", c.server, c.floor, c.kind, got, c.want)
		}
	}
}

// Before any decision has reported a mode, an outage refuses with the enforce
// floor even though FailOpenWhenModeUnknown would otherwise matter.
func TestMinimumMode_EnforceRefusesWhenModeUnknown(t *testing.T) {
	e := newEnforcer(t, &fakeDecider{err: errors.New("connection refused")}, func(cfg *pep.Config) {
		cfg.MinimumMode = socrate.PolicyModeEnforce
	})
	err := e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})
	var d *pep.Denial
	if !errors.As(err, &d) || d.Code != pep.CodeUnavailable || d.Status != 503 {
		t.Fatalf("got %v, want policy_unavailable 503", err)
	}

	// With the shadow floor and no mode known yet, the default still refuses
	// and FailOpenWhenModeUnknown still lets it through: the floor adds nothing
	// below enforce when the server mode is unknown.
	e = newEnforcer(t, &fakeDecider{err: errors.New("connection refused")}, func(cfg *pep.Config) {
		cfg.MinimumMode = socrate.PolicyModeShadow
	})
	if got := denialCode(e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})); got != pep.CodeUnavailable {
		t.Errorf("shadow floor, mode unknown: got %q, want refusal", got)
	}
	e = newEnforcer(t, &fakeDecider{err: errors.New("connection refused")}, func(cfg *pep.Config) {
		cfg.MinimumMode, cfg.FailOpenWhenModeUnknown = socrate.PolicyModeShadow, true
	})
	if got := denialCode(e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})); got != "" {
		t.Errorf("shadow floor + FailOpenWhenModeUnknown, mode unknown: got %q, want proceed", got)
	}
}

func TestNew_MinimumModeValidation(t *testing.T) {
	f := &fakeDecider{}
	for _, c := range []struct {
		floor    string
		failOpen bool
		ok       bool
	}{
		{"", false, true},
		{"off", true, true},
		{"shadow", true, true},
		{"enforce", false, true},
		{"enforce", true, false},
		{"strict", false, false},
		{"Enforce", false, false},
	} {
		_, err := pep.New(pep.Config{Decider: f, MinimumMode: c.floor, FailOpenWhenModeUnknown: c.failOpen})
		if (err == nil) != c.ok {
			t.Errorf("MinimumMode=%q FailOpen=%v: err=%v, want ok=%v", c.floor, c.failOpen, err, c.ok)
		}
	}
}

// OnDecision reports enforcement as applied, with the server's own mode in the decision.
func TestMinimumMode_OnDecisionReportsEnforcement(t *testing.T) {
	var enforced bool
	var mode string
	e := newEnforcer(t, &fakeDecider{d: &socrate.Decision{Allow: false, Mode: socrate.PolicyModeOff}}, func(cfg *pep.Config) {
		cfg.MinimumMode = socrate.PolicyModeEnforce
		cfg.OnDecision = func(_ context.Context, _ string, d *socrate.Decision, enf bool, _ error) {
			enforced, mode = enf, d.Mode
		}
	})
	_ = e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})
	if !enforced || mode != socrate.PolicyModeOff {
		t.Errorf("OnDecision enforced=%v mode=%q, want true and the server's off", enforced, mode)
	}
}
