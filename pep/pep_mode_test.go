package pep_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/ovander/backendkit/pep"
	"github.com/ovander/backendkit/socrate"
)

// scriptedDecider answers allow in off mode, advertises pep_mode when
// accepts is set, and rejects a request carrying pep_mode when rejects is set
// (an older Socrate). It records the pep_mode of every request.
type scriptedDecider struct {
	accepts, rejects bool
	sent             []string
}

func (s *scriptedDecider) Decide(_ context.Context, req socrate.DecideRequest) (*socrate.Decision, error) {
	s.sent = append(s.sent, req.PEPMode)
	if s.rejects && req.PEPMode != "" {
		return nil, fmt.Errorf("%w: decide HTTP 400: unknown field", socrate.ErrPolicyRequestRejected)
	}
	return &socrate.Decision{Allow: true, Mode: socrate.PolicyModeOff, PEPModeAccepted: s.accepts}, nil
}

func checkN(t *testing.T, e *pep.Enforcer, n int) {
	t.Helper()
	for range n {
		if err := e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{}); err != nil {
			t.Fatalf("check: %v", err)
		}
	}
}

func equal(a, b []string) bool { return fmt.Sprint(a) == fmt.Sprint(b) }

func TestPEPMode_SentOnlyOnceSocrateAcceptsIt(t *testing.T) {
	s := &scriptedDecider{accepts: true}
	e, err := pep.New(pep.Config{Decider: s, MinimumMode: socrate.PolicyModeEnforce})
	if err != nil {
		t.Fatal(err)
	}
	checkN(t, e, 3)
	// The first request cannot know yet; the next ones report the floor.
	if want := []string{"", "enforce", "enforce"}; !equal(s.sent, want) {
		t.Errorf("pep_mode sent = %q, want %q", s.sent, want)
	}
}

func TestPEPMode_NeverSentToAnOlderSocrate(t *testing.T) {
	s := &scriptedDecider{}
	e, _ := pep.New(pep.Config{Decider: s, MinimumMode: socrate.PolicyModeShadow})
	checkN(t, e, 3)
	if want := []string{"", "", ""}; !equal(s.sent, want) {
		t.Errorf("pep_mode sent = %q, want none", s.sent)
	}
}

func TestPEPMode_NotSentWithoutAFloor(t *testing.T) {
	s := &scriptedDecider{accepts: true}
	e, _ := pep.New(pep.Config{Decider: s})
	checkN(t, e, 3)
	if want := []string{"", "", ""}; !equal(s.sent, want) {
		t.Errorf("pep_mode sent = %q, want none without MinimumMode", s.sent)
	}
}

// A Socrate that advertised the field and then rejects it (downgraded) costs
// no decision: the request is asked again without it, and it is not sent again.
func TestPEPMode_RejectedIsRetriedWithoutAndForgotten(t *testing.T) {
	s := &scriptedDecider{accepts: true}
	e, _ := pep.New(pep.Config{Decider: s, MinimumMode: socrate.PolicyModeEnforce})
	checkN(t, e, 1) // learns the flag
	s.accepts, s.rejects = false, true
	checkN(t, e, 2)
	if want := []string{"", "enforce", "", ""}; !equal(s.sent, want) {
		t.Errorf("pep_mode sent = %q, want %q", s.sent, want)
	}
}
