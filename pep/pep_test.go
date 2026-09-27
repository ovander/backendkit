package pep_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/pep"
	"github.com/ovander/backendkit/socrate"
)

// fakeDecider returns a fixed answer and records what it was asked.
type fakeDecider struct {
	d    *socrate.Decision
	err  error
	last socrate.DecideRequest
	n    int
}

func (f *fakeDecider) Decide(_ context.Context, req socrate.DecideRequest) (*socrate.Decision, error) {
	f.n++
	f.last = req
	return f.d, f.err
}

func userCtx() context.Context {
	ctx := ctxutil.WithRawJWT(context.Background(), "user-token")
	ctx = ctxutil.WithAuthTime(ctx, time.Now().Unix())
	return ctxutil.WithAMR(ctx, []string{"pwd"})
}

func newEnforcer(t *testing.T, f *fakeDecider, mut ...func(*pep.Config)) *pep.Enforcer {
	t.Helper()
	cfg := pep.Config{Decider: f}
	for _, m := range mut {
		m(&cfg)
	}
	e, err := pep.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func denialCode(err error) string {
	var d *pep.Denial
	if errors.As(err, &d) {
		return d.Code
	}
	return ""
}

func TestCheck_ModeSemantics(t *testing.T) {
	deny := func(mode string) *socrate.Decision {
		return &socrate.Decision{Allow: false, Rule: "r", Reason: "denied_by_rule", Mode: mode}
	}
	cases := []struct {
		name string
		d    *socrate.Decision
		want string // "" = proceed
	}{
		{"off ignores a deny", deny(socrate.PolicyModeOff), ""},
		{"shadow logs a deny and proceeds", deny(socrate.PolicyModeShadow), ""},
		{"enforce refuses a deny", deny(socrate.PolicyModeEnforce), pep.CodeDenied},
		{"enforce passes an allow", &socrate.Decision{Allow: true, Mode: socrate.PolicyModeEnforce}, ""},
		{"an unknown future mode fails closed", deny("audit"), pep.CodeDenied},
	}
	for _, c := range cases {
		e := newEnforcer(t, &fakeDecider{d: c.d})
		if got := denialCode(e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCheck_SendsTheUsersOwnTokenAsSubject(t *testing.T) {
	f := &fakeDecider{d: &socrate.Decision{Allow: true, Mode: "enforce"}}
	e := newEnforcer(t, f)
	res := socrate.PolicyResource{Type: "invoice", ID: "inv-1", Attributes: map[string]any{"amount": 5}}
	_ = e.Check(userCtx(), "invoice.approve", res, socrate.PolicyContext{IP: "192.0.2.1"})
	if f.last.Subject == nil || f.last.Subject.Token != "user-token" || f.last.Subject.UserID != 0 ||
		f.last.Action != "invoice.approve" || f.last.Resource.ID != "inv-1" || f.last.Context.IP != "192.0.2.1" {
		t.Fatalf("request = %+v", f.last)
	}
}

// pep before jwtauth is a wiring bug. It must never degrade into deciding as
// the application.
func TestCheck_NoUserToken_IsUnauthenticated_AndNeverAsked(t *testing.T) {
	f := &fakeDecider{d: &socrate.Decision{Allow: true, Mode: "enforce"}}
	e := newEnforcer(t, f)
	if got := denialCode(e.Check(context.Background(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})); got != pep.CodeUnauthenticated {
		t.Fatalf("got %q", got)
	}
	if f.n != 0 {
		t.Fatal("Socrate was asked with no subject")
	}
}

func TestCheck_Obligations(t *testing.T) {
	allowWith := func(o ...string) *fakeDecider {
		return &fakeDecider{d: &socrate.Decision{Allow: true, Obligations: o, Mode: "enforce"}}
	}
	stale := ctxutil.WithAuthTime(userCtx(), time.Now().Add(-time.Hour).Unix())
	noAuthTime := ctxutil.WithAuthTime(userCtx(), 0)
	mfa := ctxutil.WithAMR(userCtx(), []string{"pwd", "otp", "mfa"})

	cases := []struct {
		name string
		ctx  context.Context
		f    *fakeDecider
		want string
	}{
		{"fresh auth met", userCtx(), allowWith(socrate.ObligationFreshAuth), ""},
		{"fresh auth stale", stale, allowWith(socrate.ObligationFreshAuth), pep.CodeElevationRequired},
		{"fresh auth unknown", noAuthTime, allowWith(socrate.ObligationFreshAuth), pep.CodeElevationRequired},
		{"mfa missing", userCtx(), allowWith(socrate.ObligationMFA), pep.CodeMFARequired},
		{"mfa present", mfa, allowWith(socrate.ObligationMFA), ""},
		{"unknown obligation", userCtx(), allowWith("require_hardware_key"), pep.CodeDenied},
	}
	for _, c := range cases {
		e := newEnforcer(t, c.f)
		if got := denialCode(e.Check(c.ctx, "a", socrate.PolicyResource{}, socrate.PolicyContext{})); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}

	// In shadow an unmet obligation is logged, not enforced.
	f := &fakeDecider{d: &socrate.Decision{Allow: true, Obligations: []string{socrate.ObligationMFA}, Mode: "shadow"}}
	if err := newEnforcer(t, f).Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{}); err != nil {
		t.Fatalf("shadow with unmet obligation: %v", err)
	}
}

// An outage is judged by the mode Socrate reported with it, else by the last
// mode seen, else — before any decision — by FailOpenWhenModeUnknown.
func TestCheck_Outages(t *testing.T) {
	down := errors.New("connection refused")

	// Never reached Socrate: refuses by default.
	e := newEnforcer(t, &fakeDecider{err: down})
	if got := denialCode(e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})); got != pep.CodeUnavailable {
		t.Fatalf("unknown mode: %q, want policy_unavailable", got)
	}
	// ...unless told otherwise.
	e = newEnforcer(t, &fakeDecider{err: down}, func(c *pep.Config) { c.FailOpenWhenModeUnknown = true })
	if err := e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{}); err != nil {
		t.Fatalf("FailOpenWhenModeUnknown: %v", err)
	}

	// Last seen shadow, then an outage: the application keeps working.
	f := &fakeDecider{d: &socrate.Decision{Allow: true, Mode: "shadow"}}
	e = newEnforcer(t, f)
	_ = e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})
	f.d, f.err = nil, down
	if err := e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{}); err != nil {
		t.Fatalf("outage after shadow: %v", err)
	}

	// Last seen enforce, then an outage: refuse.
	f = &fakeDecider{d: &socrate.Decision{Allow: true, Mode: "enforce"}}
	e = newEnforcer(t, f)
	_ = e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})
	f.d, f.err = nil, down
	if got := denialCode(e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})); got != pep.CodeUnavailable {
		t.Fatalf("outage after enforce: %q", got)
	}

	// Socrate answered 503 but said "shadow": trust what it said.
	e = newEnforcer(t, &fakeDecider{d: &socrate.Decision{Mode: "shadow"}, err: socrate.ErrPolicyUnavailable})
	if err := e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{}); err != nil {
		t.Fatalf("503 in shadow: %v", err)
	}
}

func TestMiddleware(t *testing.T) {
	f := &fakeDecider{d: &socrate.Decision{Allow: false, Mode: "enforce"}}
	e := newEnforcer(t, f)
	reached := false
	h := e.Middleware(func(r *http.Request) (string, socrate.PolicyResource, bool) {
		if r.URL.Path == "/public" {
			return "", socrate.PolicyResource{}, false
		}
		return "doc.read", socrate.PolicyResource{Type: "doc"}, true
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	serve := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil).WithContext(userCtx())
		req.RemoteAddr = "198.51.100.7:4321"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	rr := serve("/doc")
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), `"policy_denied"`) || reached {
		t.Fatalf("denied request: %d %s reached=%v", rr.Code, rr.Body.String(), reached)
	}
	if f.last.Context.IP != "198.51.100.7" {
		t.Fatalf("context ip = %q", f.last.Context.IP)
	}
	if rr := serve("/public"); rr.Code != http.StatusOK || !reached {
		t.Fatalf("ungated route: %d reached=%v", rr.Code, reached)
	}
}

func TestOnDecisionHook(t *testing.T) {
	var got []bool
	f := &fakeDecider{d: &socrate.Decision{Allow: false, Mode: "enforce"}}
	e := newEnforcer(t, f, func(c *pep.Config) {
		c.OnDecision = func(_ context.Context, _ string, _ *socrate.Decision, enforced bool, _ error) {
			got = append(got, enforced)
		}
	})
	_ = e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})
	f.d.Mode = "shadow"
	_ = e.Check(userCtx(), "a", socrate.PolicyResource{}, socrate.PolicyContext{})
	if len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("hook saw %v, want [true false]", got)
	}
}

func TestNew_RequiresDecider(t *testing.T) {
	if _, err := pep.New(pep.Config{}); err == nil {
		t.Fatal("New accepted a nil Decider")
	}
}

func TestWriteDenial(t *testing.T) {
	rr := httptest.NewRecorder()
	if pep.WriteDenial(rr, nil) {
		t.Fatal("nil error wrote a response")
	}
	rr = httptest.NewRecorder()
	if !pep.WriteDenial(rr, errors.New("boom")) || rr.Code != http.StatusInternalServerError {
		t.Fatalf("plain error → %d", rr.Code)
	}
}
