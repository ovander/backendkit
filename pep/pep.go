// Package pep is the policy enforcement point for applications built on
// backendkit (A4 part 2 / EPIC-11 / RFC-004). It asks Socrate's policy
// decision point about each action and acts on the answer according to the
// mode Socrate reports with it:
//
//	off      the decision is ignored — the request proceeds
//	shadow   a denial is logged ("would deny") — the request proceeds
//	enforce  a denial is refused with 403
//
// The mode is set once, centrally, by Socrate's POLICY_MODE, so an operator
// rolls a policy out across every application at once and no application
// needs a redeploy to go from shadow to enforce. An application that must be
// stricter than the server (enforce its rules while POLICY_MODE is still off
// or shadow for the others) sets Config.MinimumMode: the effective mode is
// the stricter of the two.
//
// Two ways to use it:
//
//	// Route-level: one decision per request, before the handler.
//	r.Use(enforcer.Middleware(func(r *http.Request) (string, socrate.PolicyResource, bool) {
//	    return "invoice.read", socrate.PolicyResource{Type: "invoice"}, true
//	}))
//
//	// Object-level: inside a handler, once the resource is loaded.
//	if err := enforcer.Check(r.Context(), "invoice.approve", socrate.PolicyResource{
//	    Type: "invoice", ID: inv.ID, Attributes: map[string]any{"amount": inv.Amount, "owner_id": inv.OwnerID},
//	}, pep.ContextFor(r)); pep.WriteDenial(w, err) {
//	    return
//	}
//
// Both must run after jwtauth.Middleware: the user's own access token is sent
// as the decision's subject, and Socrate verifies it.
package pep

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/socrate"
)

// DefaultFreshAuthMaxAge matches Socrate's default admin step-up window.
const DefaultFreshAuthMaxAge = 5 * time.Minute

// Denial codes, returned as {"error": code}. elevation_required and
// mfa_required are the same codes Socrate's own admin API uses, so a client
// that already handles step-up there handles it here.
const (
	CodeDenied            = "policy_denied"
	CodeElevationRequired = "elevation_required"
	CodeMFARequired       = "mfa_required"
	CodeUnavailable       = "policy_unavailable"
	CodeUnauthenticated   = "unauthenticated"
)

// Decider is what an Enforcer consults. *socrate.Client satisfies it.
type Decider interface {
	Decide(ctx context.Context, req socrate.DecideRequest) (*socrate.Decision, error)
}

// Config configures an Enforcer.
type Config struct {
	// Decider is required — normally the application's *socrate.Client.
	Decider Decider
	// FreshAuthMaxAge is the window for the require_fresh_auth obligation.
	// Zero uses DefaultFreshAuthMaxAge.
	FreshAuthMaxAge time.Duration
	// FailOpenWhenModeUnknown decides what happens when Socrate cannot be
	// reached before any decision has told this process the mode. The
	// default, false, refuses (503): a process that starts while Socrate is
	// down and policy is enforced must not quietly let everything through.
	// Once one decision has arrived the last known mode is used instead, so
	// an outage during shadow never takes the application down.
	FailOpenWhenModeUnknown bool
	// MinimumMode is a floor under the mode Socrate reports: the effective
	// mode is the stricter of the two (off < shadow < enforce). Empty or
	// "off", the default, follows Socrate exactly. With "enforce", in every
	// server mode: a rule's deny is a deny (403), an unmet obligation is a
	// deny (elevation_required / mfa_required), and an unreachable decision
	// point is a *Denial with policy_unavailable (503) for the caller to map,
	// even before any decision has reported a mode. With "shadow", a server in
	// off mode is treated as shadow (would-deny lines are logged). Socrate
	// evaluates its rules in every mode, so floor-enforced decisions are real
	// decisions. MinimumMode "enforce" together with FailOpenWhenModeUnknown is
	// contradictory and New refuses it; an unknown value is refused too.
	MinimumMode string
	// Logger receives would-deny lines in shadow mode and outage warnings.
	Logger *logrus.Entry
	// OnDecision, when set, is called once per check — for metrics. err is
	// the Decider's error, if any; enforced reports whether the request was
	// refused.
	OnDecision func(ctx context.Context, action string, d *socrate.Decision, enforced bool, err error)
}

// Enforcer applies Socrate's decisions.
type Enforcer struct {
	cfg      Config
	lastMode atomic.Value // string
}

// New returns an Enforcer.
func New(cfg Config) (*Enforcer, error) {
	if cfg.Decider == nil {
		return nil, errors.New("pep: Decider is required")
	}
	if cfg.MinimumMode == "" {
		cfg.MinimumMode = socrate.PolicyModeOff
	}
	if _, ok := modeRank[cfg.MinimumMode]; !ok {
		return nil, errors.New("pep: MinimumMode must be off, shadow or enforce")
	}
	if cfg.MinimumMode == socrate.PolicyModeEnforce && cfg.FailOpenWhenModeUnknown {
		return nil, errors.New("pep: MinimumMode enforce and FailOpenWhenModeUnknown contradict each other")
	}
	if cfg.FreshAuthMaxAge <= 0 {
		cfg.FreshAuthMaxAge = DefaultFreshAuthMaxAge
	}
	if cfg.Logger == nil {
		cfg.Logger = logrus.NewEntry(logrus.StandardLogger())
	}
	return &Enforcer{cfg: cfg}, nil
}

// Denial is returned by Check when a request must be refused.
type Denial struct {
	Code     string
	Status   int
	Decision *socrate.Decision // nil when Socrate could not be asked
}

func (d *Denial) Error() string { return "pep: " + d.Code }

// Check asks about action on resource for the user in ctx and applies the
// mode. A nil error means proceed; a *Denial means refuse (see WriteDenial).
func (e *Enforcer) Check(ctx context.Context, action string, resource socrate.PolicyResource, pctx socrate.PolicyContext) error {
	token := ctxutil.GetRawJWT(ctx)
	if token == "" {
		// Without the user's token there is no subject to decide for. This
		// is a wiring error (pep before jwtauth), never a reason to evaluate
		// the request as the application itself.
		return &Denial{Code: CodeUnauthenticated, Status: http.StatusUnauthorized}
	}
	return e.check(ctx, socrate.DecideRequest{
		Subject:  &socrate.PolicySubject{Token: token},
		Action:   action,
		Resource: resource,
		Context:  pctx,
	})
}

// CheckAsApp decides for the application itself (no user), e.g. for a
// background job. The same mode semantics apply.
func (e *Enforcer) CheckAsApp(ctx context.Context, action string, resource socrate.PolicyResource) error {
	return e.check(ctx, socrate.DecideRequest{Action: action, Resource: resource})
}

func (e *Enforcer) check(ctx context.Context, req socrate.DecideRequest) error {
	d, err := e.cfg.Decider.Decide(ctx, req)
	if err != nil {
		denial := e.unavailable(ctx, req.Action, d, err)
		e.report(ctx, req.Action, d, denial != nil, err)
		return denial
	}
	e.lastMode.Store(d.Mode)

	unmet := ""
	if d.Allow {
		unmet = e.unmetObligation(ctx, d.Obligations)
	}
	allowed := d.Allow && unmet == ""

	mode := e.effectiveMode(d.Mode)
	switch {
	case allowed || mode == socrate.PolicyModeOff:
		e.report(ctx, req.Action, d, false, nil)
		return nil
	case mode == socrate.PolicyModeShadow:
		e.log(ctx).WithFields(logrus.Fields{
			"action":         req.Action,
			"rule":           d.Rule,
			"reason":         d.Reason,
			"unmet":          unmet,
			"policy_version": d.PolicyVersion,
			"server_mode":    d.Mode,
		}).Warn("pep: policy would deny (shadow mode)")
		e.report(ctx, req.Action, d, false, nil)
		return nil
	default:
		// enforce — and any mode this version does not know, which fails
		// closed rather than guessing.
		denial := &Denial{Code: CodeDenied, Status: http.StatusForbidden, Decision: d}
		switch unmet {
		case socrate.ObligationFreshAuth:
			denial.Code = CodeElevationRequired
		case socrate.ObligationMFA:
			denial.Code = CodeMFARequired
		}
		e.report(ctx, req.Action, d, true, nil)
		return denial
	}
}

// unavailable decides what an error means, from the mode Socrate reported
// with it or, failing that, the last mode seen.
func (e *Enforcer) unavailable(ctx context.Context, action string, d *socrate.Decision, err error) error {
	mode := ""
	if d != nil && d.Mode != "" {
		mode = d.Mode
		e.lastMode.Store(mode)
	} else if m, ok := e.lastMode.Load().(string); ok {
		mode = m
	}

	if mode != "" || e.cfg.MinimumMode == socrate.PolicyModeEnforce {
		mode = e.effectiveMode(mode)
	}
	entry := e.log(ctx).WithFields(logrus.Fields{"action": action, "mode": mode, "error": err.Error()})
	switch mode {
	case socrate.PolicyModeOff, socrate.PolicyModeShadow:
		entry.Warn("pep: policy decision unavailable; proceeding (not enforced)")
		return nil
	case "":
		if e.cfg.FailOpenWhenModeUnknown {
			entry.Warn("pep: policy decision unavailable and mode unknown; proceeding (FailOpenWhenModeUnknown)")
			return nil
		}
		entry.Error("pep: policy decision unavailable and mode unknown; refusing")
	default:
		entry.Error("pep: policy decision unavailable in enforce mode; refusing")
	}
	return &Denial{Code: CodeUnavailable, Status: http.StatusServiceUnavailable, Decision: d}
}

// modeRank orders the modes this version knows, from the most permissive.
var modeRank = map[string]int{
	socrate.PolicyModeOff:     0,
	socrate.PolicyModeShadow:  1,
	socrate.PolicyModeEnforce: 2,
}

// effectiveMode is the stricter of the server's mode and MinimumMode. A server
// mode this version does not know is returned as is (check treats it as
// enforce); an empty one (unknown) counts as off, so only the floor applies.
func (e *Enforcer) effectiveMode(server string) string {
	r, known := modeRank[server]
	if !known && server != "" {
		return server
	}
	if modeRank[e.cfg.MinimumMode] > r {
		return e.cfg.MinimumMode
	}
	return server
}

// unmetObligation returns the first obligation the user's token does not
// satisfy. The facts come from the token jwtauth verified.
func (e *Enforcer) unmetObligation(ctx context.Context, obligations []string) string {
	for _, o := range obligations {
		switch o {
		case socrate.ObligationFreshAuth:
			at := ctxutil.GetAuthTime(ctx)
			if at == 0 || time.Since(time.Unix(at, 0)) > e.cfg.FreshAuthMaxAge {
				return o
			}
		case socrate.ObligationMFA:
			if !slices.Contains(ctxutil.GetAMR(ctx), "mfa") {
				return o
			}
		default:
			// An obligation this version cannot honour is not silently
			// dropped: treat it as unmet.
			return o
		}
	}
	return ""
}

func (e *Enforcer) report(ctx context.Context, action string, d *socrate.Decision, enforced bool, err error) {
	if e.cfg.OnDecision != nil {
		e.cfg.OnDecision(ctx, action, d, enforced, err)
	}
}

func (e *Enforcer) log(ctx context.Context) *logrus.Entry {
	entry := e.cfg.Logger
	if id := ctxutil.GetRequestID(ctx); id != "" {
		entry = entry.WithField("request_id", id)
	}
	return entry
}

// Route maps a request to the action and resource to decide on. ok=false
// leaves the request ungated.
type Route func(r *http.Request) (action string, resource socrate.PolicyResource, ok bool)

// Middleware gates each request the route maps to an action.
func (e *Enforcer) Middleware(route Route) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			action, resource, ok := route(r)
			if !ok {
				next.ServeHTTP(w, r)
				return
			}
			if WriteDenial(w, e.Check(r.Context(), action, resource, ContextFor(r))) {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ContextFor builds the decision context from a request: the peer address.
// Behind a proxy, set RemoteAddr correctly first (a trusted real-IP
// middleware) — a spoofable X-Forwarded-For must never reach a policy.
func ContextFor(r *http.Request) socrate.PolicyContext {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return socrate.PolicyContext{IP: host}
}

// WriteDenial writes err as a JSON error response and reports whether it did.
// A nil err writes nothing and returns false; any error that is not a
// *Denial is written as 500.
func WriteDenial(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var d *Denial
	status, code := http.StatusInternalServerError, "internal_error"
	if errors.As(err, &d) {
		status, code = d.Status, d.Code
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
	return true
}

var _ Decider = (*socrate.Client)(nil)
