package bff

import (
	"context"
	"net/url"
	"slices"
	"time"

	"github.com/ovander/backendkit/ctxutil"
)

// StepUpClockSkew is how far in the future an auth_time may be and still be
// accepted by StepUp.Satisfied: the clocks of Socrate and of the checking
// service may differ a little.
const StepUpClockSkew = time.Minute

// StepUp is a step-up sign-in asked for before a sensitive action (an export,
// a payment, a change of rights): a fresh authentication on Socrate's login
// page and, with RequireMFA, a second factor.
//
// A BFF adds AuthorizeParams to the /oauth/authorize redirect of that login.
// The access token it then gets carries the sign-in's auth_time and amr; the
// service that performs the action checks them with Satisfied or
// SatisfiedByContext, since that check, not the request, is what protects
// the action.
type StepUp struct {
	// RequireMFA asks for a sign-in with a second factor (acr_values=mfa):
	// Socrate refuses one without it (unmet_authentication_requirements)
	// under its ACR_VALUES_MODE=enforce, and Satisfied requires "mfa" in amr
	// whatever that mode.
	RequireMFA bool
}

// AuthorizeParams returns the parameters to add to the /oauth/authorize
// request for this step-up: prompt=login and max_age=0 (OpenID Connect Core
// §3.1.2.1, a new sign-in whatever the session), and acr_values=mfa when
// RequireMFA. Socrate meets max_age=0 with the sign-in on its login page from
// v1.16.2, and acts on acr_values=mfa under ACR_VALUES_MODE from v1.16.2.
func (s StepUp) AuthorizeParams() url.Values {
	v := url.Values{"prompt": {"login"}, "max_age": {"0"}}
	if s.RequireMFA {
		v.Set("acr_values", "mfa")
	}
	return v
}

// Satisfied reports whether an authentication, given by its auth_time (Unix
// seconds) and amr (RFC 8176), meets this step-up at now: it happened at most
// maxAge ago (and not more than StepUpClockSkew in the future), and, with
// RequireMFA, amr contains "mfa". An unknown auth_time (0) or a negative
// maxAge never satisfies it (fail closed).
func (s StepUp) Satisfied(authTime int64, amr []string, maxAge time.Duration, now time.Time) bool {
	if authTime <= 0 || maxAge < 0 {
		return false
	}
	at := time.Unix(authTime, 0)
	if at.After(now.Add(StepUpClockSkew)) || now.Sub(at) > maxAge {
		return false
	}
	return !s.RequireMFA || slices.Contains(amr, "mfa")
}

// SatisfiedByContext is Satisfied for the request's access token, as
// jwtauth.Middleware recorded it (ctxutil.GetAuthTime, ctxutil.GetAMR). A
// request without them never satisfies it.
func (s StepUp) SatisfiedByContext(ctx context.Context, maxAge time.Duration, now time.Time) bool {
	return s.Satisfied(ctxutil.GetAuthTime(ctx), ctxutil.GetAMR(ctx), maxAge, now)
}
