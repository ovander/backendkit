// Package jwtauth provides an HTTP middleware that validates RS256 JWTs issued
// by Socrate. Public keys are fetched from the Socrate JWKS endpoint and
// cached for one hour (configurable); a refresh is attempted on cache miss or
// expiry, with graceful fallback to the stale cache on fetch failure.
//
// Validated claims are stored in the request context via ctxutil helpers so
// that all downstream middleware and handlers can read them without importing
// this package.
package jwtauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/ovander/backendkit/apierror"
	"github.com/ovander/backendkit/ctxutil"
)

// SocrateClaims is the JWT claims structure emitted by Socrate.
//
// Claims present in every access token issued by the server:
//   - RegisteredClaims.Subject ("sub") — numeric user ID as a string, e.g. "42"
//   - Role          — the user's app-scoped role (admin, manager, editor, viewer, user)
//   - AppRoles      — map of app client_id → role for all apps the user belongs to
//   - TokenVersion  — monotonic counter; incremented on password change / token revocation
//
// Claims NOT issued by the default Socrate server (require custom server configuration):
//   - TenantID — multi-tenancy identifier, read from the tenant_id claim, or from the claim
//     named by WithTenantClaim; empty unless the server is configured to issue it
//   - Plan     — commercial tier; will be empty, causing GetUserPlan to default to "freemium"
//
// Claims only present in ID tokens (OIDC flow), NOT in access tokens:
//   - Email, Name — present in /oauth/userinfo response but not in the bearer access token.
//     Use GetCurrentUserProfile() to fetch them when needed.
type SocrateClaims struct {
	// Standard Socrate access-token claims.
	Role         string            `json:"role,omitempty"`
	AppRoles     map[string]string `json:"app_roles,omitempty"`
	TokenVersion int               `json:"token_version,omitempty"`
	// AuthTime and Amr say when and how the user authenticated (RFC 9068 /
	// OIDC auth_time, RFC 8176 amr). They are what a step-up or MFA check —
	// including a policy obligation (pep) — needs to look at.
	AuthTime int64    `json:"auth_time,omitempty"`
	Amr      []string `json:"amr,omitempty"`

	// Custom claims — require server-side configuration to be populated.
	// With WithTenantClaim, the middleware replaces TenantID with the value of
	// the named claim (empty when the token does not carry it).
	TenantID string `json:"tenant_id,omitempty"`
	Plan     string `json:"plan,omitempty"`

	// ID-token-only claims (empty in access tokens; use GetCurrentUserProfile instead).
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`

	jwt.RegisteredClaims

	// scopes holds the token's scopes, read by validateToken from the scope
	// and scp claims of the verified payload (see Scopes); scopesErr records a
	// scope or scp claim of an unexpected JSON type.
	scopes    []string
	scopesErr error
}

// Scopes returns the token's OAuth scopes: the space-separated scope claim
// (RFC 8693 §4.2, RFC 9068 §2.2.3; what Socrate emits) and the scp claim (a
// JSON array of strings, or a single space-separated string, as other issuers
// emit it). When both are present the result is their union, in token order
// (scope first), without duplicates or empty values. It returns nil when the
// token carries neither claim, when a claim has an unexpected JSON type, and
// for claims not produced by the middleware's validation. The result is a
// copy.
func (c *SocrateClaims) Scopes() []string {
	if c == nil || len(c.scopes) == 0 {
		return nil
	}
	return append([]string(nil), c.scopes...)
}

// jwksKey represents a single key from a JWKS endpoint.
type jwksKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksResponse is the full JWKS endpoint payload.
type jwksResponse struct {
	Keys []jwksKey `json:"keys"`
}

// Middleware validates RS256 JWTs using RSA public keys from a JWKS endpoint.
type Middleware struct {
	jwksURL string
	issuer  string
	// audiences are the accepted aud values; a token passes when its aud
	// intersects them. audienceSet records that an audience option was given,
	// so that WithAudiences with no usable value rejects every token instead of
	// silently disabling the check.
	audiences       []string
	audienceSet     bool
	revocationCheck RevocationChecker
	// writeErr writes rejections; nil uses the default JSON envelope.
	writeErr apierror.ErrorWriter
	// tenantClaim is the claim the tenant is read from when tenantClaimSet
	// (WithTenantClaim); otherwise it is tenant_id, decoded into SocrateClaims.
	// An empty tenantClaim with tenantClaimSet rejects every token.
	tenantClaim    string
	tenantClaimSet bool
	// requiredScopes are the scopes every token must carry when
	// requiredScopesSet (RequireScopes); an empty set with requiredScopesSet
	// rejects every token.
	requiredScopes    []string
	requiredScopesSet bool
	logger            *logrus.Entry
	httpClient        *http.Client
	cacheTTL          time.Duration

	// leeway is the clock-skew tolerance applied to time-based claim validation
	// (exp/nbf/iat). See WithLeeway.
	leeway time.Duration

	// minRefetchInterval is the minimum wall-clock gap between outbound JWKS
	// refetches. A cache miss (unknown kid) within this window does NOT trigger
	// a network fetch — it returns key-not-found — so an attacker presenting
	// tokens with random kids cannot force one outbound fetch per request. The
	// first miss after the window elapses triggers exactly one refetch, so a
	// legitimately rotated kid still resolves. See WithMinRefetchInterval.
	minRefetchInterval time.Duration

	// negativeCacheTTL is how long a recently-seen unknown kid is remembered so
	// repeated tokens bearing that kid short-circuit without attempting work.
	// See WithNegativeCacheTTL.
	negativeCacheTTL time.Duration

	// sf coalesces concurrent refetches: N simultaneous cache misses trigger a
	// single outbound JWKS fetch rather than N (single-flight).
	sf singleflight.Group

	mu                 sync.RWMutex
	keys               map[string]*rsa.PublicKey
	lastFetch          time.Time
	lastRefetchAttempt time.Time
	negativeCache      map[string]time.Time // kid → time it was last seen unknown
}

// Option configures optional Middleware behaviour. Pass options to New.
type Option func(*Middleware)

// RevocationChecker reports whether an already-validated token is still live.
// It runs after signature, algorithm, issuer, audience and expiry checks have
// passed, receiving the request context and the parsed claims. Returning a
// non-nil error rejects the request with 401.
//
// The context already carries the raw bearer token (ctxutil.GetRawJWT), so a
// checker can introspect it at Socrate (/oauth/introspect). The identity
// values (ctxutil.GetUserID and the like) are not set yet: they are injected
// only once the check has passed.
//
// Use it to enforce revocation that signature validation alone cannot — most
// commonly comparing claims.TokenVersion against the current value for
// claims.Subject (incremented on password change / logout), or consulting a
// jti denylist via claims.ID.
type RevocationChecker func(ctx context.Context, claims *SocrateClaims) error

// WithAudience enables JWT audience ("aud") validation. When set, a token is
// accepted only if its aud claim contains expectedAudience — typically this
// service's OAuth client_id. This prevents a token minted for one app from
// being replayed against another app that shares the same issuer and JWKS.
//
// Audience validation is opt-in for backward compatibility: when WithAudience is
// not supplied the aud claim is not checked. New services should set it. A token
// that lacks an aud claim is rejected when an expected audience is configured.
//
// WithAudience(a) is WithAudiences(a), except that WithAudience("") keeps its
// historical meaning of no audience check.
func WithAudience(expectedAudience string) Option {
	return func(m *Middleware) {
		if expectedAudience == "" {
			m.audiences, m.audienceSet = nil, false
			return
		}
		m.audiences, m.audienceSet = []string{expectedAudience}, true
	}
}

// WithAudiences enables JWT audience ("aud") validation against a set: a token
// is accepted only if its aud claim contains at least one of the expected
// audiences. Use it for a route group that serves several applications of the
// same Socrate (for example a portal and two service accounts); each token is
// still bound to one of them, and its role claim is that application's role.
//
// Empty strings and duplicates are ignored. Fail closed: when no non-empty
// audience is given, every token is rejected (and New logs an error), rather
// than the check being disabled. A token that lacks an aud claim is rejected.
// The last audience option passed to New wins.
func WithAudiences(expectedAudiences ...string) Option {
	return func(m *Middleware) {
		var set []string
		for _, a := range expectedAudiences {
			if a != "" && !slices.Contains(set, a) {
				set = append(set, a)
			}
		}
		m.audiences, m.audienceSet = set, true
	}
}

// WithErrorWriter sets how the middleware writes its 401 responses (missing
// or invalid bearer, invalid or expired token, revoked token, invalid tenant
// claim) and its 403 response (a required scope missing, see RequireScopes). Pass apierror.ProblemWriter for RFC 9457 application/problem+json.
// Without it, or with nil, the default apierror JSON envelope is written,
// byte-for-byte as before.
func WithErrorWriter(write apierror.ErrorWriter) Option {
	return func(m *Middleware) { m.writeErr = write }
}

// WithRevocationCheck enables a post-validation revocation check. The supplied
// function runs on every request after the token's signature and claims have
// been validated; a non-nil return rejects the request with 401.
//
// Revocation is opt-in for backward compatibility: with no checker configured a
// token remains accepted until its exp, regardless of token_version. Services
// that need logout / password-change / admin revocation to take effect before
// expiry should supply one, e.g.:
//
//	auth := jwtauth.New(jwksURL, issuer, logger,
//	    jwtauth.WithRevocationCheck(func(ctx context.Context, c *jwtauth.SocrateClaims) error {
//	        if c.TokenVersion < store.CurrentTokenVersion(ctx, c.Subject) {
//	            return errors.New("token_version superseded")
//	        }
//	        return nil
//	    }))
func WithRevocationCheck(fn RevocationChecker) Option {
	return func(m *Middleware) { m.revocationCheck = fn }
}

// WithTenantClaim names the claim the tenant is read from, instead of
// tenant_id. Use it when the issuer does not emit a plain tenant_id: a stock
// Socrate projects custom claims through a client's claim mappings under its
// claims namespace, so a mapping named tenant_id reaches the token as
// "https://socrate/tenant_id":
//
//	auth := jwtauth.New(jwksURL, issuer, logger,
//	    jwtauth.WithAudience(clientID),
//	    jwtauth.WithTenantClaim("https://socrate/tenant_id"))
//
// The tenant still comes only from the signed token. With this option, the
// named claim replaces SocrateClaims.TenantID (so a RevocationChecker sees the
// same tenant as the request context) and a plain tenant_id claim is ignored.
// The claim must be a string holding a UUID: any other value rejects the token
// with 401. When the token does not carry the claim, no tenant is set and
// httpware.RequireTenant rejects the request.
//
// Fail closed: an empty or blank name rejects every token (and New logs an
// error) rather than falling back to tenant_id. The last WithTenantClaim
// passed to New wins.
func WithTenantClaim(name string) Option {
	return func(m *Middleware) {
		m.tenantClaim, m.tenantClaimSet = strings.TrimSpace(name), true
	}
}

// RequireScopes makes the middleware accept a token only when it carries every
// one of scopes (see SocrateClaims.Scopes for how the scope and scp claims are
// read). A valid token that lacks one is rejected with 403 (RFC 6750 §3.1
// insufficient_scope) through the configured error writer, with a
// WWW-Authenticate header naming the required scopes; the identity values are
// not injected. A token whose scope or scp claim has an unexpected JSON type
// is rejected the same way.
//
// Use it on the Middleware of a route group that only a service account may
// call, for example a worker API that requires its own scope:
//
//	worker := jwtauth.New(jwksURL, issuer, logger,
//	    jwtauth.WithAudience("my-api"),
//	    jwtauth.RequireScopes("my-api:worker"))
//
// Empty strings and duplicates are ignored. Fail closed: when no non-empty
// scope is given, every token is rejected (and New logs an error) rather than
// the check being disabled. The last RequireScopes passed to New wins.
func RequireScopes(scopes ...string) Option {
	return func(m *Middleware) {
		var set []string
		for _, sc := range scopes {
			if sc = strings.TrimSpace(sc); sc != "" && !slices.Contains(set, sc) {
				set = append(set, sc)
			}
		}
		m.requiredScopes, m.requiredScopesSet = set, true
	}
}

// WithLeeway sets the clock-skew tolerance applied to time-based claim checks
// (exp/nbf/iat). The default is 60s. A negative value is ignored.
func WithLeeway(d time.Duration) Option {
	return func(m *Middleware) {
		if d >= 0 {
			m.leeway = d
		}
	}
}

// WithMinRefetchInterval sets the minimum interval between outbound JWKS
// refetches (default 15s). Within this window a token bearing an unknown kid is
// rejected without a network fetch, so an attacker cannot turn unknown-kid
// tokens into one outbound request per attempt. Set a small value in tests that
// need a rotated key to resolve quickly. A non-positive value is ignored.
func WithMinRefetchInterval(d time.Duration) Option {
	return func(m *Middleware) {
		if d > 0 {
			m.minRefetchInterval = d
		}
	}
}

// WithNegativeCacheTTL sets how long a recently-seen unknown kid is remembered
// so repeated unknown-kid tokens short-circuit without work (default 30s). A
// non-positive value is ignored.
func WithNegativeCacheTTL(d time.Duration) Option {
	return func(m *Middleware) {
		if d > 0 {
			m.negativeCacheTTL = d
		}
	}
}

// New creates a Middleware that validates tokens against the JWKS at jwksURL.
// issuer is optional; when non-empty it is enforced via jwt.WithIssuer.
//
// Optional behaviour (e.g. audience validation) is configured via opts; see
// WithAudience. Passing no options preserves the historical behaviour, so
// existing three-argument calls continue to compile and behave unchanged.
//
// When issuer is empty the iss claim is not enforced; New logs a warning at
// construction so the disabled check is visible at startup rather than silent.
// It does the same when no WithAudience option is given: without it a token
// issued to another application on the same Socrate validates here, and its
// role claim (the user's role in that application) is trusted.
func New(jwksURL, issuer string, logger *logrus.Entry, opts ...Option) *Middleware {
	m := &Middleware{
		jwksURL:            jwksURL,
		issuer:             issuer,
		logger:             logger,
		httpClient:         &http.Client{Timeout: 10 * time.Second},
		keys:               make(map[string]*rsa.PublicKey),
		cacheTTL:           1 * time.Hour,
		leeway:             60 * time.Second,
		minRefetchInterval: 15 * time.Second,
		negativeCacheTTL:   30 * time.Second,
	}
	for _, opt := range opts {
		opt(m)
	}
	if issuer == "" && logger != nil {
		logger.Warn("jwtauth: issuer validation disabled (empty issuer) — set issuer to enforce the iss claim")
	}
	if !m.audienceSet && logger != nil {
		logger.Warn("jwtauth: audience validation disabled — pass WithAudience(clientID), or tokens issued to other applications on the same issuer are accepted, with their role")
	}
	if m.audienceSet && len(m.audiences) == 0 && logger != nil {
		logger.Error("jwtauth: WithAudiences was given no audience — every token is rejected")
	}
	if m.requiredScopesSet && len(m.requiredScopes) == 0 && logger != nil {
		logger.Error("jwtauth: RequireScopes was given no scope — every token is rejected")
	}
	if m.tenantClaimSet && m.tenantClaim == "" && logger != nil {
		logger.Error("jwtauth: WithTenantClaim was given an empty claim name — every token is rejected")
	}
	return m
}

// Handler is the chi-compatible middleware function.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearer(r)
		if err != nil {
			m.logger.WithError(err).Warn("missing bearer token")
			m.writeError(w, r, apierror.Unauthorized("missing or invalid authorization header"))
			return
		}

		claims, err := m.validateToken(token)
		if err != nil {
			m.logger.WithError(err).Warn("token validation failed")
			m.writeError(w, r, apierror.Unauthorized("invalid or expired token"))
			return
		}

		// Store the raw JWT so downstream clients (e.g. socrate.Client) can
		// forward it without re-parsing; use ctxutil.GetRawJWT to retrieve it.
		// It is set before the revocation check so a checker can introspect it.
		ctx := ctxutil.WithRawJWT(r.Context(), token)

		// Optional revocation check (e.g. token_version / denylist). Runs after
		// validation so a revoked token never has its identity injected.
		if m.revocationCheck != nil {
			if err := m.revocationCheck(ctx, claims); err != nil {
				m.logger.WithError(err).Warn("token revoked")
				m.writeError(w, r, apierror.Unauthorized("token revoked"))
				return
			}
		}

		if m.requiredScopesSet {
			if missing := m.missingScopes(claims); missing != nil {
				m.logger.WithField("missing_scopes", missing).Warn("token lacks a required scope")
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q`, strings.Join(m.requiredScopes, " ")))
				m.writeError(w, r, apierror.Forbidden("insufficient scope"))
				return
			}
		}
		if sc := claims.Scopes(); len(sc) > 0 {
			ctx = ctxutil.WithScopes(ctx, sc)
		}

		// tenant_id — only present when the server is configured to issue it.
		if claims.TenantID != "" {
			tenantID, err := uuid.Parse(claims.TenantID)
			if err != nil {
				m.logger.WithError(err).Warn("invalid tenant_id in claims")
				m.writeError(w, r, apierror.Unauthorized("invalid tenant_id"))
				return
			}
			ctx = ctxutil.WithTenantID(ctx, tenantID)
		}

		// sub — Socrate issues a numeric string (e.g. "42"); parse as UUID or derive one.
		if sub := claims.Subject; sub != "" {
			userID, err := uuid.Parse(sub)
			if err != nil {
				// Deterministic UUID from the opaque numeric Socrate subject.
				userID = uuid.NewSHA1(uuid.NameSpaceDNS, []byte("socrate:"+sub))
			}
			ctx = ctxutil.WithUserID(ctx, userID)
			ctx = ctxutil.WithUserSub(ctx, sub)
		}

		// email / name — only non-empty when an ID token is used as the bearer token.
		// For standard access tokens use socrate.Client.GetCurrentUserProfile() instead.
		if claims.Email != "" {
			ctx = ctxutil.WithUserEmail(ctx, claims.Email)
		}
		if claims.Name != "" {
			ctx = ctxutil.WithUserName(ctx, claims.Name)
		}
		if claims.Role != "" {
			ctx = ctxutil.WithUserRole(ctx, claims.Role)
		}
		// plan — only present when the server is configured to issue it.
		// Defaults to "freemium" via ctxutil.GetUserPlan when absent.
		if claims.Plan != "" {
			ctx = ctxutil.WithUserPlan(ctx, claims.Plan)
		}
		if len(claims.AppRoles) > 0 {
			ctx = ctxutil.WithAppRoles(ctx, claims.AppRoles)
		}
		if claims.TokenVersion != 0 {
			ctx = ctxutil.WithTokenVersion(ctx, claims.TokenVersion)
		}
		if claims.AuthTime != 0 {
			ctx = ctxutil.WithAuthTime(ctx, claims.AuthTime)
		}
		if claims.Amr != nil {
			ctx = ctxutil.WithAMR(ctx, claims.Amr)
		}
		// aud — the audiences the token was accepted for (ctxutil.GetAudiences).
		if aud := m.acceptedAudiences(claims.Audience); len(aud) > 0 {
			ctx = ctxutil.WithAudiences(ctx, aud)
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

// acceptedAudiences returns the token's aud values the token was accepted for:
// those in the configured set when an audience check is configured, else all
// of them; in the token's order, without duplicates or empty values.
func (m *Middleware) acceptedAudiences(tokenAud []string) []string {
	var out []string
	for _, a := range tokenAud {
		if a == "" || slices.Contains(out, a) {
			continue
		}
		if m.audienceSet && !slices.Contains(m.audiences, a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func (m *Middleware) writeError(w http.ResponseWriter, r *http.Request, e *apierror.AppError) {
	if m.writeErr != nil {
		m.writeErr(w, r, e)
		return
	}
	e.WriteJSON(w)
}

func extractBearer(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid Authorization header format")
	}
	return parts[1], nil
}

func (m *Middleware) validateToken(tokenString string) (*SocrateClaims, error) {
	claims := &SocrateClaims{}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256"}),
		// Reject tokens minted without an exp claim (a missing exp otherwise
		// means "never expires"). Also apply a small leeway for clock skew.
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(m.leeway),
	}
	if m.issuer != "" {
		opts = append(opts, jwt.WithIssuer(m.issuer))
	}
	if m.audienceSet {
		if len(m.audiences) == 0 {
			return nil, fmt.Errorf("token invalid")
		}
		// jwt.WithAudience accepts the token when its aud contains any of them.
		opts = append(opts, jwt.WithAudience(m.audiences...))
	}

	tok, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("token missing kid header")
		}
		return m.getKey(kid)
	}, opts...)

	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("token invalid")
	}
	claims.scopes, claims.scopesErr = scopeClaims(tokenString)
	if m.tenantClaimSet {
		tenant, err := stringClaim(tokenString, m.tenantClaim)
		if err != nil {
			return nil, err
		}
		claims.TenantID = tenant
	}
	return claims, nil
}

// missingScopes returns the required scopes the token lacks, every required
// scope when its scope claims are malformed, and a non-nil empty slice when
// RequireScopes was given none (fail closed); nil means the token passes.
func (m *Middleware) missingScopes(claims *SocrateClaims) []string {
	if len(m.requiredScopes) == 0 {
		return []string{}
	}
	if claims.scopesErr != nil {
		return m.requiredScopes
	}
	var missing []string
	for _, sc := range m.requiredScopes {
		if !slices.Contains(claims.scopes, sc) {
			missing = append(missing, sc)
		}
	}
	return missing
}

// scopeClaims reads the scope (space-separated string) and scp (array of
// strings, or a space-separated string) claims of an already-verified token
// and returns their union. Like stringClaim, it decodes the payload a second
// time because the two claims have shapes SocrateClaims cannot type, and a
// malformed claim must not fail validation for callers that never look at
// scopes: the error is returned for RequireScopes to act on.
func scopeClaims(tokenString string) ([]string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token payload: %w", err)
	}
	var all struct {
		Scope json.RawMessage `json:"scope"`
		Scp   json.RawMessage `json:"scp"`
	}
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, fmt.Errorf("token payload: %w", err)
	}
	var out []string
	add := func(values ...string) {
		for _, v := range values {
			for _, f := range strings.Fields(v) {
				if !slices.Contains(out, f) {
					out = append(out, f)
				}
			}
		}
	}
	for _, c := range []struct {
		name     string
		raw      json.RawMessage
		arrayToo bool
	}{{"scope", all.Scope, false}, {"scp", all.Scp, true}} {
		if len(c.raw) == 0 || strings.TrimSpace(string(c.raw)) == "null" {
			continue
		}
		var single string
		if err := json.Unmarshal(c.raw, &single); err == nil {
			add(single)
			continue
		}
		var list []string
		if c.arrayToo && json.Unmarshal(c.raw, &list) == nil {
			add(list...)
			continue
		}
		return nil, fmt.Errorf("claim %q has an unexpected type", c.name)
	}
	return out, nil
}

// stringClaim returns the named claim of an already-verified token: "" when
// absent, an error when it is not a JSON string. SocrateClaims cannot carry a
// claim whose name is only known at run time, hence the second decode of the
// payload, which runs only after the signature has been checked.
func stringClaim(tokenString, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("tenant claim not configured")
	}
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("token invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("token payload: %w", err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(payload, &all); err != nil {
		return "", fmt.Errorf("token payload: %w", err)
	}
	raw, ok := all[name]
	if !ok {
		return "", nil
	}
	// json.Unmarshal accepts null into a string without error; a present claim
	// that is not a string is rejected, null included.
	var v string
	if strings.TrimSpace(string(raw)) == "null" || json.Unmarshal(raw, &v) != nil {
		return "", fmt.Errorf("claim %q is not a string", name)
	}
	return v, nil
}

func (m *Middleware) getKey(kid string) (*rsa.PublicKey, error) {
	m.mu.RLock()
	key, ok := m.keys[kid]
	expired := time.Since(m.lastFetch) > m.cacheTTL
	inCooldown := time.Since(m.lastRefetchAttempt) < m.minRefetchInterval
	negAt, negged := m.negativeCache[kid]
	negFresh := negged && time.Since(negAt) < m.negativeCacheTTL
	m.mu.RUnlock()

	// Fast path: a fresh, known key.
	if ok && !expired {
		return key, nil
	}

	// Negative cache: this kid was recently seen and was absent from the JWKS.
	// Don't attempt any work — repeated unknown-kid tokens can't accumulate cost.
	if !ok && negFresh {
		return nil, fmt.Errorf("kid %q not found in JWKS", kid)
	}

	// Cooldown: within minRefetchInterval of the last refetch attempt we do NOT
	// hit the network. A miss here means an unknown kid cannot force an outbound
	// fetch per request; a stale-but-present key is still served rather than
	// dropped. The first miss AFTER the window triggers exactly one refetch, so a
	// legitimately rotated kid still resolves.
	if inCooldown {
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("kid %q not found in JWKS", kid)
	}

	// Single-flight: coalesce concurrent refetches so N simultaneous misses
	// trigger a single outbound JWKS fetch.
	_, err, _ := m.sf.Do("jwks-refetch", func() (interface{}, error) {
		m.mu.Lock()
		m.lastRefetchAttempt = time.Now()
		m.mu.Unlock()
		return nil, m.fetchJWKS()
	})
	if err != nil {
		if ok {
			m.logger.WithError(err).Warn("JWKS refresh failed, using cached key")
			return key, nil
		}
		return nil, err
	}

	m.mu.RLock()
	key, ok = m.keys[kid]
	m.mu.RUnlock()
	if !ok {
		m.rememberUnknownKid(kid)
		return nil, fmt.Errorf("kid %q not found in JWKS", kid)
	}
	return key, nil
}

// rememberUnknownKid records kid in the negative cache and opportunistically
// prunes expired entries so a stream of distinct unknown kids can't grow the map
// without bound.
func (m *Middleware) rememberUnknownKid(kid string) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.negativeCache == nil {
		m.negativeCache = make(map[string]time.Time)
	}
	for k, t := range m.negativeCache {
		if now.Sub(t) >= m.negativeCacheTTL {
			delete(m.negativeCache, k)
		}
	}
	m.negativeCache[kid] = now
}

func (m *Middleware) fetchJWKS() error {
	if m.jwksURL == "" {
		return fmt.Errorf("jwtauth: JWKS URL not configured")
	}
	resp, err := m.httpClient.Get(m.jwksURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&jwks); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			m.logger.WithError(err).WithField("kid", k.Kid).Warn("failed to parse JWKS key")
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return fmt.Errorf("no usable RSA signing keys in JWKS")
	}

	m.mu.Lock()
	m.keys = keys
	m.lastFetch = time.Now()
	// Fresh key material may include a previously-unknown kid, so drop negative
	// cache entries that would otherwise mask a just-rotated key.
	m.negativeCache = nil
	m.mu.Unlock()

	m.logger.WithField("key_count", len(keys)).Debug("JWKS keys refreshed")
	return nil
}

const (
	// maxJWKSBytes caps how much of a JWKS response is read into memory. JWKS
	// documents are small; this guards against an oversized/hostile endpoint.
	maxJWKSBytes = 1 << 20 // 1 MiB

	// minRSAKeyBits is the smallest RSA modulus accepted from a JWKS endpoint.
	// Keys below this are rejected as insufficiently strong (INV-13).
	minRSAKeyBits = 2048
	// maxRSAExponent bounds the public exponent to a sane range — far above the
	// conventional 65537 — so malformed/oversized exponents are rejected rather
	// than silently truncated.
	maxRSAExponent = 1 << 31
)

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	if n.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("RSA modulus too small: %d bits (minimum %d)", n.BitLen(), minRSAKeyBits)
	}

	// The public exponent must be an odd integer > 1 that fits in an int.
	// Reject (rather than silently truncate via Int64) anything outside that range.
	eBig := new(big.Int).SetBytes(eBytes)
	if !eBig.IsInt64() {
		return nil, fmt.Errorf("RSA public exponent too large")
	}
	e := eBig.Int64()
	if e < 3 || e > maxRSAExponent || e&1 == 0 {
		return nil, fmt.Errorf("invalid RSA public exponent: %d", e)
	}

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}
