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
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

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
//   - TenantID — multi-tenancy identifier; will be empty unless the server is extended
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

	// Custom claims — require server-side configuration to be populated.
	TenantID string `json:"tenant_id,omitempty"`
	Plan     string `json:"plan,omitempty"`

	// ID-token-only claims (empty in access tokens; use GetCurrentUserProfile instead).
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`

	jwt.RegisteredClaims
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
	jwksURL         string
	issuer          string
	audience        string
	revocationCheck RevocationChecker
	logger          *logrus.Entry
	httpClient      *http.Client
	cacheTTL        time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

// Option configures optional Middleware behaviour. Pass options to New.
type Option func(*Middleware)

// RevocationChecker reports whether an already-validated token is still live.
// It runs after signature, algorithm, issuer, audience and expiry checks have
// passed, receiving the request context and the parsed claims. Returning a
// non-nil error rejects the request with 401.
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
func WithAudience(expectedAudience string) Option {
	return func(m *Middleware) { m.audience = expectedAudience }
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

// New creates a Middleware that validates tokens against the JWKS at jwksURL.
// issuer is optional; when non-empty it is enforced via jwt.WithIssuer.
//
// Optional behaviour (e.g. audience validation) is configured via opts; see
// WithAudience. Passing no options preserves the historical behaviour, so
// existing three-argument calls continue to compile and behave unchanged.
//
// When issuer is empty the iss claim is not enforced; New logs a warning at
// construction so the disabled check is visible at startup rather than silent.
func New(jwksURL, issuer string, logger *logrus.Entry, opts ...Option) *Middleware {
	m := &Middleware{
		jwksURL:    jwksURL,
		issuer:     issuer,
		logger:     logger,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]*rsa.PublicKey),
		cacheTTL:   1 * time.Hour,
	}
	for _, opt := range opts {
		opt(m)
	}
	if issuer == "" && logger != nil {
		logger.Warn("jwtauth: issuer validation disabled (empty issuer) — set issuer to enforce the iss claim")
	}
	return m
}

// Handler is the chi-compatible middleware function.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := extractBearer(r)
		if err != nil {
			m.logger.WithError(err).Warn("missing bearer token")
			apierror.Unauthorized("missing or invalid authorization header").WriteJSON(w)
			return
		}

		claims, err := m.validateToken(token)
		if err != nil {
			m.logger.WithError(err).Warn("token validation failed")
			apierror.Unauthorized("invalid or expired token").WriteJSON(w)
			return
		}

		// Optional revocation check (e.g. token_version / denylist). Runs after
		// validation so a revoked token never has its identity injected.
		if m.revocationCheck != nil {
			if err := m.revocationCheck(r.Context(), claims); err != nil {
				m.logger.WithError(err).Warn("token revoked")
				apierror.Unauthorized("token revoked").WriteJSON(w)
				return
			}
		}

		ctx := r.Context()

		// tenant_id — only present when the server is configured to issue it.
		if claims.TenantID != "" {
			tenantID, err := uuid.Parse(claims.TenantID)
			if err != nil {
				m.logger.WithError(err).Warn("invalid tenant_id in claims")
				apierror.Unauthorized("invalid tenant_id").WriteJSON(w)
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

		// Store raw JWT so downstream clients (e.g. socrate.Client) can forward
		// it without re-parsing. Use ctxutil.GetRawJWT to retrieve it.
		ctx = ctxutil.WithRawJWT(ctx, token)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ────────────────────────────────────────────────────────────────────────────

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
	opts := []jwt.ParserOption{jwt.WithValidMethods([]string{"RS256"})}
	if m.issuer != "" {
		opts = append(opts, jwt.WithIssuer(m.issuer))
	}
	if m.audience != "" {
		opts = append(opts, jwt.WithAudience(m.audience))
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
	return claims, nil
}

func (m *Middleware) getKey(kid string) (*rsa.PublicKey, error) {
	m.mu.RLock()
	key, ok := m.keys[kid]
	expired := time.Since(m.lastFetch) > m.cacheTTL
	m.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	if err := m.fetchJWKS(); err != nil {
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
		return nil, fmt.Errorf("kid %q not found in JWKS", kid)
	}
	return key, nil
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
