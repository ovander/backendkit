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
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"github.com/ovander/backendkit/socrate"
)

// SocrateClaims is the JWT claims structure emitted by Socrate.
type SocrateClaims struct {
	TenantID string `json:"tenant_id"`
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Plan     string `json:"plan"`
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
	jwksURL    string
	issuer     string
	logger     *logrus.Entry
	httpClient *http.Client
	cacheTTL   time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

// New creates a Middleware that validates tokens against the JWKS at jwksURL.
// issuer is optional; when non-empty it is enforced via jwt.WithIssuer.
func New(jwksURL, issuer string, logger *logrus.Entry) *Middleware {
	return &Middleware{
		jwksURL:    jwksURL,
		issuer:     issuer,
		logger:     logger,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		keys:       make(map[string]*rsa.PublicKey),
		cacheTTL:   1 * time.Hour,
	}
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

		ctx := r.Context()

		if claims.TenantID != "" {
			tenantID, err := uuid.Parse(claims.TenantID)
			if err != nil {
				m.logger.WithError(err).Warn("invalid tenant_id in claims")
				apierror.Unauthorized("invalid tenant_id").WriteJSON(w)
				return
			}
			ctx = ctxutil.WithTenantID(ctx, tenantID)
		}

		// user_id claim takes precedence over jwt.sub
		userIDStr := claims.UserID
		if userIDStr == "" {
			userIDStr = claims.Subject
		}
		if userIDStr != "" {
			userID, err := uuid.Parse(userIDStr)
			if err != nil {
				// Deterministic UUID from opaque Socrate subject
				userID = uuid.NewSHA1(uuid.NameSpaceDNS, []byte("socrate:"+userIDStr))
			}
			ctx = ctxutil.WithUserID(ctx, userID)
			ctx = ctxutil.WithUserSub(ctx, userIDStr)
		}

		if claims.Email != "" {
			ctx = ctxutil.WithUserEmail(ctx, claims.Email)
		}
		if claims.Name != "" {
			ctx = ctxutil.WithUserName(ctx, claims.Name)
		}
		if claims.Role != "" {
			ctx = ctxutil.WithUserRole(ctx, claims.Role)
		}
		if claims.Plan != "" {
			ctx = ctxutil.WithUserPlan(ctx, claims.Plan)
		}

		// Store raw JWT so downstream can forward it to Socrate service calls.
		ctx = socrate.WithJWT(ctx, token)

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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
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

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}
