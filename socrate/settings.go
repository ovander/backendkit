package socrate

// settings.go — read-only server configuration and connectivity probes on the
// admin port (/api/admin/settings/*). All calls forward the caller's admin JWT.

import (
	"context"
	"net/http"
)

// ServerConfigFeatures reflects the feature-flag subset of the server config.
type ServerConfigFeatures struct {
	MFAEnabled            bool `json:"mfa_enabled"`
	PasswordPolicyEnabled bool `json:"password_policy_enabled"`
	AuditLoggingEnabled   bool `json:"audit_logging_enabled"`
}

// ServerConfig mirrors dto.ServerConfigResponse — the non-secret server config.
type ServerConfig struct {
	IssuerURL         string               `json:"issuer_url"`
	AccessTokenTTL    int                  `json:"access_token_ttl"`  // seconds
	RefreshTokenTTL   int                  `json:"refresh_token_ttl"` // seconds
	RateLimitRequests int                  `json:"rate_limit_requests"`
	RateLimitWindow   int                  `json:"rate_limit_window"` // seconds
	Environment       string               `json:"environment"`
	Version           string               `json:"version"`
	Features          ServerConfigFeatures `json:"features"`
}

// ConnectionTest is the result of a TestDB / TestCache probe.
type ConnectionTest struct {
	Status    string `json:"status"` // "ok" or "error"
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// GetServerConfig returns the server's non-secret runtime configuration.
func (c *Client) GetServerConfig(ctx context.Context) (*ServerConfig, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/settings/config"), nil)
	if err != nil {
		return nil, err
	}
	var cfg ServerConfig
	if err := decodeJSON(resp, "get server config", &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// TestDB probes the server's database connection and reports status + latency.
func (c *Client) TestDB(ctx context.Context) (*ConnectionTest, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/settings/test-db"), nil)
	if err != nil {
		return nil, err
	}
	var t ConnectionTest
	if err := decodeJSON(resp, "test db", &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// TestCache probes the server's cache connection and reports status + latency.
func (c *Client) TestCache(ctx context.Context) (*ConnectionTest, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/settings/test-cache"), nil)
	if err != nil {
		return nil, err
	}
	var t ConnectionTest
	if err := decodeJSON(resp, "test cache", &t); err != nil {
		return nil, err
	}
	return &t, nil
}
