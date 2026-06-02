// Package socrate provides a typed client for the Socrate OAuth2 identity
// provider used across all backends.
//
// # Dual-auth strategy
//
//   - User-scoped calls (ListUsers, GetUser, UpdateUserRole, DeleteUser, …):
//     the caller's JWT must be present in the context (injected by jwtauth.Middleware
//     or set manually via WithJWT). The client forwards it as the Authorization header.
//   - Service-account calls (RegisterUser, InviteUserAsService, GetUserAsService):
//     the client exchanges ClientID + ClientSecret for a client_credentials token
//     automatically and caches it until near-expiry.
//
// # Dual-port routing
//
// Socrate exposes two TCP ports:
//
//	8080 — OAuth/OIDC server (public-facing)
//	         /oauth/token, /oauth/userinfo, /oauth/introspect, /oauth/revoke, …
//	8081 — Admin API (internal; restrict at network level)
//	         /api/admin/*, /api/apps/{id}/users/*, /api/apps/{id}/service/*
//
// AdminBaseURL defaults to BaseURL with the host port replaced by 8081.
// All user-management and admin calls are routed to AdminBaseURL automatically.
package socrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ovander/backendkit/ctxutil"
)

// ErrUserAlreadyExists is returned by CreateUser / RegisterUser / InviteUserAsService
// when Socrate responds with 409 Conflict.
var ErrUserAlreadyExists = errors.New("user already exists in Socrate")

// ErrMagicLinkRateLimited is returned by SendMagicLink when Socrate responds with
// 429 Too Many Requests — the per-address limit (5 requests / hour) has been
// reached for this email + app pair.
var ErrMagicLinkRateLimited = errors.New("magic link rate limit reached, please try again later")

// ────────────────────────────────────────────────────────────────────────────
// Client
// ────────────────────────────────────────────────────────────────────────────

// Client is a Socrate API client.
type Client struct {
	baseURL      string // OAuth port  (8080) — /oauth/* endpoints
	adminBaseURL string // Admin port  (8081) — /api/admin/*, /api/apps/* endpoints
	clientID     string // OAuth client ID
	clientSecret string // OAuth client secret (client_credentials grant)

	resolvedAppID string // lazily resolved numeric app ID

	httpClient *http.Client

	svcTokenMu     sync.Mutex
	svcToken       string
	svcTokenExpiry time.Time
}

// ClientConfig holds the constructor options for Client.
type ClientConfig struct {
	BaseURL      string        // OAuth port URL  (e.g. https://auth.example.com)
	AdminBaseURL string        // Admin port URL  (e.g. https://auth.example.com:8081); derived from BaseURL if empty
	ClientID     string        // OAuth client ID
	ClientSecret string        // OAuth client secret (required for service-account calls)
	AppID        string        // Pre-resolved numeric app ID; skips runtime resolution when set
	Timeout      time.Duration // HTTP client timeout; defaults to 30 s
}

// NewClient constructs and validates a Client from cfg.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("socrate: base URL is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("socrate: client ID is required")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	adminBaseURL := cfg.AdminBaseURL
	if adminBaseURL == "" {
		if u, err := url.Parse(cfg.BaseURL); err == nil {
			u.Host = u.Hostname() + ":8081"
			adminBaseURL = u.String()
		} else {
			adminBaseURL = cfg.BaseURL
		}
	}

	c := &Client{
		baseURL:      cfg.BaseURL,
		adminBaseURL: adminBaseURL,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		httpClient:   &http.Client{Timeout: timeout},
	}
	if cfg.AppID != "" {
		c.resolvedAppID = cfg.AppID
	}
	return c, nil
}

// WithJWT stores a user JWT in ctx for forwarding to Socrate.
// It delegates to ctxutil.WithRawJWT so the token is stored under the same
// key regardless of whether it was set by jwtauth.Middleware or by this call.
func WithJWT(ctx context.Context, jwt string) context.Context {
	return ctxutil.WithRawJWT(ctx, jwt)
}

// ────────────────────────────────────────────────────────────────────────────
// Internal HTTP helpers
// ────────────────────────────────────────────────────────────────────────────

// doHTTP is the single low-level request builder. fullURL must be a complete URL.
func (c *Client) doHTTP(ctx context.Context, token, method, fullURL string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}

// oauthURL builds a full URL on the OAuth port (baseURL).
func (c *Client) oauthURL(path string) string { return c.baseURL + path }

// adminURL builds a full URL on the Admin port (adminBaseURL).
func (c *Client) adminURL(path string) string { return c.adminBaseURL + path }

// doWithJWT sends a request to fullURL forwarding the user JWT from context.
func (c *Client) doWithJWT(ctx context.Context, method, fullURL string, body interface{}) (*http.Response, error) {
	jwt := ctxutil.GetRawJWT(ctx)
	if jwt == "" {
		return nil, errors.New("socrate: no JWT in context — use WithJWT or jwtauth.Middleware")
	}
	return c.doHTTP(ctx, jwt, method, fullURL, body)
}

// doWithServiceToken sends a request to fullURL using the cached service-account token.
func (c *Client) doWithServiceToken(ctx context.Context, method, fullURL string, body interface{}) (*http.Response, error) {
	tok, err := c.getServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get service token: %w", err)
	}
	return c.doHTTP(ctx, tok, method, fullURL, body)
}

// readBody reads and closes the response body.
func readBody(r *http.Response) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

// ────────────────────────────────────────────────────────────────────────────
// App ID resolution  (uses Admin port — /api/admin/apps)
// ────────────────────────────────────────────────────────────────────────────

// getAppID resolves the numeric app ID for the configured clientID using the
// caller's JWT. The result is cached after the first successful lookup.
func (c *Client) getAppID(ctx context.Context) (string, error) {
	if c.resolvedAppID != "" {
		return c.resolvedAppID, nil
	}
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/apps"), nil)
	if err != nil {
		return "", fmt.Errorf("fetch apps: %w", err)
	}
	return c.parseAppID(resp)
}

// getAppIDAsService resolves the numeric app ID using the service-account token.
//
// IMPORTANT: The Socrate Admin API at /api/admin/apps requires a human-admin
// JWT, not a service-account token.  This fallback lookup therefore always
// returns 401 in practice.  Callers MUST supply AppID in ClientConfig so the
// value is cached on construction and this network call is never made.
// If AppID is absent and the lookup fails with 401, a clear error is returned
// rather than a confusing "invalid token claims" message.
func (c *Client) getAppIDAsService(ctx context.Context) (string, error) {
	if c.resolvedAppID != "" {
		return c.resolvedAppID, nil
	}
	resp, err := c.doWithServiceToken(ctx, http.MethodGet, c.adminURL("/api/admin/apps"), nil)
	if err != nil {
		return "", fmt.Errorf("fetch apps: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// Service-account tokens cannot authenticate against the admin-user
		// endpoints.  Avoid this call entirely by setting AppID in ClientConfig.
		return "", errors.New("socrate: AppID must be set in ClientConfig for service-account calls — " +
			"the /api/admin/apps lookup requires an admin JWT, not a service-account token")
	}
	return c.parseAppID(resp)
}

func (c *Client) parseAppID(resp *http.Response) (string, error) {
	b, err := readBody(resp)
	if err != nil {
		return "", fmt.Errorf("read apps response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch apps HTTP %d: %s", resp.StatusCode, b)
	}
	var result struct {
		Apps []struct {
			ID       uint   `json:"id"`
			ClientID string `json:"client_id"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		return "", fmt.Errorf("decode apps: %w", err)
	}
	for _, app := range result.Apps {
		if app.ClientID == c.clientID {
			c.resolvedAppID = fmt.Sprintf("%d", app.ID)
			return c.resolvedAppID, nil
		}
	}
	return "", fmt.Errorf("socrate: no app found for client_id %s", c.clientID)
}

// ────────────────────────────────────────────────────────────────────────────
// Service-account token management  (POST /oauth/token — OAuth port)
// ────────────────────────────────────────────────────────────────────────────

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// getServiceToken returns a cached service-account token, refreshing it when
// near-expiry. Thread-safe.
func (c *Client) getServiceToken(ctx context.Context) (string, error) {
	c.svcTokenMu.Lock()
	defer c.svcTokenMu.Unlock()

	if c.svcToken != "" && time.Now().Add(30*time.Second).Before(c.svcTokenExpiry) {
		return c.svcToken, nil
	}
	if c.clientSecret == "" {
		return "", errors.New("socrate: client_secret required for service-account token exchange")
	}

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.oauthURL("/oauth/token"), bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange HTTP %d: %s", resp.StatusCode, b)
	}

	var tr tokenResponse
	if err := json.Unmarshal(b, &tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	c.svcToken = tr.AccessToken
	if tr.ExpiresIn > 0 {
		c.svcTokenExpiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	} else {
		c.svcTokenExpiry = time.Now().Add(55 * time.Minute)
	}
	return c.svcToken, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Data types
// ────────────────────────────────────────────────────────────────────────────

// User mirrors the AppUserResponse returned by the app-scoped /api/apps/{id}/users endpoints.
type User struct {
	ID         uint       `json:"id"`
	Email      string     `json:"email"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	IsVerified bool       `json:"is_verified"`
	InviteSent bool       `json:"invite_sent"`
	CreatedAt  time.Time  `json:"created_at"`
	LastLogin  *time.Time `json:"last_login,omitempty"`
}

// UserListResponse is the paginated list returned by ListUsers.
type UserListResponse struct {
	Users      []User `json:"users"`
	TotalCount int64  `json:"total_count"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
}

// CreateUserRequest is the body for adding a user to an app.
// Name is optional; when empty Socrate uses the email address as the display name.
type CreateUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	Role  string `json:"role"`
}

// CreateUserResult is returned by CreateUser, RegisterUser, and InviteUserAsService.
// It reflects the one-time invite information returned by Socrate.
type CreateUserResult struct {
	UserID      uint   `json:"user_id"`
	InviteToken string `json:"invite_token"`
	Role        string `json:"role"`
	EmailSent   bool   `json:"email_sent"`
	EmailError  string `json:"email_error,omitempty"`
}

// ServiceInviteRequest is the body for the service-account invite endpoint.
type ServiceInviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// ProfileInfo mirrors the OIDC /oauth/userinfo response.
type ProfileInfo struct {
	Sub         string `json:"sub"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
	GivenName   string `json:"given_name,omitempty"`
	FamilyName  string `json:"family_name,omitempty"`
}

// ActivityLog is a Socrate security audit log entry.
type ActivityLog struct {
	ID        uint            `json:"id"`
	EventType string          `json:"event_type"`
	Severity  string          `json:"severity"`
	UserID    *uint           `json:"user_id,omitempty"`
	UserEmail string          `json:"user_email,omitempty"`
	AppID     *uint           `json:"app_id,omitempty"`
	IPAddress string          `json:"ip_address,omitempty"`
	UserAgent string          `json:"user_agent,omitempty"`
	Success   bool            `json:"success"`
	Details   json.RawMessage `json:"details,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// ActivityLogResponse is the paginated security events response.
type ActivityLogResponse struct {
	Events     []ActivityLog `json:"events"`
	TotalCount int64         `json:"total_count"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
}

// IntrospectResponse holds the token introspection result (RFC 7662).
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Role      string `json:"role,omitempty"`
}

// ────────────────────────────────────────────────────────────────────────────
// User management — JWT-forwarding methods  (Admin port)
// ────────────────────────────────────────────────────────────────────────────

// ListUsers retrieves a paginated + searchable user list for the app using the caller's JWT.
func (c *Client) ListUsers(ctx context.Context, search string, page, pageSize int) (*UserListResponse, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	path := fmt.Sprintf("/api/apps/%s/users?page=%d&page_size=%d", appID, page, pageSize)
	if search != "" {
		path += "&search=" + url.QueryEscape(search)
	}
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list users HTTP %d: %s", resp.StatusCode, b)
	}
	var result UserListResponse
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode list users: %w", err)
	}
	return &result, nil
}

// GetUser retrieves a user by ID using the caller's JWT.
// Returns nil, nil when the user is not found (404).
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doWithJWT(ctx, http.MethodGet,
		c.adminURL(fmt.Sprintf("/api/apps/%s/users/%s", appID, userID)), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user HTTP %d: %s", resp.StatusCode, b)
	}
	var u User
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	return &u, nil
}

// CreateUser adds a user to the app using the caller's JWT.
// If the user does not yet exist in Socrate, they are created and an invite email is sent.
// Returns ErrUserAlreadyExists when the user already has a role in the app (409).
func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResult, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doWithJWT(ctx, http.MethodPost,
		c.adminURL(fmt.Sprintf("/api/apps/%s/users", appID)), req)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrUserAlreadyExists
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("create user HTTP %d: %s", resp.StatusCode, b)
	}
	var result CreateUserResult
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode create user response: %w", err)
	}
	return &result, nil
}

// UpdateUserRole changes the role of a user within the app using the caller's JWT.
// Valid roles: admin, manager, editor, viewer, user.
func (c *Client) UpdateUserRole(ctx context.Context, userID, role string) error {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return fmt.Errorf("resolve app ID: %w", err)
	}
	body := map[string]string{"role": role}
	resp, err := c.doWithJWT(ctx, http.MethodPut,
		c.adminURL(fmt.Sprintf("/api/apps/%s/users/%s", appID, userID)), body)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update user role HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// DeleteUser removes a user from the app (removes the role assignment) using the caller's JWT.
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doWithJWT(ctx, http.MethodDelete,
		c.adminURL(fmt.Sprintf("/api/apps/%s/users/%s", appID, userID)), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete user HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ResendVerification re-sends the email verification message for a user.
func (c *Client) ResendVerification(ctx context.Context, userID string) error {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doWithJWT(ctx, http.MethodPost,
		c.adminURL(fmt.Sprintf("/api/apps/%s/users/%s/resend-verification", appID, userID)), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("resend verification HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ForcePasswordReset triggers a password-reset email for a user.
func (c *Client) ForcePasswordReset(ctx context.Context, userID string) error {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doWithJWT(ctx, http.MethodPost,
		c.adminURL(fmt.Sprintf("/api/apps/%s/users/%s/reset-password", appID, userID)), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("force password reset HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// User management — service-account methods  (Admin port)
// ────────────────────────────────────────────────────────────────────────────

// GetUserAsService retrieves a user by numeric ID using the service-account token.
// Returns nil, nil when the user is not found (404).
func (c *Client) GetUserAsService(ctx context.Context, userID string) (*User, error) {
	appID, err := c.getAppIDAsService(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doWithServiceToken(ctx, http.MethodGet,
		c.adminURL(fmt.Sprintf("/api/apps/%s/users/%s", appID, userID)), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user HTTP %d: %s", resp.StatusCode, b)
	}
	var u User
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	return &u, nil
}

// RegisterUser creates a user and adds them to the app using the service-account token.
// Socrate dispatches an invite email automatically.
// Returns ErrUserAlreadyExists on 409.
func (c *Client) RegisterUser(ctx context.Context, req CreateUserRequest) (*CreateUserResult, error) {
	appID, err := c.getAppIDAsService(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doWithServiceToken(ctx, http.MethodPost,
		c.adminURL(fmt.Sprintf("/api/apps/%s/users", appID)), req)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrUserAlreadyExists
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("register user HTTP %d: %s", resp.StatusCode, b)
	}
	var result CreateUserResult
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode register user response: %w", err)
	}
	return &result, nil
}

// InviteUserAsService creates a user via the dedicated M2M service route and
// dispatches an invite email. No user JWT is required.
// Returns ErrUserAlreadyExists on 409.
func (c *Client) InviteUserAsService(ctx context.Context, req ServiceInviteRequest) (*CreateUserResult, error) {
	appID, err := c.getAppIDAsService(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doWithServiceToken(ctx, http.MethodPost,
		c.adminURL(fmt.Sprintf("/api/apps/%s/service/users", appID)), req)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrUserAlreadyExists
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invite user HTTP %d: %s", resp.StatusCode, b)
	}
	var result CreateUserResult
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode invite user response: %w", err)
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// OIDC / Token operations  (OAuth port)
// ────────────────────────────────────────────────────────────────────────────

// GetCurrentUserProfile calls GET /oauth/userinfo using the JWT in ctx.
// Returns nil, nil on 401/404.
func (c *Client) GetCurrentUserProfile(ctx context.Context) (*ProfileInfo, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.oauthURL("/oauth/userinfo"), nil)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo HTTP %d: %s", resp.StatusCode, b)
	}
	var p ProfileInfo
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	// OIDC standard aliases
	if p.FirstName == "" {
		p.FirstName = p.GivenName
	}
	if p.LastName == "" {
		p.LastName = p.FamilyName
	}
	return &p, nil
}

// RevokeToken revokes an access or refresh token (RFC 7009).
// Uses the service-account credentials for client authentication.
func (c *Client) RevokeToken(ctx context.Context, token string) error {
	if c.clientSecret == "" {
		return errors.New("socrate: client_secret required for token revocation")
	}
	data := url.Values{
		"token":         {token},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.oauthURL("/oauth/revoke"), bytes.NewBufferString(data.Encode()))
	if err != nil {
		return fmt.Errorf("build revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("revoke HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// IntrospectToken validates a token server-side and returns its active state and claims (RFC 7662).
// Uses the service-account credentials for client authentication.
func (c *Client) IntrospectToken(ctx context.Context, token string) (*IntrospectResponse, error) {
	if c.clientSecret == "" {
		return nil, errors.New("socrate: client_secret required for token introspection")
	}
	data := url.Values{
		"token":         {token},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.oauthURL("/oauth/introspect"), bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build introspect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspect: %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspect HTTP %d: %s", resp.StatusCode, b)
	}
	var result IntrospectResponse
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode introspect: %w", err)
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Passwordless magic-link  (Admin port — service-account only)
// ────────────────────────────────────────────────────────────────────────────

// MagicLinkResponse is the body returned by POST /api/apps/{id}/service/magic-link.
// In development mode Socrate populates MagicURL with the raw token URL so that
// integration tests can drive the full flow without a live mail server.
// In production, MagicURL is always empty.
type MagicLinkResponse struct {
	Message  string `json:"message"`
	MagicURL string `json:"magic_url,omitempty"`
}

// SendMagicLink asks Socrate to email a single-use passwordless login link to
// the given address on behalf of the app.
//
// This is a service-account (M2M) call — the client exchanges its
// ClientID + ClientSecret for a client_credentials token and sends the request
// to POST /api/apps/{app_id}/service/magic-link on the Admin port (8081).
// No human-user JWT is needed or accepted.
//
// Security notes mirrored from Socrate:
//   - The response is always the same opaque 202 regardless of whether the
//     email is registered — callers cannot use the response to enumerate users.
//   - Socrate rate-limits requests to 5 per address per hour; a 429 is returned
//     when the limit is exceeded.
//   - Only set email on behalf of a user who explicitly requested a login link —
//     triggering unsolicited emails is a terms-of-service violation.
func (c *Client) SendMagicLink(ctx context.Context, email string) (*MagicLinkResponse, error) {
	appID, err := c.getAppIDAsService(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	body := map[string]string{"email": email}
	resp, err := c.doWithServiceToken(ctx, http.MethodPost,
		c.adminURL(fmt.Sprintf("/api/apps/%s/service/magic-link", appID)), body)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, ErrMagicLinkRateLimited
	}
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("send magic link HTTP %d: %s", resp.StatusCode, b)
	}
	var result MagicLinkResponse
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode magic link response: %w", err)
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Security / Audit  (Admin port)
// ────────────────────────────────────────────────────────────────────────────

// GetActivityLogs retrieves paginated security audit events for the app.
func (c *Client) GetActivityLogs(ctx context.Context, page, pageSize int) (*ActivityLogResponse, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	path := fmt.Sprintf("/api/admin/security/events?app_id=%s&page=%d&page_size=%d", appID, page, pageSize)
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get security events HTTP %d: %s", resp.StatusCode, b)
	}
	var result ActivityLogResponse
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &result, nil
}
