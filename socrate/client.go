// Package socrate provides a typed client for the Socrate OAuth2 identity
// provider used across all backends.
//
// Dual-auth strategy
//
//   - User-scoped calls (ListUsers, GetUser, CreateUser, …): the caller's JWT
//     must be stored in the context via WithJWT, and the client forwards it as
//     the Authorization header.
//   - Service-account calls (RegisterUser, InviteUserAsService, SendMagicLink,
//     GetUserAsService, ListUsersAsService): the client exchanges
//     ClientID + ClientSecret for a client_credentials token automatically and
//     caches it until expiry.
//
// Dual-port routing
//
//	Socrate exposes two TCP ports:
//	  8080 — user-facing API (requires user JWT with a numeric sub claim)
//	  8081 — admin API (accepts client_credentials tokens; used for service calls)
//
//	AdminBaseURL defaults to BaseURL with the host port replaced by 8081.
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
)

// contextKey is an unexported type for context keys in this package.
type contextKey string

// JWTContextKey is the context key under which the user JWT is stored.
const JWTContextKey contextKey = "socrate_jwt"

// ErrUserAlreadyExists is returned by CreateUser / RegisterUser / InviteUserAsService
// when Socrate responds with 409 Conflict.
var ErrUserAlreadyExists = errors.New("user already exists in Socrate")

// Client is a Socrate API client.
type Client struct {
	baseURL      string
	adminBaseURL string // Socrate admin port (8081)
	clientID     string // OAuth client ID (used to resolve numeric app ID)
	clientSecret string // OAuth client secret (client_credentials grant)

	resolvedAppID string // lazily resolved numeric app ID

	httpClient *http.Client

	svcTokenMu     sync.Mutex
	svcToken       string
	svcTokenExpiry time.Time
}

// ClientConfig holds the constructor options for Client.
type ClientConfig struct {
	BaseURL      string
	AdminBaseURL string        // Socrate admin port URL; derived from BaseURL if empty
	ClientID     string        // OAuth client ID
	ClientSecret string        // OAuth client secret
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
func WithJWT(ctx context.Context, jwt string) context.Context {
	return context.WithValue(ctx, JWTContextKey, jwt)
}

// getJWT extracts the JWT stored by WithJWT.
func getJWT(ctx context.Context) (string, error) {
	jwt, ok := ctx.Value(JWTContextKey).(string)
	if !ok || jwt == "" {
		return "", errors.New("socrate: no JWT in context")
	}
	return jwt, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Internal HTTP helpers
// ────────────────────────────────────────────────────────────────────────────

// doRequest forwards the user JWT from context.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	jwt, err := getJWT(ctx)
	if err != nil {
		return nil, err
	}
	return c.doRequestWithToken(ctx, jwt, method, path, body)
}

// doRequestWithToken sends an authenticated request with an explicit token.
func (c *Client) doRequestWithToken(ctx context.Context, token, method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}

// ────────────────────────────────────────────────────────────────────────────
// App ID resolution
// ────────────────────────────────────────────────────────────────────────────

// App represents an application registered in Socrate.
type App struct {
	ID       uint   `json:"id"`
	Name     string `json:"name"`
	ClientID string `json:"client_id"`
}

// AppListResponse is the payload returned by the apps list endpoint.
type AppListResponse struct {
	Apps []App `json:"apps"`
}

func (c *Client) getAppID(ctx context.Context) (string, error) {
	if c.resolvedAppID != "" {
		return c.resolvedAppID, nil
	}
	resp, err := c.doRequest(ctx, http.MethodGet, "/api/admin/apps", nil)
	if err != nil {
		return "", fmt.Errorf("fetch apps: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("fetch apps failed HTTP %d: %s", resp.StatusCode, b)
	}
	var result AppListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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

func (c *Client) getAppIDWithToken(ctx context.Context, token string) (string, error) {
	if c.resolvedAppID != "" {
		return c.resolvedAppID, nil
	}
	resp, err := c.doRequestWithToken(ctx, token, http.MethodGet, "/api/admin/apps", nil)
	if err != nil {
		return "", fmt.Errorf("fetch apps: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("fetch apps failed HTTP %d: %s", resp.StatusCode, b)
	}
	var result AppListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
// Data types
// ────────────────────────────────────────────────────────────────────────────

// User represents a Socrate identity record.
type User struct {
	ID          uint       `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	FirstName   string     `json:"first_name"`
	LastName    string     `json:"last_name"`
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	IsVerified  bool       `json:"is_verified"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLogin   *time.Time `json:"last_login,omitempty"`
}

// UserListResponse is the paginated list response.
type UserListResponse struct {
	Users      []User `json:"users"`
	TotalCount int64  `json:"total_count"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
}

// CreateUserRequest is the body for creating a user.
type CreateUserRequest struct {
	Email       string `json:"email"`
	FullName    string `json:"full_name"`
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	Password    string `json:"password,omitempty"`
}

// UpdateUserRequest is the body for updating a user (all fields optional).
type UpdateUserRequest struct {
	FullName    *string `json:"full_name,omitempty"`
	FirstName   *string `json:"first_name,omitempty"`
	LastName    *string `json:"last_name,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Role        *string `json:"role,omitempty"`
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

// ServiceInviteRequest is the body for the admin-port invite endpoint.
type ServiceInviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// ServiceInviteResponse wraps the created user and email delivery metadata.
type ServiceInviteResponse struct {
	User       *User
	EmailSent  bool   `json:"email_sent"`
	EmailError string `json:"email_error,omitempty"`
}

// ────────────────────────────────────────────────────────────────────────────
// decodeUserResponse
// ────────────────────────────────────────────────────────────────────────────

// decodeUserResponse handles both flat {"id":1,...} and wrapped {"user":{...}}
// response shapes from Socrate.
func decodeUserResponse(body []byte) (*User, error) {
	var u User
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	if u.ID != 0 {
		return &u, nil
	}
	var env struct {
		User User `json:"user"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.User.ID != 0 {
		return &env.User, nil
	}
	return &u, nil
}

// ────────────────────────────────────────────────────────────────────────────
// User management — JWT-forwarding methods
// ────────────────────────────────────────────────────────────────────────────

// ListUsers retrieves a paginated + searchable user list using the caller's JWT.
func (c *Client) ListUsers(ctx context.Context, search string, page, pageSize int) (*UserListResponse, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	path := fmt.Sprintf("/api/apps/%s/users?page=%d&page_size=%d", appID, page, pageSize)
	if search != "" {
		path += "&search=" + url.QueryEscape(search)
	}
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list users HTTP %d: %s", resp.StatusCode, b)
	}
	var result UserListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode list users: %w", err)
	}
	return &result, nil
}

// GetUser retrieves a user by ID using the caller's JWT.
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodGet, fmt.Sprintf("/api/apps/%s/users/%s", appID, userID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get user HTTP %d: %s", resp.StatusCode, b)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read get user: %w", err)
	}
	return decodeUserResponse(b)
}

// CreateUser creates a user using the caller's JWT.
func (c *Client) CreateUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/apps/%s/users", appID), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrUserAlreadyExists
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create user HTTP %d: %s", resp.StatusCode, b)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read create user: %w", err)
	}
	return decodeUserResponse(b)
}

// UpdateUser updates a user's fields using the caller's JWT.
func (c *Client) UpdateUser(ctx context.Context, userID string, req UpdateUserRequest) (*User, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPut, fmt.Sprintf("/api/apps/%s/users/%s", appID, userID), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("update user HTTP %d: %s", resp.StatusCode, b)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read update user: %w", err)
	}
	return decodeUserResponse(b)
}

// DeleteUser removes a user using the caller's JWT.
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/apps/%s/users/%s", appID, userID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete user HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ResendVerification re-sends the verification email for a user.
func (c *Client) ResendVerification(ctx context.Context, userID string) error {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/apps/%s/users/%s/resend-verification", appID, userID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend verification HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ResetPassword triggers a password-reset email for a user.
func (c *Client) ResetPassword(ctx context.Context, userID string) error {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doRequest(ctx, http.MethodPost, fmt.Sprintf("/api/apps/%s/users/%s/reset-password", appID, userID), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("reset password HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// GetCurrentUserProfile calls the OIDC /oauth/userinfo endpoint using the JWT
// in ctx. Returns nil, nil on 401/404 (soft failure).
func (c *Client) GetCurrentUserProfile(ctx context.Context) (*User, error) {
	jwt, err := getJWT(ctx)
	if err != nil {
		return nil, fmt.Errorf("no JWT in context: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/oauth/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("build userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo HTTP %d: %s", resp.StatusCode, b)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read userinfo: %w", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	u := &User{}
	str := func(key string) string {
		v, _ := raw[key].(string)
		return v
	}
	u.Email = str("email")
	u.Name = str("name")
	u.DisplayName = str("display_name")
	u.FirstName = str("first_name")
	u.LastName = str("last_name")
	if u.FirstName == "" {
		u.FirstName = str("given_name")
	}
	if u.LastName == "" {
		u.LastName = str("family_name")
	}
	return u, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Service-account token management (client_credentials grant)
// ────────────────────────────────────────────────────────────────────────────

type clientCredentialsTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// getServiceToken returns a cached service-account token, refreshing it when
// expired. Thread-safe.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/oauth/token", bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange HTTP %d: %s", resp.StatusCode, b)
	}

	var tr clientCredentialsTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
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
// Service-account user management (no user JWT required)
// ────────────────────────────────────────────────────────────────────────────

// GetUserAsService retrieves a user by Socrate numeric ID using the
// client_credentials token. Returns nil, nil when the user is not found.
func (c *Client) GetUserAsService(ctx context.Context, userID string) (*User, error) {
	tok, err := c.getServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get service token: %w", err)
	}
	appID, err := c.getAppIDWithToken(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doRequestWithToken(ctx, tok, http.MethodGet, fmt.Sprintf("/api/apps/%s/users/%s", appID, userID), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get user HTTP %d: %s", resp.StatusCode, b)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read get user: %w", err)
	}
	return decodeUserResponse(b)
}

// ListUsersAsService fetches the full paginated user list via the admin port
// using the client_credentials token.
func (c *Client) ListUsersAsService(ctx context.Context, page, pageSize int) (*UserListResponse, error) {
	tok, err := c.getServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get service token: %w", err)
	}
	appID, err := c.getAppIDWithToken(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	rawURL := fmt.Sprintf("%s/api/apps/%s/service/users?page=%d&page_size=%d", c.adminBaseURL, appID, page, pageSize)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list users HTTP %d: %s", resp.StatusCode, b)
	}
	var result UserListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &result, nil
}

// RegisterUser creates a user using the client_credentials service token.
// Socrate dispatches a verification email automatically.
func (c *Client) RegisterUser(ctx context.Context, req CreateUserRequest) (*User, error) {
	tok, err := c.getServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get service token: %w", err)
	}
	appID, err := c.getAppIDWithToken(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	resp, err := c.doRequestWithToken(ctx, tok, http.MethodPost, fmt.Sprintf("/api/apps/%s/users", appID), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrUserAlreadyExists
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("register user HTTP %d: %s", resp.StatusCode, b)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read register user: %w", err)
	}
	return decodeUserResponse(b)
}

// InviteUserAsService creates a user and dispatches an invite email via the
// Socrate admin-port endpoint (no user JWT needed). Returns ErrUserAlreadyExists
// on 409.
func (c *Client) InviteUserAsService(ctx context.Context, req ServiceInviteRequest) (*ServiceInviteResponse, error) {
	tok, err := c.getServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get service token: %w", err)
	}
	appID, err := c.getAppIDWithToken(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}

	rawURL := fmt.Sprintf("%s/api/apps/%s/service/users", c.adminBaseURL, appID)
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal invite: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("build invite request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+tok)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("invite user: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return nil, ErrUserAlreadyExists
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("invite user HTTP %d: %s", resp.StatusCode, b)
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read invite response: %w", err)
	}
	var env struct {
		EmailSent  bool   `json:"email_sent"`
		EmailError string `json:"email_error"`
	}
	_ = json.Unmarshal(rawBody, &env)
	user, _ := decodeUserResponse(rawBody)
	return &ServiceInviteResponse{
		User:       user,
		EmailSent:  env.EmailSent,
		EmailError: env.EmailError,
	}, nil
}

// SendMagicLink dispatches a passwordless sign-in email. Returns nil when the
// user is not found (suppresses 404 to avoid account enumeration).
func (c *Client) SendMagicLink(ctx context.Context, email, callbackURL string) error {
	tok, err := c.getServiceToken(ctx)
	if err != nil {
		return fmt.Errorf("get service token: %w", err)
	}
	appID, err := c.getAppIDWithToken(ctx, tok)
	if err != nil {
		return fmt.Errorf("resolve app ID: %w", err)
	}

	listPath := fmt.Sprintf("/api/apps/%s/users?search=%s&page=1&page_size=1", appID, url.QueryEscape(email))
	listResp, err := c.doRequestWithToken(ctx, tok, http.MethodGet, listPath, nil)
	if err != nil {
		return fmt.Errorf("find user: %w", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(listResp.Body)
		return fmt.Errorf("find user HTTP %d: %s", listResp.StatusCode, b)
	}
	var list UserListResponse
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		return fmt.Errorf("decode user list: %w", err)
	}
	if len(list.Users) == 0 {
		return nil // suppress: no account enumeration
	}

	userID := fmt.Sprintf("%d", list.Users[0].ID)
	body := map[string]string{"callback_url": callbackURL}
	resp, err := c.doRequestWithToken(ctx, tok, http.MethodPost, fmt.Sprintf("/api/apps/%s/users/%s/magic-link", appID, userID), body)
	if err != nil {
		return fmt.Errorf("send magic link: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("send magic link HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Activity logs
// ────────────────────────────────────────────────────────────────────────────

// GetActivityLogs retrieves paginated security audit events from Socrate.
func (c *Client) GetActivityLogs(ctx context.Context, page, pageSize int) (*ActivityLogResponse, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	path := fmt.Sprintf("/api/admin/security/events?app_id=%s&page=%d&page_size=%d", appID, page, pageSize)
	resp, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get security events HTTP %d: %s", resp.StatusCode, b)
	}
	var result ActivityLogResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &result, nil
}
