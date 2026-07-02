package socrate

// admin.go — admin-port operations routed to adminBaseURL (port 8081).
//
// Two authentication modes are used:
//
//   Admin JWT (human superadmin):
//     POST/GET/PUT/DELETE  /api/admin/apps/{id}
//     POST                 /api/admin/apps/{id}/rotate-secret
//     GET/DELETE           /api/admin/users/{id}
//     POST                 /api/admin/users/{id}/block|unlock|revoke-tokens
//     GET                  /api/admin/users/{id}/apps
//     POST/GET/PUT/DELETE  /api/admin/superadmins/{id}
//     GET                  /api/admin/security/events|threats|geo
//     GET/POST/DELETE      /api/admin/security/blocked-ips
//     GET                  /api/admin/security/ip-reputation/{ip}
//     GET                  /api/admin/dashboard/stats|activity|health
//     GET                  /api/admin/logs
//
//   Service-account token (M2M client_credentials, sub=app:{id}):
//     POST /api/apps/{id}/service/magic-link  — see client.go SendMagicLink
//     POST /api/apps/{id}/service/users       — see client.go InviteUserAsService

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// App management
// ────────────────────────────────────────────────────────────────────────────

// App is the standard OAuth application record.
type App struct {
	ID           uint      `json:"id"`
	Name         string    `json:"name"`
	ClientID     string    `json:"client_id"`
	Active       bool      `json:"active"`
	IsPublic     bool      `json:"is_public"`
	RequirePKCE  bool      `json:"require_pkce"`
	URL          *string   `json:"url,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	OwnerID      *uint     `json:"owner_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// AppWithSecret wraps App with the one-time plaintext client_secret returned on
// creation and rotation. The server never stores the plaintext — only a bcrypt hash.
// Save it immediately; it cannot be retrieved again.
type AppWithSecret struct {
	App
	ClientSecret string `json:"client_secret"` // empty for public clients
}

// CreateAppRequest is the payload for POST /api/admin/apps.
type CreateAppRequest struct {
	Name         string   `json:"name"`
	URL          *string  `json:"url,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	// IsPublic marks this as a public client (SPA / mobile).
	// No client_secret is generated; PKCE is automatically enforced.
	IsPublic    bool `json:"is_public"`
	RequirePKCE bool `json:"require_pkce"`
}

// UpdateAppRequest is the payload for PUT /api/admin/apps/{id} (all fields optional).
type UpdateAppRequest struct {
	Name         *string  `json:"name,omitempty"`
	URL          *string  `json:"url,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	Active       *bool    `json:"active,omitempty"`
}

// AppListResponse is the paginated apps list.
type AppListResponse struct {
	Apps       []App `json:"apps"`
	TotalCount int64 `json:"total_count"`
}

// ListApps returns all OAuth applications visible to the authenticated admin.
func (c *Client) ListApps(ctx context.Context) (*AppListResponse, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/apps"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list apps HTTP %d: %s", resp.StatusCode, b)
	}
	var result AppListResponse
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode apps: %w", err)
	}
	return &result, nil
}

// GetApp retrieves a single app by numeric ID.
func (c *Client) GetApp(ctx context.Context, appID string) (*App, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/apps/"+url.PathEscape(appID)), nil)
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
		return nil, fmt.Errorf("get app HTTP %d: %s", resp.StatusCode, b)
	}
	var app App
	if err := json.Unmarshal(b, &app); err != nil {
		return nil, fmt.Errorf("decode app: %w", err)
	}
	return &app, nil
}

// CreateApp registers a new OAuth application.
// The plaintext client_secret in the response is shown only once — save it now.
func (c *Client) CreateApp(ctx context.Context, req CreateAppRequest) (*AppWithSecret, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPost, c.adminURL("/api/admin/apps"), req)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("create app HTTP %d: %s", resp.StatusCode, b)
	}
	var result AppWithSecret
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode create app response: %w", err)
	}
	return &result, nil
}

// UpdateApp modifies an existing application's metadata.
func (c *Client) UpdateApp(ctx context.Context, appID string, req UpdateAppRequest) (*App, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPut, c.adminURL("/api/admin/apps/"+url.PathEscape(appID)), req)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update app HTTP %d: %s", resp.StatusCode, b)
	}
	var app App
	if err := json.Unmarshal(b, &app); err != nil {
		return nil, fmt.Errorf("decode updated app: %w", err)
	}
	return &app, nil
}

// DeleteApp permanently removes an OAuth application.
func (c *Client) DeleteApp(ctx context.Context, appID string) error {
	resp, err := c.doWithJWT(ctx, http.MethodDelete, c.adminURL("/api/admin/apps/"+url.PathEscape(appID)), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete app HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// RotateSecret generates a new client_secret for the app, invalidating the old one.
// The new plaintext secret is returned and shown only once.
func (c *Client) RotateSecret(ctx context.Context, appID string) (*AppWithSecret, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPost,
		c.adminURL("/api/admin/apps/"+url.PathEscape(appID)+"/rotate-secret"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rotate secret HTTP %d: %s", resp.StatusCode, b)
	}
	var result AppWithSecret
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode rotate secret response: %w", err)
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Global user administration
// ────────────────────────────────────────────────────────────────────────────

// GlobalUser mirrors dto.UserResponse — the richer user record returned by the
// global admin endpoints, including optional profile fields.
type GlobalUser struct {
	ID         uint       `json:"id"`
	Email      string     `json:"email"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	IsVerified bool       `json:"is_verified"`
	Title      *string    `json:"title,omitempty"`
	Division   *string    `json:"division,omitempty"`
	Company    *string    `json:"company,omitempty"`
	Country    *string    `json:"country,omitempty"`
	Phone      *string    `json:"phone,omitempty"`
	JobTitle   *string    `json:"job_title,omitempty"`
	Department *string    `json:"department,omitempty"`
	Language   *string    `json:"language,omitempty"`
	Timezone   *string    `json:"timezone,omitempty"`
	LastLogin  *time.Time `json:"last_login,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// GlobalUserListResponse wraps the paginated global user list.
type GlobalUserListResponse struct {
	Users      []GlobalUser `json:"users"`
	TotalCount int64        `json:"total_count"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
}

// AdminListUsers lists all users globally (superadmin only).
func (c *Client) AdminListUsers(ctx context.Context, page, pageSize int) (*GlobalUserListResponse, error) {
	path := fmt.Sprintf("/api/admin/users?page=%d&page_size=%d", page, pageSize)
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin list users HTTP %d: %s", resp.StatusCode, b)
	}
	var result GlobalUserListResponse
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode users: %w", err)
	}
	return &result, nil
}

// AdminGetUser retrieves a single user by numeric ID (superadmin only).
func (c *Client) AdminGetUser(ctx context.Context, userID string) (*GlobalUser, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/users/"+url.PathEscape(userID)), nil)
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
		return nil, fmt.Errorf("admin get user HTTP %d: %s", resp.StatusCode, b)
	}
	var u GlobalUser
	if err := json.Unmarshal(b, &u); err != nil {
		return nil, fmt.Errorf("decode user: %w", err)
	}
	return &u, nil
}

// AdminDeleteUser permanently deletes a user account (superadmin only).
func (c *Client) AdminDeleteUser(ctx context.Context, userID string) error {
	resp, err := c.doWithJWT(ctx, http.MethodDelete, c.adminURL("/api/admin/users/"+url.PathEscape(userID)), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("admin delete user HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// GetUserApps returns all apps the given user belongs to.
func (c *Client) GetUserApps(ctx context.Context, userID string) ([]App, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/users/"+url.PathEscape(userID)+"/apps"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get user apps HTTP %d: %s", resp.StatusCode, b)
	}
	var apps []App
	if err := json.Unmarshal(b, &apps); err != nil {
		return nil, fmt.Errorf("decode user apps: %w", err)
	}
	return apps, nil
}

// BlockUser disables a user account. The user will be unable to log in.
func (c *Client) BlockUser(ctx context.Context, userID string) error {
	resp, err := c.doWithJWT(ctx, http.MethodPost, c.adminURL("/api/admin/users/"+url.PathEscape(userID)+"/block"), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("block user HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// UnlockUser re-enables a blocked or locked-out user account.
func (c *Client) UnlockUser(ctx context.Context, userID string) error {
	resp, err := c.doWithJWT(ctx, http.MethodPost, c.adminURL("/api/admin/users/"+url.PathEscape(userID)+"/unlock"), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unlock user HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// RevokeUserTokens invalidates all active tokens for the user, forcing a re-login.
func (c *Client) RevokeUserTokens(ctx context.Context, userID string) error {
	resp, err := c.doWithJWT(ctx, http.MethodPost,
		c.adminURL("/api/admin/users/"+url.PathEscape(userID)+"/revoke-tokens"), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("revoke user tokens HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Superadmin management
// ────────────────────────────────────────────────────────────────────────────

// Superadmin is a Socrate superadmin record.
type Superadmin struct {
	ID        uint      `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateSuperadminRequest is the payload for POST /api/admin/superadmins.
type CreateSuperadminRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

// UpdateSuperadminRequest is the payload for PUT /api/admin/superadmins/{id}.
type UpdateSuperadminRequest struct {
	Name  *string `json:"name,omitempty"`
	Email *string `json:"email,omitempty"`
}

// ListSuperadmins returns all superadmin accounts.
func (c *Client) ListSuperadmins(ctx context.Context) ([]Superadmin, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/superadmins"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list superadmins HTTP %d: %s", resp.StatusCode, b)
	}
	var admins []Superadmin
	if err := json.Unmarshal(b, &admins); err != nil {
		// try wrapped form {"superadmins": [...]}
		var env struct {
			Superadmins []Superadmin `json:"superadmins"`
		}
		if err2 := json.Unmarshal(b, &env); err2 == nil {
			return env.Superadmins, nil
		}
		return nil, fmt.Errorf("decode superadmins: %w", err)
	}
	return admins, nil
}

// GetSuperadmin retrieves a superadmin by numeric ID.
func (c *Client) GetSuperadmin(ctx context.Context, id string) (*Superadmin, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/superadmins/"+url.PathEscape(id)), nil)
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
		return nil, fmt.Errorf("get superadmin HTTP %d: %s", resp.StatusCode, b)
	}
	var sa Superadmin
	if err := json.Unmarshal(b, &sa); err != nil {
		return nil, fmt.Errorf("decode superadmin: %w", err)
	}
	return &sa, nil
}

// CreateSuperadmin registers a new superadmin account.
func (c *Client) CreateSuperadmin(ctx context.Context, req CreateSuperadminRequest) (*Superadmin, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPost, c.adminURL("/api/admin/superadmins"), req)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("create superadmin HTTP %d: %s", resp.StatusCode, b)
	}
	var sa Superadmin
	if err := json.Unmarshal(b, &sa); err != nil {
		return nil, fmt.Errorf("decode superadmin: %w", err)
	}
	return &sa, nil
}

// UpdateSuperadmin updates a superadmin's name or email.
func (c *Client) UpdateSuperadmin(ctx context.Context, id string, req UpdateSuperadminRequest) (*Superadmin, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPut, c.adminURL("/api/admin/superadmins/"+url.PathEscape(id)), req)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update superadmin HTTP %d: %s", resp.StatusCode, b)
	}
	var sa Superadmin
	if err := json.Unmarshal(b, &sa); err != nil {
		return nil, fmt.Errorf("decode superadmin: %w", err)
	}
	return &sa, nil
}

// DeleteSuperadmin removes a superadmin account.
func (c *Client) DeleteSuperadmin(ctx context.Context, id string) error {
	resp, err := c.doWithJWT(ctx, http.MethodDelete, c.adminURL("/api/admin/superadmins/"+url.PathEscape(id)), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("delete superadmin HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Security monitoring
// ────────────────────────────────────────────────────────────────────────────

// ThreatMetrics holds aggregated security threat data.
type ThreatMetrics struct {
	FailedLogins     int64   `json:"failed_logins"`
	BlockedIPs       int64   `json:"blocked_ips"`
	SuspiciousEvents int64   `json:"suspicious_events"`
	RiskScore        float64 `json:"risk_score"`
}

// BlockedIP represents a blocked IP address.
type BlockedIP struct {
	ID        uint      `json:"id"`
	IPAddress string    `json:"ip_address"`
	Reason    string    `json:"reason,omitempty"`
	BlockedAt time.Time `json:"blocked_at"`
}

// BlockIPRequest is the payload for POST /api/admin/security/blocked-ips.
type BlockIPRequest struct {
	IPAddress string `json:"ip_address"`
	Reason    string `json:"reason,omitempty"`
}

// IPReputation holds the reputation score for an IP address.
type IPReputation struct {
	IPAddress  string     `json:"ip_address"`
	Score      float64    `json:"score"`
	IsBlocked  bool       `json:"is_blocked"`
	FailedAuth int64      `json:"failed_auth"`
	LastSeen   *time.Time `json:"last_seen,omitempty"`
}

// GetThreatMetrics returns aggregated security threat data.
func (c *Client) GetThreatMetrics(ctx context.Context) (*ThreatMetrics, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/security/threats"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get threat metrics HTTP %d: %s", resp.StatusCode, b)
	}
	var m ThreatMetrics
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("decode threat metrics: %w", err)
	}
	return &m, nil
}

// ListBlockedIPs returns all currently blocked IP addresses.
func (c *Client) ListBlockedIPs(ctx context.Context) ([]BlockedIP, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/security/blocked-ips"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list blocked IPs HTTP %d: %s", resp.StatusCode, b)
	}
	var ips []BlockedIP
	if err := json.Unmarshal(b, &ips); err != nil {
		var env struct {
			BlockedIPs []BlockedIP `json:"blocked_ips"`
		}
		if err2 := json.Unmarshal(b, &env); err2 == nil {
			return env.BlockedIPs, nil
		}
		return nil, fmt.Errorf("decode blocked IPs: %w", err)
	}
	return ips, nil
}

// BlockIP adds an IP address to the block list.
func (c *Client) BlockIP(ctx context.Context, req BlockIPRequest) (*BlockedIP, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPost, c.adminURL("/api/admin/security/blocked-ips"), req)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("block IP HTTP %d: %s", resp.StatusCode, b)
	}
	var ip BlockedIP
	if err := json.Unmarshal(b, &ip); err != nil {
		return nil, fmt.Errorf("decode blocked IP: %w", err)
	}
	return &ip, nil
}

// UnblockIP removes an IP from the block list by its record ID.
func (c *Client) UnblockIP(ctx context.Context, id string) error {
	resp, err := c.doWithJWT(ctx, http.MethodDelete,
		c.adminURL("/api/admin/security/blocked-ips/"+url.PathEscape(id)), nil)
	if err != nil {
		return err
	}
	b, err := readBody(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unblock IP HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// GetIPReputation returns the security reputation for an IP address.
func (c *Client) GetIPReputation(ctx context.Context, ip string) (*IPReputation, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet,
		c.adminURL("/api/admin/security/ip-reputation/"+url.PathEscape(ip)), nil)
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
		return nil, fmt.Errorf("get IP reputation HTTP %d: %s", resp.StatusCode, b)
	}
	var rep IPReputation
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("decode IP reputation: %w", err)
	}
	return &rep, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Dashboard
// ────────────────────────────────────────────────────────────────────────────

// DashboardStats holds the high-level metrics returned by GET /api/admin/dashboard/stats.
type DashboardStats struct {
	TotalUsers     int64   `json:"total_users"`
	TotalApps      int64   `json:"total_apps"`
	ActiveSessions int64   `json:"active_sessions"`
	FailedLogins   int64   `json:"failed_logins"`
	BlockedIPs     int64   `json:"blocked_ips"`
	RiskScore      float64 `json:"risk_score,omitempty"`
}

// GetDashboardStats returns the admin dashboard statistics.
func (c *Client) GetDashboardStats(ctx context.Context) (*DashboardStats, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/dashboard/stats"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get dashboard stats HTTP %d: %s", resp.StatusCode, b)
	}
	var stats DashboardStats
	if err := json.Unmarshal(b, &stats); err != nil {
		return nil, fmt.Errorf("decode dashboard stats: %w", err)
	}
	return &stats, nil
}

// GetDashboardHealth returns the health summary of Socrate's subsystems.
func (c *Client) GetDashboardHealth(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/dashboard/health"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get dashboard health HTTP %d: %s", resp.StatusCode, b)
	}
	var health map[string]interface{}
	if err := json.Unmarshal(b, &health); err != nil {
		return nil, fmt.Errorf("decode health: %w", err)
	}
	return health, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Admin audit logs
// ────────────────────────────────────────────────────────────────────────────

// AdminLog mirrors dto.AdminLogResponse.
type AdminLog struct {
	ID           uint                   `json:"id"`
	AdminID      uint                   `json:"admin_id"`
	AppID        *uint                  `json:"app_id,omitempty"`
	TargetUserID *uint                  `json:"target_user_id,omitempty"`
	Action       string                 `json:"action"`
	Details      map[string]interface{} `json:"details"`
	CreatedAt    time.Time              `json:"created_at"`
}

// AdminLogListResponse is the paginated admin logs response.
type AdminLogListResponse struct {
	Logs       []AdminLog `json:"logs"`
	TotalCount int64      `json:"total_count"`
	Page       int        `json:"page"`
	PageSize   int        `json:"page_size"`
}

// ListAdminLogs retrieves paginated admin audit log entries.
func (c *Client) ListAdminLogs(ctx context.Context, page, pageSize int) (*AdminLogListResponse, error) {
	path := fmt.Sprintf("/api/admin/logs?page=%d&page_size=%d", page, pageSize)
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list admin logs HTTP %d: %s", resp.StatusCode, b)
	}
	var result AdminLogListResponse
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("decode admin logs: %w", err)
	}
	return &result, nil
}

// GetAdminLog retrieves a single admin audit log entry by ID.
func (c *Client) GetAdminLog(ctx context.Context, id string) (*AdminLog, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/logs/"+url.PathEscape(id)), nil)
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
		return nil, fmt.Errorf("get admin log HTTP %d: %s", resp.StatusCode, b)
	}
	var log AdminLog
	if err := json.Unmarshal(b, &log); err != nil {
		return nil, fmt.Errorf("decode admin log: %w", err)
	}
	return &log, nil
}
