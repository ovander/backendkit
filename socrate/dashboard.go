package socrate

// dashboard.go — admin dashboard analytics and admin-meta endpoints that the
// original client did not wrap: dashboard activity feed, login trends, app
// usage, the current admin's profile, top-level admin stats, the admin activity
// feed, and CSV export of admin audit logs. All forward the caller's admin JWT.

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// Dashboard activity feed  (/api/admin/dashboard/activity)
// ────────────────────────────────────────────────────────────────────────────

// DashboardActivityItem is a single entry in the dashboard activity feed.
type DashboardActivityItem struct {
	ID          uint                   `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	UserID      *uint                  `json:"user_id,omitempty"`
	UserEmail   string                 `json:"user_email,omitempty"`
	AppID       *uint                  `json:"app_id,omitempty"`
	AppName     string                 `json:"app_name,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	Success     bool                   `json:"success"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// DashboardActivityResponse is the dashboard activity feed.
type DashboardActivityResponse struct {
	Activities []DashboardActivityItem `json:"activities"`
	Total      int64                   `json:"total"`
}

// GetDashboardActivity returns the most recent activity entries for the
// dashboard. limit caps the number of items (<= 0 uses the server default).
func (c *Client) GetDashboardActivity(ctx context.Context, limit int) (*DashboardActivityResponse, error) {
	path := "/api/admin/dashboard/activity"
	if limit > 0 {
		path += fmt.Sprintf("?limit=%d", limit)
	}
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	var result DashboardActivityResponse
	if err := decodeJSON(resp, "get dashboard activity", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Login trends  (/api/admin/dashboard/login-trends)
// ────────────────────────────────────────────────────────────────────────────

// LoginTrendItem holds login counts for a single day.
type LoginTrendItem struct {
	Date         string `json:"date"`
	SuccessCount int64  `json:"success_count"`
	FailureCount int64  `json:"failure_count"`
	UniqueUsers  int64  `json:"unique_users"`
}

// LoginTrendsResponse is the login-trends series.
type LoginTrendsResponse struct {
	Trends []LoginTrendItem `json:"trends"`
	Period string           `json:"period"`
}

// GetLoginTrends returns daily login success/failure trends over the last
// `days` days (<= 0 uses the server default window).
func (c *Client) GetLoginTrends(ctx context.Context, days int) (*LoginTrendsResponse, error) {
	path := "/api/admin/dashboard/login-trends"
	if days > 0 {
		path += fmt.Sprintf("?days=%d", days)
	}
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	var result LoginTrendsResponse
	if err := decodeJSON(resp, "get login trends", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// App usage  (/api/admin/dashboard/app-usage)
// ────────────────────────────────────────────────────────────────────────────

// AppUsageItem holds usage statistics for a single app.
type AppUsageItem struct {
	AppID        uint       `json:"app_id"`
	AppName      string     `json:"app_name"`
	ClientID     string     `json:"client_id"`
	TotalUsers   int64      `json:"total_users"`
	ActiveUsers  int64      `json:"active_users"`
	TotalLogins  int64      `json:"total_logins"`
	LastActivity *time.Time `json:"last_activity,omitempty"`
}

// AppUsageResponse is the per-app usage breakdown.
type AppUsageResponse struct {
	Apps  []AppUsageItem `json:"apps"`
	Total int64          `json:"total"`
}

// GetAppUsage returns per-app usage statistics across all apps.
func (c *Client) GetAppUsage(ctx context.Context) (*AppUsageResponse, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/dashboard/app-usage"), nil)
	if err != nil {
		return nil, err
	}
	var result AppUsageResponse
	if err := decodeJSON(resp, "get app usage", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Admin meta  (/api/admin/profile, /api/admin/stats, /api/admin/activity)
// ────────────────────────────────────────────────────────────────────────────

// GetAdminProfile returns the profile of the currently authenticated admin.
// Maps to GET /api/admin/profile.
func (c *Client) GetAdminProfile(ctx context.Context) (*FullProfile, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/profile"), nil)
	if err != nil {
		return nil, err
	}
	var p FullProfile
	if err := decodeJSON(resp, "get admin profile", &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetAdminStats returns the lightweight top-of-page admin stats
// (total_users, total_apps). Maps to GET /api/admin/stats.
func (c *Client) GetAdminStats(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/stats"), nil)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := decodeJSON(resp, "get admin stats", &result); err != nil {
		return nil, err
	}
	return result, nil
}

// GetAdminActivity returns the paginated admin activity feed. Maps to
// GET /api/admin/activity and shares the admin-log response shape.
func (c *Client) GetAdminActivity(ctx context.Context, page, pageSize int) (*AdminLogListResponse, error) {
	path := fmt.Sprintf("/api/admin/activity?page=%d&page_size=%d", page, pageSize)
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	var result AdminLogListResponse
	if err := decodeJSON(resp, "get admin activity", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ExportAdminLogs downloads the admin audit log as CSV and returns the raw
// bytes. Maps to GET /api/admin/logs/export.
func (c *Client) ExportAdminLogs(ctx context.Context) ([]byte, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/logs/export"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read export response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("export admin logs HTTP %d: %s", resp.StatusCode, b)
	}
	return b, nil
}
