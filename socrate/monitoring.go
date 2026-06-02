package socrate

// monitoring.go — admin-port monitoring surface that the original client did
// not wrap: app activity logs, active sessions, geographic analytics, token
// analytics, and the real-time security event stream (SSE). All calls forward
// the caller's admin JWT.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ────────────────────────────────────────────────────────────────────────────
// App activity logs  (/api/apps/{app_id}/logs — app-admin scope)
// ────────────────────────────────────────────────────────────────────────────

// AppActivityLog mirrors dto.AppActivityLogResponse — a per-app activity entry
// distinct from the global security audit log (see GetActivityLogs).
type AppActivityLog struct {
	ID            uint                   `json:"id"`
	AppID         uint                   `json:"app_id"`
	UserID        *uint                  `json:"user_id,omitempty"`
	EventType     string                 `json:"event_type"`
	EventCategory string                 `json:"event_category"`
	Metadata      map[string]interface{} `json:"metadata"`
	IPAddress     *string                `json:"ip_address,omitempty"`
	UserAgent     *string                `json:"user_agent,omitempty"`
	Success       bool                   `json:"success"`
	CreatedAt     time.Time              `json:"created_at"`
}

// AppActivityLogListResponse is the paginated app activity log response.
type AppActivityLogListResponse struct {
	Logs       []AppActivityLog `json:"logs"`
	TotalCount int64            `json:"total_count"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
}

// GetAppLogs retrieves the paginated activity log for the configured app.
// Requires the caller to be an admin of the app. Maps to
// GET /api/apps/{app_id}/logs.
func (c *Client) GetAppLogs(ctx context.Context, page, pageSize int) (*AppActivityLogListResponse, error) {
	appID, err := c.getAppID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	path := fmt.Sprintf("/api/apps/%s/logs?page=%d&page_size=%d", appID, page, pageSize)
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	var result AppActivityLogListResponse
	if err := decodeJSON(resp, "get app logs", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Sessions  (/api/admin/sessions, /api/admin/users/{id}/sessions)
// ────────────────────────────────────────────────────────────────────────────

// Session mirrors dto.SessionResponse — an active user session.
type Session struct {
	ID           string    `json:"id"`
	UserID       uint      `json:"user_id"`
	UserEmail    string    `json:"user_email"`
	AppID        uint      `json:"app_id"`
	AppName      string    `json:"app_name"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SessionListResponse is the paginated sessions response.
type SessionListResponse struct {
	Sessions []Session `json:"sessions"`
	Total    int64     `json:"total"`
	Page     int       `json:"page"`
	PageSize int       `json:"page_size"`
}

// ListSessions returns all active sessions, paginated (superadmin scope).
func (c *Client) ListSessions(ctx context.Context, page, pageSize int) (*SessionListResponse, error) {
	path := fmt.Sprintf("/api/admin/sessions?page=%d&page_size=%d", page, pageSize)
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	var result SessionListResponse
	if err := decodeJSON(resp, "list sessions", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUserSessions returns the active sessions for a single user.
func (c *Client) GetUserSessions(ctx context.Context, userID string) (*SessionListResponse, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet,
		c.adminURL("/api/admin/users/"+userID+"/sessions"), nil)
	if err != nil {
		return nil, err
	}
	var result SessionListResponse
	if err := decodeJSON(resp, "get user sessions", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Geographic analytics  (/api/admin/security/geo)
// ────────────────────────────────────────────────────────────────────────────

// GeoCountryStats holds per-country login statistics.
type GeoCountryStats struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	LoginCount  int64  `json:"login_count"`
	UniqueUsers int64  `json:"unique_users"`
	FailedCount int64  `json:"failed_count"`
}

// GeoCityStats holds per-city login statistics.
type GeoCityStats struct {
	City        string  `json:"city"`
	CountryCode string  `json:"country_code"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	LoginCount  int64   `json:"login_count"`
	FailedCount int64   `json:"failed_count"`
}

// GeoAnomaly represents an impossible-travel / unusual-location anomaly.
type GeoAnomaly struct {
	UserID       uint      `json:"user_id"`
	UserEmail    string    `json:"user_email"`
	Description  string    `json:"description"`
	UsualCountry string    `json:"usual_country"`
	LoginCountry string    `json:"login_country"`
	CreatedAt    time.Time `json:"created_at"`
}

// GeoAnalytics mirrors dto.GeoAnalyticsResponse. GeoConfigured is false when the
// server has no GeoIP database configured, in which case the slices are empty.
type GeoAnalytics struct {
	Period        string            `json:"period"`
	GeoConfigured bool              `json:"geo_configured"`
	ByCountry     []GeoCountryStats `json:"by_country"`
	ByCity        []GeoCityStats    `json:"by_city"`
	Anomalies     []GeoAnomaly      `json:"anomalies"`
}

// GetGeoAnalytics returns geographic login analytics for the given period
// (e.g. "24h", "7d", "30d"; empty string defaults to "24h").
func (c *Client) GetGeoAnalytics(ctx context.Context, period string) (*GeoAnalytics, error) {
	path := "/api/admin/security/geo"
	if period != "" {
		path += "?period=" + period
	}
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	var result GeoAnalytics
	if err := decodeJSON(resp, "get geo analytics", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Token analytics  (/api/admin/tokens/stats)
// ────────────────────────────────────────────────────────────────────────────

// TokenCounts holds issued-token counts by type.
type TokenCounts struct {
	AccessTokens  int64 `json:"access_tokens"`
	RefreshTokens int64 `json:"refresh_tokens"`
	IDTokens      int64 `json:"id_tokens"`
}

// TokenAppStats holds per-app token statistics.
type TokenAppStats struct {
	AppID     uint   `json:"app_id"`
	AppName   string `json:"app_name"`
	Issued    int64  `json:"issued"`
	Refreshed int64  `json:"refreshed"`
	Revoked   int64  `json:"revoked"`
}

// TokenHourlyStats holds token statistics bucketed by hour.
type TokenHourlyStats struct {
	Hour      time.Time `json:"hour"`
	Issued    int64     `json:"issued"`
	Refreshed int64     `json:"refreshed"`
	Revoked   int64     `json:"revoked"`
}

// TokenStats mirrors dto.TokenStatsResponse.
type TokenStats struct {
	Period               string             `json:"period"`
	Issued               TokenCounts        `json:"issued"`
	Refreshed            int64              `json:"refreshed"`
	Revoked              int64              `json:"revoked"`
	ExpiredUsageAttempts int64              `json:"expired_usage_attempts"`
	InvalidUsageAttempts int64              `json:"invalid_usage_attempts"`
	ByApp                []TokenAppStats    `json:"by_app"`
	ByHour               []TokenHourlyStats `json:"by_hour"`
}

// GetTokenStats returns token issuance/refresh/revocation analytics for the
// given period (empty string uses the server default).
func (c *Client) GetTokenStats(ctx context.Context, period string) (*TokenStats, error) {
	path := "/api/admin/tokens/stats"
	if period != "" {
		path += "?period=" + period
	}
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	var result TokenStats
	if err := decodeJSON(resp, "get token stats", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Real-time security event stream  (/api/admin/events/stream — SSE)
// ────────────────────────────────────────────────────────────────────────────

// StreamEvent is a single Server-Sent Event from the security event stream.
// Name is the SSE event name ("security_event", "heartbeat", …); Data is the
// raw JSON payload, which you can unmarshal based on Name.
type StreamEvent struct {
	Name string
	Data json.RawMessage
}

// StreamEventOptions filters the security event stream.
type StreamEventOptions struct {
	Severity    string // optional severity filter
	EventType   string // optional event-type filter
	LastEventID string // resume after this event ID
}

// StreamSecurityEvents opens the admin SSE stream and invokes handler for each
// event until ctx is cancelled, the connection closes, or handler returns an
// error. It blocks for the lifetime of the stream and forwards the caller's
// admin JWT. Heartbeat frames are delivered with Name == "heartbeat".
func (c *Client) StreamSecurityEvents(ctx context.Context, opts StreamEventOptions, handler func(StreamEvent) error) error {
	path := "/api/admin/events/stream"
	q := make([]string, 0, 3)
	if opts.Severity != "" {
		q = append(q, "severity="+opts.Severity)
	}
	if opts.EventType != "" {
		q = append(q, "event_type="+opts.EventType)
	}
	if opts.LastEventID != "" {
		q = append(q, "last_event_id="+opts.LastEventID)
	}
	if len(q) > 0 {
		path += "?" + strings.Join(q, "&")
	}

	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return fmt.Errorf("open event stream: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := readBody(resp)
		return fmt.Errorf("open event stream HTTP %d: %s", resp.StatusCode, b)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var name string
	var data strings.Builder

	dispatch := func() error {
		if data.Len() == 0 {
			name, data = "", strings.Builder{}
			return nil
		}
		ev := StreamEvent{Name: name, Data: json.RawMessage(data.String())}
		name, data = "", strings.Builder{}
		return handler(ev)
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Text()
		switch {
		case line == "": // end of an event frame
			if err := dispatch(); err != nil {
				return err
			}
		case strings.HasPrefix(line, "event:"):
			name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		default:
			// ignore comments (": …") and other SSE fields (id:, retry:)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read event stream: %w", err)
	}
	return nil
}
