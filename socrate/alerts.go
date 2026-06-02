package socrate

// alerts.go — security alert rules and triggered-alert history on the admin
// port (/api/admin/alerts/*). All calls forward the caller's admin JWT.

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// AlertRule mirrors dto.AlertRuleResponse — a configured alerting rule.
type AlertRule struct {
	ID          uint                   `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	EventType   string                 `json:"event_type"`
	Condition   map[string]interface{} `json:"condition"`
	Severity    string                 `json:"severity"`
	Enabled     bool                   `json:"enabled"`
	Actions     []string               `json:"actions"`
	Recipients  []string               `json:"recipients,omitempty"`
	WebhookURL  string                 `json:"webhook_url,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// AlertRuleRequest is the body for creating or updating an alert rule.
type AlertRuleRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	EventType   string                 `json:"event_type"`
	Condition   map[string]interface{} `json:"condition"`
	Severity    string                 `json:"severity"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	Actions     []string               `json:"actions"`
	Recipients  []string               `json:"recipients,omitempty"`
	WebhookURL  string                 `json:"webhook_url,omitempty"`
}

// AlertRulesListResponse is the list of configured alert rules.
type AlertRulesListResponse struct {
	Rules []AlertRule `json:"rules"`
	Total int64       `json:"total"`
}

// TriggeredAlert mirrors dto.TriggeredAlertResponse — a fired alert instance.
type TriggeredAlert struct {
	ID              uint                   `json:"id"`
	RuleID          uint                   `json:"rule_id"`
	RuleName        string                 `json:"rule_name"`
	Severity        string                 `json:"severity"`
	Message         string                 `json:"message"`
	Details         map[string]interface{} `json:"details,omitempty"`
	Acknowledged    bool                   `json:"acknowledged"`
	AcknowledgedBy  *uint                  `json:"acknowledged_by,omitempty"`
	AcknowledgedAt  *time.Time             `json:"acknowledged_at,omitempty"`
	AcknowledgeNote string                 `json:"acknowledge_note,omitempty"`
	TriggeredAt     time.Time              `json:"triggered_at"`
}

// AlertsHistoryResponse is the paginated triggered-alert history.
type AlertsHistoryResponse struct {
	Alerts         []TriggeredAlert `json:"alerts"`
	Total          int64            `json:"total"`
	Unacknowledged int64            `json:"unacknowledged"`
	Page           int              `json:"page"`
	PageSize       int              `json:"page_size"`
}

// ListAlertRules returns all configured alert rules.
func (c *Client) ListAlertRules(ctx context.Context) (*AlertRulesListResponse, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/alerts/rules"), nil)
	if err != nil {
		return nil, err
	}
	var result AlertRulesListResponse
	if err := decodeJSON(resp, "list alert rules", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreateAlertRule creates a new alert rule and returns the stored record.
func (c *Client) CreateAlertRule(ctx context.Context, req AlertRuleRequest) (*AlertRule, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPost, c.adminURL("/api/admin/alerts/rules"), req)
	if err != nil {
		return nil, err
	}
	var rule AlertRule
	if err := decodeJSON(resp, "create alert rule", &rule, http.StatusCreated, http.StatusOK); err != nil {
		return nil, err
	}
	return &rule, nil
}

// UpdateAlertRule updates an existing alert rule by ID.
func (c *Client) UpdateAlertRule(ctx context.Context, id string, req AlertRuleRequest) (*AlertRule, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPut, c.adminURL("/api/admin/alerts/rules/"+id), req)
	if err != nil {
		return nil, err
	}
	var rule AlertRule
	if err := decodeJSON(resp, "update alert rule", &rule); err != nil {
		return nil, err
	}
	return &rule, nil
}

// DeleteAlertRule removes an alert rule by ID.
func (c *Client) DeleteAlertRule(ctx context.Context, id string) error {
	resp, err := c.doWithJWT(ctx, http.MethodDelete, c.adminURL("/api/admin/alerts/rules/"+id), nil)
	if err != nil {
		return err
	}
	return decodeJSON(resp, "delete alert rule", nil, http.StatusOK, http.StatusNoContent)
}

// GetAlertHistory returns the paginated triggered-alert history.
func (c *Client) GetAlertHistory(ctx context.Context, page, pageSize int) (*AlertsHistoryResponse, error) {
	path := fmt.Sprintf("/api/admin/alerts/history?page=%d&page_size=%d", page, pageSize)
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL(path), nil)
	if err != nil {
		return nil, err
	}
	var result AlertsHistoryResponse
	if err := decodeJSON(resp, "get alert history", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// AcknowledgeAlert acknowledges a triggered alert by ID, with an optional note.
func (c *Client) AcknowledgeAlert(ctx context.Context, id, note string) error {
	body := map[string]string{"note": note}
	resp, err := c.doWithJWT(ctx, http.MethodPost,
		c.adminURL("/api/admin/alerts/"+id+"/acknowledge"), body)
	if err != nil {
		return err
	}
	return decodeJSON(resp, "acknowledge alert", nil, http.StatusOK, http.StatusNoContent)
}
