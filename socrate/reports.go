package socrate

// reports.go — security report generation on the admin port
// (/api/admin/reports/*). All calls forward the caller's admin JWT.

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// ReportPeriod is the time window a report covers.
type ReportPeriod struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ReportRequest is the body for GenerateSecurityReport. Type defaults to
// "security_summary" and Format to "json" server-side; Format must be "json"
// or "csv".
type ReportRequest struct {
	Type     string       `json:"type,omitempty"`
	Period   ReportPeriod `json:"period"`
	Format   string       `json:"format,omitempty"`
	Sections []string     `json:"sections,omitempty"`
}

// Report mirrors dto.ReportResponse — the status record for a generated report.
type Report struct {
	ReportID            string     `json:"report_id"`
	Status              string     `json:"status"`
	Type                string     `json:"type"`
	Format              string     `json:"format"`
	DownloadURL         string     `json:"download_url,omitempty"`
	EstimatedCompletion *time.Time `json:"estimated_completion,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
}

// GenerateSecurityReport requests a new security report. Reports are generated
// synchronously server-side, so the returned Report is usually already
// Status == "completed" with a populated DownloadURL.
func (c *Client) GenerateSecurityReport(ctx context.Context, req ReportRequest) (*Report, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPost, c.adminURL("/api/admin/reports/security"), req)
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := decodeJSON(resp, "generate security report", &rep, http.StatusCreated, http.StatusOK); err != nil {
		return nil, err
	}
	return &rep, nil
}

// GetReportStatus returns the status record of a previously generated report.
// Returns nil, nil when the report ID is unknown (404).
func (c *Client) GetReportStatus(ctx context.Context, reportID string) (*Report, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.adminURL("/api/admin/reports/"+reportID), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = readBody(resp)
		return nil, nil
	}
	var rep Report
	if err := decodeJSON(resp, "get report status", &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// DownloadReport downloads a generated report's content (JSON or CSV depending
// on the report's Format) and returns the raw bytes. Maps to
// GET /api/admin/reports/{id}/download.
func (c *Client) DownloadReport(ctx context.Context, reportID string) ([]byte, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet,
		c.adminURL("/api/admin/reports/"+reportID+"/download"), nil)
	if err != nil {
		return nil, err
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read report download: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download report HTTP %d: %s", resp.StatusCode, b)
	}
	return b, nil
}
