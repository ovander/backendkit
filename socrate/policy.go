package socrate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ────────────────────────────────────────────────────────────────────────────
// Policy decisions  (Admin port — POST /api/apps/{id}/service/policy/decide)
// ────────────────────────────────────────────────────────────────────────────

// Policy modes, as reported by Socrate with every decision. The mode is set
// centrally (POLICY_MODE) and tells an enforcement point what to do with the
// answer; see the pep package, which implements exactly that.
const (
	PolicyModeOff     = "off"     // ignore the decision
	PolicyModeShadow  = "shadow"  // log a denial, allow the request
	PolicyModeEnforce = "enforce" // honour the decision
)

// Policy obligations an allow can carry. The enforcement point must honour
// them; the pep package does.
const (
	ObligationFreshAuth = "require_fresh_auth"
	ObligationMFA       = "require_mfa"
)

// ErrPolicyUnavailable is returned by Decide when Socrate answers but has no
// policy it can evaluate (503). The returned Decision still carries the mode.
var ErrPolicyUnavailable = errors.New("socrate: policy unavailable")

// PolicySubject names the user a decision is about. Prefer Token — the user's
// own access token, which Socrate verifies and which supplies how and when the
// user authenticated. UserID works too, but then rules about scopes, amr or
// auth_time cannot be satisfied. Nil means the application itself.
type PolicySubject struct {
	Token  string `json:"token,omitempty"`
	UserID uint   `json:"user_id,omitempty"`
}

// PolicyResource is what is being acted on.
type PolicyResource struct {
	Type       string         `json:"type,omitempty"`
	ID         string         `json:"id,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// PolicyContext is the request as the application observed it.
type PolicyContext struct {
	// IP is the end user's address. Socrate derives ip_country from it.
	IP         string         `json:"ip,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// DecideRequest asks Socrate's policy decision point about one action.
type DecideRequest struct {
	Subject  *PolicySubject `json:"subject,omitempty"`
	Action   string         `json:"action"`
	Resource PolicyResource `json:"resource"`
	Context  PolicyContext  `json:"context"`
}

// Decision is Socrate's answer.
type Decision struct {
	Allow         bool     `json:"allow"`
	Rule          string   `json:"rule,omitempty"`
	Reason        string   `json:"reason"`
	Obligations   []string `json:"obligations,omitempty"`
	PolicyVersion int64    `json:"policy_version"`
	Mode          string   `json:"mode"`
}

// Decide asks Socrate's policy decision point about req, authenticated as this
// application with its client-credentials token. Requires ClientSecret and
// AppID in ClientConfig.
//
// Socrate resolves the subject itself — role, attributes, membership of this
// application, and for a token, how the user authenticated — so nothing about
// the user is taken on the application's word. The request id in ctx is sent
// as X-Correlation-ID, which is how a denial is found in Socrate's decision log.
//
// Errors: ErrPolicyUnavailable (503; the Decision carries the mode),
// or an error describing a rejected request (unknown subject, invalid token,
// malformed action).
func (c *Client) Decide(ctx context.Context, req DecideRequest) (*Decision, error) {
	appID, err := c.getAppIDAsService(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve app ID: %w", err)
	}
	tok, err := c.getServiceToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("get service token: %w", err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal decide request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.adminURL(fmt.Sprintf("/api/apps/%s/service/policy/decide", url.PathEscape(appID))),
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+tok)
	httpReq.Header.Set("Content-Type", "application/json")
	setCorrelationID(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("decide: %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var d Decision
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, fmt.Errorf("decode decision: %w", err)
		}
		return &d, nil
	case http.StatusServiceUnavailable:
		var d Decision
		_ = json.Unmarshal(b, &d) // best effort: the mode, if present
		return &d, ErrPolicyUnavailable
	default:
		return nil, fmt.Errorf("decide HTTP %d: %s", resp.StatusCode, b)
	}
}
