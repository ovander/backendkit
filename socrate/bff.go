package socrate

// bff.go — backend-for-frontend (BFF) helpers. In a BFF architecture the
// browser never holds tokens directly; the backend performs the OAuth code
// exchange and refresh, then keeps tokens in a server-side session. These
// helpers wrap the token-issuing endpoints the client could not previously
// reach (only the internal client_credentials exchange was wired up).
//
//	ExchangeCode    POST /oauth/token            grant_type=authorization_code
//	RefreshToken    POST /oauth/token            grant_type=refresh_token
//	VerifyMagicLink POST /api/auth/magic-link/verify
//	AdminLogin      POST /api/admin/login        (admin port)
//	Logout          POST /api/auth/logout        (forwards the user JWT)

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ErrMagicLinkAlreadyUsed is returned by VerifyMagicLink when the single-use
// token has already been consumed (HTTP 422).
var ErrMagicLinkAlreadyUsed = errors.New("magic link already used")

// ErrMagicLinkInvalid is returned by VerifyMagicLink when the token is invalid,
// expired, or does not match the client (HTTP 401).
var ErrMagicLinkInvalid = errors.New("magic link invalid or expired")

// ErrInvalidCredentials is returned by AdminLogin on HTTP 401.
var ErrInvalidCredentials = errors.New("invalid credentials")

// OAuthError is a non-2xx response from the /oauth/token endpoint. Code and
// Description carry the RFC 6749 §5.2 {"error","error_description"} body when
// the server sent one (Code is empty otherwise). Callers use errors.As to
// distinguish a rejected grant (e.g. Code == "invalid_grant": the refresh
// token is spent, expired or revoked — the session is dead) from a transient
// failure (transport error, 5xx: retry, keep the session).
type OAuthError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("token endpoint: %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("token endpoint HTTP %d: %s", e.StatusCode, e.Description)
}

// TokenSet is the response of the /oauth/token endpoint (authorization_code and
// refresh_token grants). RefreshToken and IDToken are present depending on the
// granted scopes and flow.
type TokenSet struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	IDToken      string            `json:"id_token,omitempty"`
	TokenType    string            `json:"token_type"`
	ExpiresIn    int               `json:"expires_in"`
	Scope        string            `json:"scope,omitempty"`
	Roles        []string          `json:"roles,omitempty"`
	AppRoles     map[string]string `json:"app_roles,omitempty"`
}

// LoginResult is the richer token response returned by the magic-link verify and
// admin-login endpoints, which also include the resolved user ID.
type LoginResult struct {
	AccessToken        string            `json:"access_token"`
	RefreshToken       string            `json:"refresh_token"`
	IDToken            string            `json:"id_token"`
	TokenType          string            `json:"token_type"`
	ExpiresIn          int               `json:"expires_in"`
	UserID             uint              `json:"user_id"`
	Roles              []string          `json:"roles"`
	AppRoles           map[string]string `json:"app_roles"`
	MustChangePassword bool              `json:"must_change_password,omitempty"`
}

// postForm sends an application/x-www-form-urlencoded POST to fullURL.
func (c *Client) postForm(ctx context.Context, fullURL string, data url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build form request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.httpClient.Do(req)
}

// decodeTokenSet decodes a /oauth/token response, surfacing a non-2xx status
// as a typed *OAuthError carrying the RFC 6749 {"error","error_description"}
// body when present.
func decodeTokenSet(resp *http.Response) (*TokenSet, error) {
	b, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		oe := &OAuthError{StatusCode: resp.StatusCode}
		if json.Unmarshal(b, &body) == nil && body.Error != "" {
			oe.Code, oe.Description = body.Error, body.ErrorDescription
		} else {
			oe.Description = string(b)
		}
		return nil, oe
	}
	var ts TokenSet
	if err := json.Unmarshal(b, &ts); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &ts, nil
}

// ExchangeCode exchanges an authorization code for tokens (Authorization Code
// flow, RFC 6749 §4.1.3). Pass the PKCE codeVerifier you generated before the
// /oauth/authorize redirect; pass "" if PKCE was not used. The configured
// ClientSecret is sent automatically for confidential clients.
func (c *Client) ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (*TokenSet, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {c.clientID},
	}
	if c.clientSecret != "" {
		data.Set("client_secret", c.clientSecret)
	}
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}
	resp, err := c.postForm(ctx, c.oauthURL("/oauth/token"), data)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	return decodeTokenSet(resp)
}

// RefreshToken exchanges a refresh token for a fresh token set
// (RFC 6749 §6). The configured ClientSecret is sent for confidential clients.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenSet, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.clientID},
	}
	if c.clientSecret != "" {
		data.Set("client_secret", c.clientSecret)
	}
	resp, err := c.postForm(ctx, c.oauthURL("/oauth/token"), data)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	return decodeTokenSet(resp)
}

// VerifyMagicLink completes a passwordless login by exchanging the single-use
// token (from the emailed link) for a full token set. The configured ClientID
// is sent as required by the public verify endpoint.
//
// Returns ErrMagicLinkAlreadyUsed (422) or ErrMagicLinkInvalid (401) for the
// two recoverable failure modes.
func (c *Client) VerifyMagicLink(ctx context.Context, token string) (*LoginResult, error) {
	body := map[string]string{"token": token, "client_id": c.clientID}
	resp, err := c.doHTTPNoAuth(ctx, http.MethodPost, c.oauthURL("/api/auth/magic-link/verify"), body)
	if err != nil {
		return nil, fmt.Errorf("verify magic link: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusUnprocessableEntity:
		_, _ = readBody(resp)
		return nil, ErrMagicLinkAlreadyUsed
	case http.StatusUnauthorized:
		_, _ = readBody(resp)
		return nil, ErrMagicLinkInvalid
	}
	var lr LoginResult
	if err := decodeJSON(resp, "verify magic link", &lr); err != nil {
		return nil, err
	}
	return &lr, nil
}

// AdminLogin authenticates a human superadmin against the admin portal and
// returns a token set. Maps to POST /api/admin/login on the admin port. Returns
// ErrInvalidCredentials on 401.
func (c *Client) AdminLogin(ctx context.Context, email, password string) (*LoginResult, error) {
	body := map[string]string{"email": email, "password": password}
	resp, err := c.doHTTPNoAuth(ctx, http.MethodPost, c.adminURL("/api/admin/login"), body)
	if err != nil {
		return nil, fmt.Errorf("admin login: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = readBody(resp)
		return nil, ErrInvalidCredentials
	}
	var lr LoginResult
	if err := decodeJSON(resp, "admin login", &lr); err != nil {
		return nil, err
	}
	return &lr, nil
}

// Logout invalidates the caller's current session/token server-side. Maps to
// POST /api/auth/logout and forwards the user JWT from context.
func (c *Client) Logout(ctx context.Context) error {
	resp, err := c.doWithJWT(ctx, http.MethodPost, c.oauthURL("/api/auth/logout"), nil)
	if err != nil {
		return err
	}
	return decodeJSON(resp, "logout", nil, http.StatusOK, http.StatusNoContent)
}

// doHTTPNoAuth sends a JSON request without an Authorization header — for the
// public token/login endpoints that authenticate via the body instead.
func (c *Client) doHTTPNoAuth(ctx context.Context, method, fullURL string, body interface{}) (*http.Response, error) {
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.httpClient.Do(req)
}
