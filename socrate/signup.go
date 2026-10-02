package socrate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// SignupRequest is the body of a self-service sign-up: the user's own name,
// email and password. The configured ClientID is added by Signup.
type SignupRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SignupResult is Socrate's answer to a successful sign-up. VerifyURL is set
// only by a Socrate running in development mode.
type SignupResult struct {
	UserID    uint   `json:"user_id"`
	Message   string `json:"message"`
	VerifyURL string `json:"verify_url,omitempty"`
}

// SignupError is returned when Socrate refuses a sign-up for a reason the user
// can act on, such as the password policy. Message is Socrate's text, which is
// safe to show to the user.
type SignupError struct {
	Message string
}

// Error implements error.
func (e *SignupError) Error() string { return "signup rejected: " + e.Message }

// Signup creates a Socrate account with the password the user chose, via
// POST /api/auth/signup on the OAuth port, and makes the user a member of this
// client's application with the "user" role. Socrate then sends a verification
// e-mail; the user can sign in once the address is verified.
//
// It is called on the user's behalf: pass the browser's address with
// WithClientAttribution, since Socrate rate-limits sign-ups per client address
// (without it, every sign-up counts against your server's address).
//
// Returns ErrUserAlreadyExists when the email has a Socrate account, possibly
// created through another application: ask the user to sign in instead, then
// add them to this application with RegisterUser or InviteUserAsService.
// Returns a *SignupError for other refusals (password policy, missing field).
func (c *Client) Signup(ctx context.Context, req SignupRequest) (*SignupResult, error) {
	body := map[string]string{
		"name": req.Name, "email": req.Email, "password": req.Password, "client_id": c.clientID,
	}
	resp, err := c.doHTTPNoAuth(ctx, http.MethodPost, c.oauthURL("/api/auth/signup"), body)
	if err != nil {
		return nil, fmt.Errorf("signup: %w", err)
	}
	b, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusOK:
		var result SignupResult
		if err := json.Unmarshal(b, &result); err != nil {
			return nil, fmt.Errorf("decode signup response: %w", err)
		}
		return &result, nil
	case http.StatusBadRequest:
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			if strings.EqualFold(e.Error, "email already exists") {
				return nil, ErrUserAlreadyExists
			}
			return nil, &SignupError{Message: e.Error}
		}
	}
	return nil, fmt.Errorf("signup HTTP %d: %s", resp.StatusCode, b)
}
