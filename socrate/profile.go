package socrate

// profile.go — user self-service profile, served on the OAuth (public) port
// under /api/profile. Unlike GetCurrentUserProfile (which reads the limited
// OIDC /oauth/userinfo claim set), these methods read and write the full user
// profile record, including editable fields such as phone, company and timezone.
//
// All calls forward the caller's JWT — they act on the *currently authenticated*
// user, never on an arbitrary user ID.

import (
	"context"
	"net/http"
	"time"
)

// FullProfile mirrors the dto.UserResponse returned by GET/PUT /api/profile.
// Optional fields are pointers and are nil when the user has not set them.
type FullProfile struct {
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

// UpdateProfileRequest is the body for UpdateProfile. Only the non-nil fields
// are changed; the email and role are intentionally not editable here.
type UpdateProfileRequest struct {
	Name       *string `json:"name,omitempty"`
	Title      *string `json:"title,omitempty"`
	Division   *string `json:"division,omitempty"`
	Company    *string `json:"company,omitempty"`
	Country    *string `json:"country,omitempty"`
	Phone      *string `json:"phone,omitempty"`
	JobTitle   *string `json:"job_title,omitempty"`
	Department *string `json:"department,omitempty"`
	Language   *string `json:"language,omitempty"`
	Timezone   *string `json:"timezone,omitempty"`
}

// GetProfile returns the full profile of the currently authenticated user.
// Returns nil, nil when the user record is not found (404).
func (c *Client) GetProfile(ctx context.Context) (*FullProfile, error) {
	resp, err := c.doWithJWT(ctx, http.MethodGet, c.oauthURL("/api/profile"), nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_, _ = readBody(resp)
		return nil, nil
	}
	var p FullProfile
	if err := decodeJSON(resp, "get profile", &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// UpdateProfile patches the authenticated user's editable profile fields and
// returns the updated record. Maps to PUT /api/profile.
func (c *Client) UpdateProfile(ctx context.Context, req UpdateProfileRequest) (*FullProfile, error) {
	resp, err := c.doWithJWT(ctx, http.MethodPut, c.oauthURL("/api/profile"), req)
	if err != nil {
		return nil, err
	}
	var p FullProfile
	if err := decodeJSON(resp, "update profile", &p); err != nil {
		return nil, err
	}
	return &p, nil
}
