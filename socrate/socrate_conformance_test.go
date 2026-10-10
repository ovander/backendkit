//go:build conformance

// Live conformance: the socrate client against a running Socrate. Run with
// scripts/conformance-local.sh (see package conformance for the environment).
// Without that environment the tests fail: the build tag is the opt-in.

package socrate_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ovander/backendkit/socrate"
)

const liveUser = "conf-socrate@example.test"

func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: the conformance tests need a running Socrate (scripts/conformance-local.sh)", name)
	}
	return v
}

// liveClient returns a client for the plain conformance client. Service-account
// calls need its numeric app id, which it learns as an application would: from
// the sub ("app:<id>") of its own service token.
func liveClient(t *testing.T) *socrate.Client {
	t.Helper()
	cfg := socrate.ClientConfig{
		BaseURL:      liveEnv(t, "SOCRATE_ISSUER"),
		AdminBaseURL: liveEnv(t, "SOCRATE_ADMIN_URL"),
		ClientID:     liveEnv(t, "SOCRATE_PLAIN_CLIENT_ID"),
		ClientSecret: liveEnv(t, "SOCRATE_PLAIN_CLIENT_SECRET"),
		Timeout:      30 * time.Second,
	}
	c, err := socrate.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := c.ServiceToken(context.Background())
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	in, err := c.IntrospectToken(context.Background(), tok)
	if err != nil || !strings.HasPrefix(in.Sub, "app:") {
		t.Fatalf("introspect the service token: %+v, %v", in, err)
	}
	cfg.AppID = strings.TrimPrefix(in.Sub, "app:")
	if c, err = socrate.NewClient(cfg); err != nil {
		t.Fatal(err)
	}
	return c
}

// liveLogin signs the test user in through Socrate's direct login API (the
// client wraps the hosted flow's token calls, not a password login) and
// returns the token set.
func liveLogin(t *testing.T) *socrate.TokenSet {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"email": liveUser, "password": liveEnv(t, "SOCRATE_USER_PASSWORD"),
		"app_client_id": liveEnv(t, "SOCRATE_PLAIN_CLIENT_ID"),
	})
	resp, err := http.Post(liveEnv(t, "SOCRATE_ISSUER")+"/api/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: HTTP %d: %.200s", resp.StatusCode, b)
	}
	var ts socrate.TokenSet
	if err := json.Unmarshal(b, &ts); err != nil || ts.AccessToken == "" || ts.RefreshToken == "" {
		t.Fatalf("login: no token set (%v)", err)
	}
	return &ts
}

func TestConformanceServiceAccount(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	tok, exp, err := c.ServiceToken(ctx)
	if err != nil {
		t.Fatalf("ServiceToken: %v", err)
	}
	if tok == "" || !exp.After(time.Now()) {
		t.Fatalf("ServiceToken: empty token or expiry %v in the past", exp)
	}
	in, err := c.IntrospectToken(ctx, tok)
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !in.Active || !strings.HasPrefix(in.Sub, "app:") || in.ClientID != liveEnv(t, "SOCRATE_PLAIN_CLIENT_ID") || in.Scope != "api" {
		t.Errorf("service token introspection = %+v, want active, sub app:<id>, the client, scope api", in)
	}
}

func TestConformanceUserCalls(t *testing.T) {
	c := liveClient(t)
	ts := liveLogin(t)
	ctx := socrate.WithJWT(context.Background(), ts.AccessToken)

	profile, err := c.GetCurrentUserProfile(ctx)
	if err != nil || profile == nil {
		t.Fatalf("GetCurrentUserProfile = %v, %v", profile, err)
	}
	if profile.Email != liveUser || !profile.EmailVerified {
		t.Errorf("userinfo = %+v, want %s, verified", profile, liveUser)
	}
	id, err := strconv.ParseUint(profile.Sub, 10, 64)
	if err != nil {
		t.Fatalf("userinfo sub %q is not the numeric user id", profile.Sub)
	}

	full, err := c.GetProfile(ctx)
	if err != nil || full == nil {
		t.Fatalf("GetProfile = %v, %v", full, err)
	}

	in, err := c.IntrospectToken(context.Background(), ts.AccessToken)
	if err != nil {
		t.Fatalf("IntrospectToken: %v", err)
	}
	if !in.Active || in.Sub != profile.Sub || in.ClientID != liveEnv(t, "SOCRATE_PLAIN_CLIENT_ID") {
		t.Errorf("introspection = %+v, want active for sub %s", in, profile.Sub)
	}

	// The application looks its member up by the token's sub.
	member, err := c.GetUserAsService(context.Background(), profile.Sub)
	if err != nil || member == nil {
		t.Fatalf("GetUserAsService(%s) = %v, %v", profile.Sub, member, err)
	}
	if member.ID != uint(id) || member.Email != liveUser || member.Role != "user" {
		t.Errorf("member = %+v, want id %d, %s, role user", member, id, liveUser)
	}
	if member.TokenVersion == nil || member.Locked == nil {
		t.Errorf("member lacks token_version or locked (Socrate ≥ v1.8.0 sends both)")
	}
	if none, err := c.GetUserAsService(context.Background(), "999999999"); err != nil || none != nil {
		t.Errorf("GetUserAsService(non-member) = %v, %v, want nil, nil", none, err)
	}
}

func TestConformanceRefreshRevokeLogout(t *testing.T) {
	c := liveClient(t)
	ctx := context.Background()
	first := liveLogin(t)

	next, err := c.RefreshToken(ctx, first.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if next.AccessToken == "" || next.RefreshToken == "" || next.RefreshToken == first.RefreshToken || next.TokenType != "Bearer" {
		t.Fatalf("RefreshToken: want a rotated Bearer token set, got type %q", next.TokenType)
	}

	// A revoked refresh token is refused with invalid_grant.
	if err := c.RevokeToken(ctx, next.RefreshToken); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	_, err = c.RefreshToken(ctx, next.RefreshToken)
	var oe *socrate.OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Errorf("refresh with a revoked token: %v, want an OAuthError invalid_grant", err)
	}
	if in, err := c.IntrospectToken(ctx, next.RefreshToken); err != nil || in.Active {
		t.Errorf("introspection of a revoked refresh token = %+v, %v, want inactive", in, err)
	}

	// Logout ends the user's tokens.
	other := liveLogin(t)
	userCtx := socrate.WithJWT(ctx, other.AccessToken)
	if err := c.Logout(userCtx); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if p, err := c.GetCurrentUserProfile(userCtx); err != nil || p != nil {
		t.Errorf("userinfo after logout = %v, %v, want nil, nil (401)", p, err)
	}
	if _, err := c.RefreshToken(ctx, other.RefreshToken); !errors.As(err, &oe) {
		t.Errorf("refresh after logout: %v, want an OAuthError", err)
	}
}
