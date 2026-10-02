package socrate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/backendkit/socrate"
)

// GetCurrentUserProfile decodes email_verified and the OIDC picture claim.
func TestGetCurrentUserProfile_EmailVerifiedAndPicture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/userinfo" || r.Header.Get("Authorization") != "Bearer user-jwt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"42","email":"ada@example.test","email_verified":true,` +
			`"name":"Ada","picture":"https://cdn.example.test/42.png"}`))
	}))
	defer srv.Close()
	c, err := socrate.NewClient(socrate.ClientConfig{BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "cid"})
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.GetCurrentUserProfile(socrate.WithJWT(context.Background(), "user-jwt"))
	if err != nil || p == nil {
		t.Fatalf("GetCurrentUserProfile = %v, %v", p, err)
	}
	if !p.EmailVerified || p.Picture != "https://cdn.example.test/42.png" || p.Sub != "42" {
		t.Fatalf("profile = %+v", p)
	}
}

// The member look-up decodes avatar_url; absent means nil.
func TestGetUserAsService_AvatarURL(t *testing.T) {
	c, _ := serviceRoutesServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/apps/3/service/users/7" {
			_, _ = w.Write([]byte(`{"id":7,"email":"m@example.test","avatar_url":"https://cdn.example.test/7.png"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":8,"email":"n@example.test"}`))
	})
	u, err := c.GetUserAsService(context.Background(), "7")
	if err != nil || u.AvatarURL == nil || *u.AvatarURL != "https://cdn.example.test/7.png" {
		t.Fatalf("with avatar: %+v, %v", u, err)
	}
	if u, err = c.GetUserAsService(context.Background(), "8"); err != nil || u.AvatarURL != nil {
		t.Fatalf("without avatar: %+v, %v", u, err)
	}
}
