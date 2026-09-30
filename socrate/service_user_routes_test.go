package socrate_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/backendkit/socrate"
)

// serviceRoutesServer is a fake Socrate that serves only the service-account
// routes, and records the path and bearer of every admin-port call.
func serviceRoutesServer(t *testing.T, users http.HandlerFunc) (*socrate.Client, *[]string) {
	t.Helper()
	var calls []string
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "svc-tok", "expires_in": 3600, "token_type": "Bearer"})
	})
	mux.HandleFunc("/api/apps/3/service/users", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["email"] != "new@example.test" || body["name"] != "New" || body["role"] != "user" {
			t.Errorf("RegisterUser body = %v", body)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(socrate.CreateUserResult{UserID: 21, Role: "user", EmailSent: true})
	})
	mux.HandleFunc("/api/apps/3/service/users/", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		users(w, r)
	})
	// The user-token routes answer a service token the way Socrate does.
	mux.HandleFunc("/api/apps/3/users", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		http.Error(w, `{"error":"invalid token claims"}`, http.StatusUnauthorized)
	})
	mux.HandleFunc("/api/apps/3/users/", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		http.Error(w, `{"error":"invalid token claims"}`, http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := socrate.NewClient(socrate.ClientConfig{
		BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "cid", ClientSecret: "secret", AppID: "3",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, &calls
}

func TestRegisterUser_UsesTheServiceRoute(t *testing.T) {
	c, calls := serviceRoutesServer(t, nil)
	res, err := c.RegisterUser(context.Background(), socrate.CreateUserRequest{Email: "new@example.test", Name: "New", Role: "user"})
	if err != nil || res.UserID != 21 || !res.EmailSent {
		t.Fatalf("RegisterUser = %+v, %v", res, err)
	}
	if len(*calls) != 1 || (*calls)[0] != "POST /api/apps/3/service/users Bearer svc-tok" {
		t.Fatalf("calls = %v", *calls)
	}
}

func TestGetUserAsService_UsesTheServiceRoute(t *testing.T) {
	c, calls := serviceRoutesServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/apps/3/service/users/7" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"user not in app"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(socrate.User{ID: 7, Email: "m@example.test", Role: "admin"})
	})
	u, err := c.GetUserAsService(context.Background(), "7")
	if err != nil || u == nil || u.ID != 7 || u.Role != "admin" {
		t.Fatalf("GetUserAsService = %+v, %v", u, err)
	}
	if (*calls)[0] != "GET /api/apps/3/service/users/7 Bearer svc-tok" {
		t.Fatalf("calls = %v", *calls)
	}

	// Socrate's own 404 (not a member, or no such user) is nil, nil.
	u, err = c.GetUserAsService(context.Background(), "8")
	if u != nil || err != nil {
		t.Fatalf("non-member = %+v, %v; want nil, nil", u, err)
	}
}

// A Socrate without the route answers the router's plain-text 404: that is an
// error, never a silent "no such user".
func TestGetUserAsService_MissingRouteIsAnError(t *testing.T) {
	c, _ := serviceRoutesServer(t, http.NotFound)
	u, err := c.GetUserAsService(context.Background(), "7")
	if u != nil || err == nil || !strings.Contains(err.Error(), "v1.5.3") {
		t.Fatalf("missing route = %+v, %v; want an error naming the Socrate version", u, err)
	}
}
