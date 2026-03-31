package socrate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/socrate"
)

// newTestServer starts a fake Socrate server that serves preset responses.
func newTestServer(mux *http.ServeMux) (*httptest.Server, func()) {
	srv := httptest.NewServer(mux)
	return srv, srv.Close
}

func appsHandler(appID int, clientID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(socrate.AppListResponse{
			Apps: []socrate.App{{ID: uint(appID), ClientID: clientID}},
		})
	}
}

func TestNewClient_RequiresBaseURL(t *testing.T) {
	_, err := socrate.NewClient(socrate.ClientConfig{ClientID: "cid"})
	if err == nil {
		t.Error("expected error for missing BaseURL")
	}
}

func TestNewClient_RequiresClientID(t *testing.T) {
	_, err := socrate.NewClient(socrate.ClientConfig{BaseURL: "http://localhost"})
	if err == nil {
		t.Error("expected error for missing ClientID")
	}
}

func TestWithJWT_StoresAndRetrieves(t *testing.T) {
	ctx := socrate.WithJWT(context.Background(), "tok123")
	// WithJWT now delegates to ctxutil.WithRawJWT; verify via ctxutil.GetRawJWT.
	if got := ctxutil.GetRawJWT(ctx); got != "tok123" {
		t.Errorf("expected tok123, got %v", got)
	}
}

func TestListUsers_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/apps", appsHandler(42, "my-client"))
	mux.HandleFunc("/api/apps/42/users", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(socrate.UserListResponse{
			Users:      []socrate.User{{ID: 1, Email: "a@b.com"}},
			TotalCount: 1,
		})
	})
	srv, close := newTestServer(mux)
	defer close()

	// AdminBaseURL must equal BaseURL in tests — both OAuth and admin routes
	// are served by the same httptest.Server.
	c, _ := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      srv.URL,
		AdminBaseURL: srv.URL,
		ClientID:     "my-client",
	})
	ctx := socrate.WithJWT(context.Background(), "user-token")
	list, err := c.ListUsers(ctx, "", 1, 10)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(list.Users) != 1 || list.Users[0].Email != "a@b.com" {
		t.Errorf("unexpected list: %+v", list)
	}
}

func TestGetUser_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/apps", appsHandler(1, "cid"))
	mux.HandleFunc("/api/apps/1/users/99", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv, close := newTestServer(mux)
	defer close()

	c, _ := socrate.NewClient(socrate.ClientConfig{BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "cid", AppID: "1"})
	ctx := socrate.WithJWT(context.Background(), "tok")
	u, err := c.GetUser(ctx, "99")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if u != nil {
		t.Errorf("expected nil user, got: %+v", u)
	}
}

func TestCreateUser_ConflictReturnsErrUserAlreadyExists(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/apps", appsHandler(1, "cid"))
	mux.HandleFunc("/api/apps/1/users", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})
	srv, close := newTestServer(mux)
	defer close()

	c, _ := socrate.NewClient(socrate.ClientConfig{BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "cid", AppID: "1"})
	ctx := socrate.WithJWT(context.Background(), "tok")
	_, err := c.CreateUser(ctx, socrate.CreateUserRequest{Email: "dup@x.com", Role: "viewer"})
	if err != socrate.ErrUserAlreadyExists {
		t.Errorf("expected ErrUserAlreadyExists, got: %v", err)
	}
}

func TestSendMagicLink_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "svc-tok",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/api/admin/apps", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(socrate.AppListResponse{
			Apps: []socrate.App{{ID: 3, ClientID: "cid"}},
		})
	})
	mux.HandleFunc("/api/apps/3/service/magic-link", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(socrate.MagicLinkResponse{
			Message:  "If that email address is registered, a login link has been sent.",
			MagicURL: "http://localhost/api/auth/magic-link/verify?token=abc123&client_id=cid",
		})
	})
	srv, close := newTestServer(mux)
	defer close()

	c, _ := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      srv.URL,
		AdminBaseURL: srv.URL,
		ClientID:     "cid",
		ClientSecret: "secret",
	})
	resp, err := c.SendMagicLink(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("SendMagicLink: %v", err)
	}
	if resp.Message == "" {
		t.Error("expected non-empty message")
	}
	if resp.MagicURL == "" {
		t.Error("expected MagicURL in dev-mode response")
	}
}

func TestSendMagicLink_RateLimited(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "svc-tok",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/api/apps/3/service/magic-link", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"too many requests, please try again later"}`, http.StatusTooManyRequests)
	})
	srv, close := newTestServer(mux)
	defer close()

	c, _ := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      srv.URL,
		AdminBaseURL: srv.URL,
		ClientID:     "cid",
		ClientSecret: "secret",
		AppID:        "3",
	})
	_, err := c.SendMagicLink(context.Background(), "alice@example.com")
	if !errors.Is(err, socrate.ErrMagicLinkRateLimited) {
		t.Errorf("expected ErrMagicLinkRateLimited, got: %v", err)
	}
}

func TestGetServiceToken_ExchangesCredentials(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "svc-tok",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	})
	mux.HandleFunc("/api/admin/apps", func(w http.ResponseWriter, r *http.Request) {
		// Called with svc-tok
		json.NewEncoder(w).Encode(socrate.AppListResponse{
			Apps: []socrate.App{{ID: 5, ClientID: "cid"}},
		})
	})
	mux.HandleFunc("/api/apps/5/users/7", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(socrate.User{ID: 7, Email: "svc@x.com"})
	})
	srv, close := newTestServer(mux)
	defer close()

	// AdminBaseURL = BaseURL so the test server handles all routes.
	c, _ := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      srv.URL,
		AdminBaseURL: srv.URL,
		ClientID:     "cid",
		ClientSecret: "secret",
	})
	u, err := c.GetUserAsService(context.Background(), "7")
	if err != nil {
		t.Fatalf("GetUserAsService: %v", err)
	}
	if u == nil || u.Email != "svc@x.com" {
		t.Errorf("unexpected user: %+v", u)
	}
}
