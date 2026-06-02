package socrate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ovander/backendkit/socrate"
)

// newExtClient builds a client whose OAuth and admin ports both point at the
// single httptest server, with AppID pre-set to skip app-ID resolution.
func newExtClient(url string) *socrate.Client {
	c, _ := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      url,
		AdminBaseURL: url,
		ClientID:     "my-client",
		ClientSecret: "secret",
		AppID:        "42",
	})
	return c
}

func TestGetProfile_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(socrate.FullProfile{ID: 7, Email: "u@x.com", Name: "U"})
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	p, err := newExtClient(srv.URL).GetProfile(ctx)
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if p == nil || p.Email != "u@x.com" {
		t.Errorf("unexpected profile: %+v", p)
	}
}

func TestGetProfile_NotFoundReturnsNil(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	p, err := newExtClient(srv.URL).GetProfile(ctx)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if p != nil {
		t.Errorf("expected nil profile, got %+v", p)
	}
}

func TestUpdateProfile_SendsBody(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		var body socrate.UpdateProfileRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Name == nil || *body.Name != "New" {
			t.Errorf("expected name New, got %+v", body.Name)
		}
		_ = json.NewEncoder(w).Encode(socrate.FullProfile{ID: 7, Name: "New"})
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	name := "New"
	p, err := newExtClient(srv.URL).UpdateProfile(ctx, socrate.UpdateProfileRequest{Name: &name})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if p.Name != "New" {
		t.Errorf("unexpected profile: %+v", p)
	}
}

func TestExchangeCode_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %s", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code_verifier") != "ver" {
			t.Errorf("code_verifier = %s", r.Form.Get("code_verifier"))
		}
		_ = json.NewEncoder(w).Encode(socrate.TokenSet{AccessToken: "at", RefreshToken: "rt", TokenType: "Bearer", ExpiresIn: 3600})
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ts, err := newExtClient(srv.URL).ExchangeCode(context.Background(), "code", "https://app/cb", "ver")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if ts.AccessToken != "at" || ts.RefreshToken != "rt" {
		t.Errorf("unexpected token set: %+v", ts)
	}
}

func TestExchangeCode_OAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "bad code"})
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	_, err := newExtClient(srv.URL).ExchangeCode(context.Background(), "code", "https://app/cb", "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyMagicLink_AlreadyUsed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/magic-link/verify", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	_, err := newExtClient(srv.URL).VerifyMagicLink(context.Background(), "tok")
	if !errors.Is(err, socrate.ErrMagicLinkAlreadyUsed) {
		t.Errorf("expected ErrMagicLinkAlreadyUsed, got %v", err)
	}
}

func TestVerifyMagicLink_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/magic-link/verify", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["client_id"] != "my-client" {
			t.Errorf("expected client_id my-client, got %s", body["client_id"])
		}
		_ = json.NewEncoder(w).Encode(socrate.LoginResult{AccessToken: "at", UserID: 9})
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	lr, err := newExtClient(srv.URL).VerifyMagicLink(context.Background(), "tok")
	if err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if lr.UserID != 9 {
		t.Errorf("unexpected login result: %+v", lr)
	}
}

func TestGetAppLogs_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/apps/42/logs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(socrate.AppActivityLogListResponse{
			Logs:       []socrate.AppActivityLog{{ID: 1, EventType: "login", Success: true}},
			TotalCount: 1,
		})
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	res, err := newExtClient(srv.URL).GetAppLogs(ctx, 1, 20)
	if err != nil {
		t.Fatalf("GetAppLogs: %v", err)
	}
	if len(res.Logs) != 1 || res.Logs[0].EventType != "login" {
		t.Errorf("unexpected logs: %+v", res)
	}
}

func TestListSessions_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/sessions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(socrate.SessionListResponse{
			Sessions: []socrate.Session{{ID: "s1", UserEmail: "a@b.com"}},
			Total:    1,
		})
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	res, err := newExtClient(srv.URL).ListSessions(ctx, 1, 20)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(res.Sessions) != 1 {
		t.Errorf("unexpected sessions: %+v", res)
	}
}

func TestAlertRulesLifecycle(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/alerts/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(socrate.AlertRulesListResponse{
				Rules: []socrate.AlertRule{{ID: 1, Name: "r1"}}, Total: 1,
			})
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(socrate.AlertRule{ID: 2, Name: "r2"})
		}
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	c := newExtClient(srv.URL)

	list, err := c.ListAlertRules(ctx)
	if err != nil || len(list.Rules) != 1 {
		t.Fatalf("ListAlertRules: %v, %+v", err, list)
	}
	created, err := c.CreateAlertRule(ctx, socrate.AlertRuleRequest{Name: "r2", EventType: "login_failed", Severity: "high", Actions: []string{"email"}})
	if err != nil || created.ID != 2 {
		t.Fatalf("CreateAlertRule: %v, %+v", err, created)
	}
}

func TestGetServerConfig_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/settings/config", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(socrate.ServerConfig{
			IssuerURL: "https://auth.example.com", AccessTokenTTL: 900,
			Features: socrate.ServerConfigFeatures{AuditLoggingEnabled: true},
		})
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	cfg, err := newExtClient(srv.URL).GetServerConfig(ctx)
	if err != nil {
		t.Fatalf("GetServerConfig: %v", err)
	}
	if cfg.AccessTokenTTL != 900 || !cfg.Features.AuditLoggingEnabled {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestGenerateAndDownloadReport(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/reports/security", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(socrate.Report{ReportID: "rpt_1", Status: "completed", Format: "json"})
	})
	mux.HandleFunc("/api/admin/reports/rpt_1/download", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	c := newExtClient(srv.URL)
	rep, err := c.GenerateSecurityReport(ctx, socrate.ReportRequest{
		Period: socrate.ReportPeriod{From: time.Now().Add(-24 * time.Hour), To: time.Now()},
	})
	if err != nil || rep.ReportID != "rpt_1" {
		t.Fatalf("GenerateSecurityReport: %v, %+v", err, rep)
	}
	data, err := c.DownloadReport(ctx, "rpt_1")
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("DownloadReport: %v, %s", err, data)
	}
}

func TestStreamSecurityEvents_ParsesFrames(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/admin/events/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: heartbeat\ndata: {\"status\":\"connected\"}\n\n"))
		_, _ = w.Write([]byte("event: security_event\ndata: {\"id\":5}\n\n"))
	})
	srv, closeFn := newTestServer(mux)
	defer closeFn()

	ctx := socrate.WithJWT(context.Background(), "tok")
	var names []string
	err := newExtClient(srv.URL).StreamSecurityEvents(ctx, socrate.StreamEventOptions{}, func(ev socrate.StreamEvent) error {
		names = append(names, ev.Name)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamSecurityEvents: %v", err)
	}
	if len(names) != 2 || names[0] != "heartbeat" || names[1] != "security_event" {
		t.Errorf("unexpected event names: %v", names)
	}
}
