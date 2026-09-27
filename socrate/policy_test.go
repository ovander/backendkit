package socrate_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/socrate"
)

// decideServer fakes Socrate's token and decide endpoints on one server.
func decideServer(t *testing.T, decide http.HandlerFunc) *socrate.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_secret") != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"svc-token","expires_in":3600,"token_type":"Bearer"}`))
	})
	mux.HandleFunc("/api/apps/3/service/policy/decide", decide)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := socrate.NewClient(socrate.ClientConfig{
		BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "billing", ClientSecret: "s3cret", AppID: "3",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDecide_SendsTheRequestAsTheApp(t *testing.T) {
	var got socrate.DecideRequest
	var auth, corr string
	c := decideServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth, corr = r.Header.Get("Authorization"), r.Header.Get("X-Correlation-ID")
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"allow":true,"rule":"r1","reason":"allowed_by_rule","obligations":["require_mfa"],"policy_version":7,"mode":"shadow"}`))
	})

	ctx := ctxutil.WithRequestID(t.Context(), "req-42")
	d, err := c.Decide(ctx, socrate.DecideRequest{
		Subject:  &socrate.PolicySubject{Token: "user-jwt"},
		Action:   "invoice.approve",
		Resource: socrate.PolicyResource{Type: "invoice", ID: "inv-1", Attributes: map[string]any{"amount": 10}},
		Context:  socrate.PolicyContext{IP: "192.0.2.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer svc-token" || corr != "req-42" {
		t.Fatalf("headers: Authorization=%q X-Correlation-ID=%q", auth, corr)
	}
	if got.Subject == nil || got.Subject.Token != "user-jwt" || got.Action != "invoice.approve" || got.Resource.ID != "inv-1" || got.Context.IP != "192.0.2.1" {
		t.Fatalf("server received %+v", got)
	}
	if !d.Allow || d.Rule != "r1" || d.PolicyVersion != 7 || d.Mode != socrate.PolicyModeShadow ||
		len(d.Obligations) != 1 || d.Obligations[0] != socrate.ObligationMFA {
		t.Fatalf("decision = %+v", d)
	}
}

func TestDecide_Unavailable_CarriesTheMode(t *testing.T) {
	c := decideServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"policy_unavailable","mode":"enforce"}`))
	})
	d, err := c.Decide(t.Context(), socrate.DecideRequest{Action: "a"})
	if !errors.Is(err, socrate.ErrPolicyUnavailable) || d == nil || d.Mode != socrate.PolicyModeEnforce {
		t.Fatalf("d=%+v err=%v", d, err)
	}
}

func TestDecide_RejectedRequest_IsAnError(t *testing.T) {
	c := decideServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"unknown subject"}`))
	})
	d, err := c.Decide(t.Context(), socrate.DecideRequest{Subject: &socrate.PolicySubject{UserID: 9}, Action: "a"})
	if err == nil || d != nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("d=%+v err=%v", d, err)
	}
}
