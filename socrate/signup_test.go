package socrate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/backendkit/socrate"
)

func signupServer(t *testing.T, status int, reply string) (*socrate.Client, *map[string]string, *http.Header) {
	t.Helper()
	var body map[string]string
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/auth/signup" {
			http.NotFound(w, r)
			return
		}
		hdr = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	c, err := socrate.NewClient(socrate.ClientConfig{BaseURL: srv.URL, AdminBaseURL: srv.URL, ClientID: "gpwa"})
	if err != nil {
		t.Fatal(err)
	}
	return c, &body, &hdr
}

func TestSignup_CreatesTheAccountForThisApp(t *testing.T) {
	c, body, hdr := signupServer(t, http.StatusCreated, `{"user_id":51,"message":"Please check your email to verify your account"}`)
	ctx := socrate.WithClientAttribution(context.Background(), socrate.ClientAttribution{IP: "198.51.100.7", UserAgent: "Firefox"})

	res, err := c.Signup(ctx, socrate.SignupRequest{Name: "Ada", Email: "ada@example.test", Password: "correct horse battery"})
	if err != nil || res.UserID != 51 {
		t.Fatalf("Signup = %+v, %v", res, err)
	}
	want := map[string]string{"name": "Ada", "email": "ada@example.test", "password": "correct horse battery", "client_id": "gpwa"}
	for k, v := range want {
		if (*body)[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, (*body)[k], v)
		}
	}
	// Sign-ups are rate-limited per client address: the browser's is sent.
	if got := hdr.Get("X-Forwarded-For"); got != "198.51.100.7" {
		t.Errorf("X-Forwarded-For = %q, want the attributed browser address", got)
	}
}

func TestSignup_ExistingEmailIsErrUserAlreadyExists(t *testing.T) {
	c, _, _ := signupServer(t, http.StatusBadRequest, `{"error":"email already exists"}`)
	if _, err := c.Signup(context.Background(), socrate.SignupRequest{Name: "A", Email: "a@x.test", Password: "p"}); !errors.Is(err, socrate.ErrUserAlreadyExists) {
		t.Fatalf("err = %v, want ErrUserAlreadyExists", err)
	}
}

func TestSignup_PolicyRefusalIsASignupError(t *testing.T) {
	c, _, _ := signupServer(t, http.StatusBadRequest, `{"error":"password must be at least 12 characters"}`)
	_, err := c.Signup(context.Background(), socrate.SignupRequest{Name: "A", Email: "a@x.test", Password: "short"})
	var se *socrate.SignupError
	if !errors.As(err, &se) || se.Message != "password must be at least 12 characters" {
		t.Fatalf("err = %v, want a SignupError with Socrate's message", err)
	}
}

func TestSignup_OtherStatusIsAnError(t *testing.T) {
	c, _, _ := signupServer(t, http.StatusTooManyRequests, `{"error":"too many requests"}`)
	_, err := c.Signup(context.Background(), socrate.SignupRequest{Name: "A", Email: "a@x.test", Password: "p"})
	var se *socrate.SignupError
	if err == nil || errors.As(err, &se) || errors.Is(err, socrate.ErrUserAlreadyExists) {
		t.Fatalf("err = %v, want a plain error for 429", err)
	}
}
