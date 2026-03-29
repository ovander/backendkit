package httpware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/httpware"
)

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	var captured string
	handler := httpware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = ctxutil.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if captured == "" {
		t.Error("expected a generated request ID in context")
	}
	if got := w.Header().Get("X-Request-ID"); got != captured {
		t.Errorf("response header X-Request-ID = %q, want %q", got, captured)
	}
}

func TestRequestID_PropagatesExistingHeader(t *testing.T) {
	const existing = "my-existing-id"
	var captured string
	handler := httpware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = ctxutil.GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Request-ID", existing)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if captured != existing {
		t.Errorf("context request ID = %q, want %q", captured, existing)
	}
	if got := w.Header().Get("X-Request-ID"); got != existing {
		t.Errorf("response header = %q, want %q", got, existing)
	}
}
