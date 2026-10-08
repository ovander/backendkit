package httpware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

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

func TestRequestID_ReplacesInvalidIDs(t *testing.T) {
	long := strings.Repeat("a", httpware.MaxRequestIDLength+1)
	for name, id := range map[string]string{
		"line break":    "abc\r\nX-Injected: 1",
		"space":         "abc def",
		"control":       "abc\x00",
		"non-ASCII":     "é-123",
		"slash":         "a/b",
		"quote":         `a"b`,
		"too long":      long,
		"json":          `{"a":1}`,
		"only spaces":   "   ",
		"html":          "<script>",
		"percent":       "a%0Ab",
		"semicolon":     "a;b",
		"comma":         "a,b",
		"equals":        "a=b",
		"tab":           "a\tb",
		"backslash":     `a\b`,
		"question mark": "a?b",
	} {
		t.Run(name, func(t *testing.T) {
			var captured string
			h := httpware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured = ctxutil.GetRequestID(r.Context())
			}))
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header["X-Request-Id"] = []string{id}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if captured == id || !httpware.ValidRequestID(captured) {
				t.Errorf("id %q kept or replaced by an invalid one (%q)", id, captured)
			}
			if _, err := uuid.Parse(captured); err != nil {
				t.Errorf("replacement %q is not a UUID", captured)
			}
			if got := w.Header().Get("X-Request-ID"); got != captured {
				t.Errorf("response header = %q, want the replacement %q", got, captured)
			}
		})
	}
}

func TestRequestID_KeepsValidIDs(t *testing.T) {
	for _, id := range []string{
		"6f1c2a4e-9b3d-4e8f-a1b2-c3d4e5f60718", // UUID
		"01J9Z3K7Q8R5T2V6W4X0Y1Z2A3",           // ULID
		"req_42.retry-1",
		"trace:span:1",
		strings.Repeat("a", httpware.MaxRequestIDLength),
	} {
		var captured string
		h := httpware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured = ctxutil.GetRequestID(r.Context())
		}))
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Request-ID", id)
		h.ServeHTTP(httptest.NewRecorder(), r)
		if captured != id {
			t.Errorf("valid id %q replaced by %q", id, captured)
		}
	}
}
