package apierror_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/backendkit/apierror"
)

func TestWriteProblem_4xx(t *testing.T) {
	w := httptest.NewRecorder()
	apierror.ValidationError("bad amount", map[string]string{"amount": "must be positive"}).WithKey("errors.amount").WriteProblem(w)

	if w.Code != http.StatusUnprocessableEntity || w.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("status %d, content type %q", w.Code, w.Header().Get("Content-Type"))
	}
	var p map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"type": "about:blank", "title": "Unprocessable Entity", "status": float64(422),
		"detail": "bad amount", "code": "validation_error", "key": "errors.amount"}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, want %v", k, p[k], v)
		}
	}
	if d, ok := p["details"].(map[string]any); !ok || d["amount"] != "must be positive" {
		t.Errorf("details = %v", p["details"])
	}
}

// A 5xx never carries the dev-facing message or details, as with WriteJSON.
func TestWriteProblem_5xxHidesInternals(t *testing.T) {
	w := httptest.NewRecorder()
	apierror.Internal("pq: connection refused to 10.0.0.5").WithDetails("stack").WriteProblem(w)
	var p map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &p)
	if w.Code != 500 || p["detail"] != nil || p["details"] != nil || p["title"] != "Internal Server Error" || p["code"] != "internal_error" {
		t.Errorf("5xx problem = %d %s", w.Code, w.Body.String())
	}
}

func TestErrorWriters(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	direct, viaWriter := httptest.NewRecorder(), httptest.NewRecorder()
	apierror.Unauthorized("nope").WriteJSON(direct)
	apierror.JSONWriter(viaWriter, r, apierror.Unauthorized("nope"))
	if direct.Body.String() != viaWriter.Body.String() || viaWriter.Header().Get("Content-Type") != "application/json" {
		t.Errorf("JSONWriter differs from WriteJSON: %q vs %q", viaWriter.Body.String(), direct.Body.String())
	}
	pw := httptest.NewRecorder()
	apierror.ProblemWriter(pw, r, apierror.Unauthorized("nope"))
	if pw.Header().Get("Content-Type") != "application/problem+json" || pw.Code != 401 {
		t.Errorf("ProblemWriter: %d %q", pw.Code, pw.Header().Get("Content-Type"))
	}
}
