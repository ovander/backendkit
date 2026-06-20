package apierror_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovander/backendkit/apierror"
)

func TestConstructors(t *testing.T) {
	tests := []struct {
		name       string
		err        *apierror.AppError
		wantStatus int
		wantCode   string
	}{
		{"NotFound", apierror.NotFound("Plan", "abc"), http.StatusNotFound, "not_found"},
		{"BadRequest", apierror.BadRequest("bad"), http.StatusBadRequest, "bad_request"},
		{"Unauthorized", apierror.Unauthorized("no"), http.StatusUnauthorized, "unauthorized"},
		{"Forbidden", apierror.Forbidden("no"), http.StatusForbidden, "forbidden"},
		{"Conflict", apierror.Conflict("dup"), http.StatusConflict, "conflict"},
		{"TooManyRequests", apierror.TooManyRequests("slow down"), http.StatusTooManyRequests, "too_many_requests"},
		{"Internal", apierror.Internal("oops"), http.StatusInternalServerError, "internal_error"},
		{"BadGateway", apierror.BadGateway("upstream down"), http.StatusBadGateway, "bad_gateway"},
		{"ServiceUnavailable", apierror.ServiceUnavailable("down"), http.StatusServiceUnavailable, "service_unavailable"},
		{"ValidationError", apierror.ValidationError("invalid", nil), http.StatusUnprocessableEntity, "validation_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", tt.err.StatusCode, tt.wantStatus)
			}
			if tt.err.Code != tt.wantCode {
				t.Errorf("Code = %q, want %q", tt.err.Code, tt.wantCode)
			}
			if tt.err.Error() == "" {
				t.Error("Error() returned empty string")
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	apierror.NotFound("User", "123").WriteJSON(w)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		Error apierror.AppError `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Error.Code != "not_found" {
		t.Errorf("body.error.code = %q, want not_found", body.Error.Code)
	}
}

func TestWriteJSON_RedactsServerErrors(t *testing.T) {
	w := httptest.NewRecorder()
	apierror.Internal("db dsn: postgres://user:p4ssw0rd@host/db").
		WithDetails(map[string]string{"stack": "internal trace"}).
		WriteJSON(w)

	body := w.Body.String()
	if strings.Contains(body, "postgres://user:p4ssw0rd") {
		t.Errorf("server-error response leaked internal Message: %s", body)
	}
	if strings.Contains(body, "internal trace") {
		t.Errorf("server-error response leaked Details: %s", body)
	}

	var parsed struct {
		Error apierror.AppError `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Error.Code != "internal_error" {
		t.Errorf("code = %q, want internal_error", parsed.Error.Code)
	}
	if parsed.Error.Message != "Internal Server Error" {
		t.Errorf("message = %q, want generic status text", parsed.Error.Message)
	}
}

func TestWriteJSON_PreservesClientErrorMessage(t *testing.T) {
	w := httptest.NewRecorder()
	apierror.BadRequest("invalid store ID").WriteJSON(w)

	var parsed struct {
		Error apierror.AppError `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Error.Message != "invalid store ID" {
		t.Errorf("4xx message = %q, want it preserved", parsed.Error.Message)
	}
}

func TestValidationErrorDetails(t *testing.T) {
	details := map[string]string{"field": "required"}
	err := apierror.ValidationError("validation failed", details)
	if err.Details == nil {
		t.Error("Details should not be nil")
	}
}

func TestNew_DerivesCodeAndPreservesStatus(t *testing.T) {
	tests := []struct {
		status   int
		wantCode string
	}{
		{http.StatusBadRequest, "bad_request"},
		{http.StatusNotFound, "not_found"},
		{http.StatusTooManyRequests, "too_many_requests"},
		{http.StatusBadGateway, "bad_gateway"},
		{http.StatusInternalServerError, "internal_error"},
		{http.StatusTeapot, "error"}, // unmapped → generic fallback
	}
	for _, tt := range tests {
		err := apierror.New(tt.status, "boom")
		if err.StatusCode != tt.status {
			t.Errorf("status %d: StatusCode = %d, want %d", tt.status, err.StatusCode, tt.status)
		}
		if err.Code != tt.wantCode {
			t.Errorf("status %d: Code = %q, want %q", tt.status, err.Code, tt.wantCode)
		}
	}
}

func TestNew_MatchesConstructorEnvelope(t *testing.T) {
	// New(400, …) must serialise identically to BadRequest(…).
	gen := httptest.NewRecorder()
	apierror.New(http.StatusBadRequest, "bad").WriteJSON(gen)

	typed := httptest.NewRecorder()
	apierror.BadRequest("bad").WriteJSON(typed)

	if gen.Body.String() != typed.Body.String() {
		t.Errorf("New envelope %q != BadRequest envelope %q", gen.Body.String(), typed.Body.String())
	}
}

func TestWrite(t *testing.T) {
	w := httptest.NewRecorder()
	apierror.Write(w, http.StatusBadGateway, "upstream timed out")

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
	var body struct {
		Error apierror.AppError `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Error.Code != "bad_gateway" {
		t.Errorf("body.error.code = %q, want bad_gateway", body.Error.Code)
	}
}
