package apierror_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		{"Internal", apierror.Internal("oops"), http.StatusInternalServerError, "internal_error"},
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

func TestValidationErrorDetails(t *testing.T) {
	details := map[string]string{"field": "required"}
	err := apierror.ValidationError("validation failed", details)
	if err.Details == nil {
		t.Error("Details should not be nil")
	}
}
