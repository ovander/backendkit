package httpware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/httpware"
)

func TestRequireTenant_WithTenant_Allows(t *testing.T) {
	called := false
	h := httpware.RequireTenant(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(ctxutil.WithTenantID(r.Context(), uuid.New()))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !called {
		t.Fatal("next handler was not called for a request carrying a tenant")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRequireTenant_MissingTenant_Returns401(t *testing.T) {
	called := false
	h := httpware.RequireTenant(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil) // no tenant in context → uuid.Nil
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if called {
		t.Error("next handler must not run when the tenant is absent (fail-closed)")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json (apierror envelope)", ct)
	}
}
