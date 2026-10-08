package httpware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ovander/backendkit/apierror"
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

func TestRequireTenantWith_ProblemWriter(t *testing.T) {
	h := httpware.RequireTenantWith(apierror.ProblemWriter)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler reached without a tenant")
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 401 || w.Header().Get("Content-Type") != "application/problem+json" || !strings.Contains(w.Body.String(), `"detail":"tenant context required"`) {
		t.Errorf("got %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
}

// RequireTenant's body is unchanged, and RequireTenantWith(nil) is RequireTenant.
func TestRequireTenant_DefaultBodyUnchanged(t *testing.T) {
	want := httptest.NewRecorder()
	apierror.Unauthorized("tenant context required").WriteJSON(want)
	for name, mw := range map[string]func(http.Handler) http.Handler{
		"RequireTenant":          httpware.RequireTenant,
		"RequireTenantWith(nil)": httpware.RequireTenantWith(nil),
	} {
		w := httptest.NewRecorder()
		mw(http.NotFoundHandler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
		if w.Code != 401 || w.Body.String() != want.Body.String() {
			t.Errorf("%s: %d %q, want %q", name, w.Code, w.Body.String(), want.Body.String())
		}
	}
}
