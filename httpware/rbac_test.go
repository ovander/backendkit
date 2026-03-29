package httpware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/httpware"
)

var testRoleMap = httpware.RoleMap{
	"viewer": {"read:resource"},
	"editor": {"read:resource", "write:resource"},
	"admin":  {"read:resource", "write:resource", "delete:resource"},
}

func rbacHandler(role string, perm httpware.Permission) http.Handler {
	logger := logrus.NewEntry(logrus.New())
	rb := httpware.NewRBAC(testRoleMap, logger)
	return rb.Require(perm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func requestWithRole(role string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	return r.WithContext(ctxutil.WithUserRole(r.Context(), role))
}

func TestRBAC_AllowsWhenPermissionGranted(t *testing.T) {
	h := rbacHandler("editor", "write:resource")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithRole("editor"))
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRBAC_DeniesWhenPermissionMissing(t *testing.T) {
	h := rbacHandler("viewer", "write:resource")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithRole("viewer"))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestRBAC_DeniesUnknownRole(t *testing.T) {
	h := rbacHandler("ghost", "read:resource")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithRole("ghost"))
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}
