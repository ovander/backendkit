package httpware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/backendkit/httpware"
)

func TestTimeout_CancelsAfterDuration(t *testing.T) {
	handler := httpware.Timeout(50 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			w.WriteHeader(http.StatusGatewayTimeout)
		case <-time.After(200 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		}
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusGatewayTimeout {
		t.Errorf("expected 504, got %d", w.Code)
	}
}

func TestTimeout_ReplacesExistingDeadline(t *testing.T) {
	// Outer timeout is 10 ms — inner (50 ms) should win because Timeout strips
	// the parent deadline via context.WithoutCancel.
	var ctxDeadlineOk bool

	inner := httpware.Timeout(200 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dl, ok := r.Context().Deadline()
		ctxDeadlineOk = ok && time.Until(dl) > 50*time.Millisecond
		w.WriteHeader(http.StatusOK)
	}))

	// Simulate an already-expired context as the parent.
	outerCtx, outerCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer outerCancel()
	time.Sleep(20 * time.Millisecond) // let the outer context expire

	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(outerCtx)
	w := httptest.NewRecorder()
	inner.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !ctxDeadlineOk {
		t.Error("inner context should have a fresh, non-expired deadline")
	}
}
