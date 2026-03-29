package httpware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/httpware"
)

func newRecoverLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(io_discard{})
	return logrus.NewEntry(l)
}

func TestRecover_CatchesPanic(t *testing.T) {
	handler := httpware.Recover(newRecoverLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went wrong")
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestRecover_PassthroughOnNoPanic(t *testing.T) {
	handler := httpware.Recover(newRecoverLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// io_discard is a discard io.Writer for silencing log output in tests.
type io_discard struct{}

func (io_discard) Write(p []byte) (int, error) { return len(p), nil }
