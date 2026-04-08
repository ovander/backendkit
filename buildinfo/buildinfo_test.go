package buildinfo_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/ovander/backendkit/buildinfo"
)

func TestGet_Defaults(t *testing.T) {
	// Package-level vars are their zero/default values in tests.
	info := buildinfo.Get()

	if info.Version != "dev" {
		t.Errorf("Version: got %q, want %q", info.Version, "dev")
	}
	if info.GoVersion != runtime.Version() {
		t.Errorf("GoVersion: got %q, want %q", info.GoVersion, runtime.Version())
	}
}

func TestGet_InjectedValues(t *testing.T) {
	// Simulate ldflags injection by setting package vars directly.
	orig := buildinfo.Version
	t.Cleanup(func() { buildinfo.Version = orig })

	buildinfo.Version = "v1.2.3"
	buildinfo.BuildTime = "2026-04-07T11:00:00Z"
	buildinfo.GitCommit = "abc1234"
	t.Cleanup(func() {
		buildinfo.BuildTime = ""
		buildinfo.GitCommit = ""
	})

	info := buildinfo.Get()
	if info.Version != "v1.2.3" {
		t.Errorf("Version: got %q, want %q", info.Version, "v1.2.3")
	}
	if info.BuildTime != "2026-04-07T11:00:00Z" {
		t.Errorf("BuildTime: got %q, want %q", info.BuildTime, "2026-04-07T11:00:00Z")
	}
	if info.GitCommit != "abc1234" {
		t.Errorf("GitCommit: got %q, want %q", info.GitCommit, "abc1234")
	}
}

func TestHandler_ResponseShape(t *testing.T) {
	buildinfo.Version = "v2.0.0"
	buildinfo.BuildTime = "2026-04-07T12:00:00Z"
	buildinfo.GitCommit = "deadbeef"
	t.Cleanup(func() {
		buildinfo.Version = "dev"
		buildinfo.BuildTime = ""
		buildinfo.GitCommit = ""
	})

	h := buildinfo.Handler()
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()

	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: got %q, want application/json", ct)
	}

	var got buildinfo.Info
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if got.Version != "v2.0.0" {
		t.Errorf("body.version: got %q, want %q", got.Version, "v2.0.0")
	}
	if got.BuildTime != "2026-04-07T12:00:00Z" {
		t.Errorf("body.buildTime: got %q, want %q", got.BuildTime, "2026-04-07T12:00:00Z")
	}
	if got.GitCommit != "deadbeef" {
		t.Errorf("body.gitCommit: got %q, want %q", got.GitCommit, "deadbeef")
	}
	if got.GoVersion == "" {
		t.Error("body.goVersion should not be empty")
	}
}

func TestHandler_EmptyBuildTimeOmitted(t *testing.T) {
	// buildTime and gitCommit default to "" → should be omitted from JSON (omitempty).
	buildinfo.Version = "dev"
	buildinfo.BuildTime = ""
	buildinfo.GitCommit = ""

	h := buildinfo.Handler()
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["buildTime"]; ok {
		t.Error("buildTime should be omitted when empty")
	}
	if _, ok := raw["gitCommit"]; ok {
		t.Error("gitCommit should be omitted when empty")
	}
}

func TestHandler_BodyReused(t *testing.T) {
	// Same handler instance must return identical bodies for each call.
	h := buildinfo.Handler()

	first := httptest.NewRecorder()
	h(first, httptest.NewRequest(http.MethodGet, "/version", nil))

	second := httptest.NewRecorder()
	h(second, httptest.NewRequest(http.MethodGet, "/version", nil))

	if first.Body.String() != second.Body.String() {
		t.Error("handler must return identical bodies across calls")
	}
}
