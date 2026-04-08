// Package buildinfo provides build-time metadata injection and a ready-to-use
// version HTTP handler for services built with BackendKit.
//
// # Usage
//
// Declare the package-level variables as ldflag targets in your Makefile:
//
//	VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
//	BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
//	GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
//
//	LDFLAGS := \
//	    -X github.com/ovander/backendkit/buildinfo.Version=$(VERSION) \
//	    -X github.com/ovander/backendkit/buildinfo.BuildTime=$(BUILD_TIME) \
//	    -X github.com/ovander/backendkit/buildinfo.GitCommit=$(GIT_COMMIT)
//
//	build:
//	    go build -ldflags "$(LDFLAGS)" ./cmd/server
//
// Then register the handler on any unauthenticated route:
//
//	import "github.com/ovander/backendkit/buildinfo"
//
//	r.Get("/api/v1/version", buildinfo.Handler())
package buildinfo

import (
	"encoding/json"
	"net/http"
	"runtime"
)

// Version, BuildTime and GitCommit are injected at link time via -ldflags.
// They fall back to safe defaults when the binary is built without them
// (e.g. go run ./cmd/server during development).
var (
	// Version is the application version string.
	// Typically set from `git describe --tags --always --dirty`.
	Version = "dev"

	// BuildTime is the RFC 3339 UTC timestamp of when the binary was built.
	// Example: "2026-04-07T11:00:00Z"
	BuildTime = ""

	// GitCommit is the short Git commit hash recorded at build time.
	// Example: "a1b2c3d"
	GitCommit = ""
)

// Info holds the build metadata for the running binary.
// All fields are safe to serialise as JSON and expose publicly.
type Info struct {
	Version   string `json:"version"`
	BuildTime string `json:"buildTime,omitempty"`
	GitCommit string `json:"gitCommit,omitempty"`
	GoVersion string `json:"goVersion"`
}

// Get returns the current build info populated from the package-level
// variables (set at link time) and runtime.Version().
func Get() Info {
	return Info{
		Version:   Version,
		BuildTime: BuildTime,
		GitCommit: GitCommit,
		GoVersion: runtime.Version(),
	}
}

// Handler returns an http.HandlerFunc that writes the build info as JSON with
// a 200 status. The response body is marshalled once at call time and reused
// for every request — the version never changes after startup.
//
// Register it on an unauthenticated route so monitoring tools and the
// frontend can read it without a token:
//
//	r.Get("/api/v1/version", buildinfo.Handler())
func Handler() http.HandlerFunc {
	body, err := json.Marshal(Get())
	if err != nil {
		// Info contains only plain strings — this path is unreachable in practice.
		panic("buildinfo: failed to marshal Info: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
