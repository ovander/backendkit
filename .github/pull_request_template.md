## What and why

<!-- What this changes and why. Link the issue if there is one ("Closes #…"). -->

## How it was tested

<!-- New or changed tests, and anything checked by hand. The same checks as CI: -->

- [ ] `go mod tidy && git diff --exit-code go.sum` leaves `go.sum` unchanged
- [ ] `go build ./...` passes
- [ ] `go vet ./...` passes
- [ ] `go test -race -count=1 -timeout=120s ./...` passes
- [ ] `golangci-lint run ./...` (v2.14.0) reports no issue
- [ ] `govulncheck ./...` reports no vulnerability
- [ ] A line is added under `## [Unreleased]` in `CHANGELOG.md`

## Compatibility

<!-- Delete what does not apply. Within v1: no removed or renamed exported symbol, no changed
     signature, no stricter default that breaks a working caller without an opt-in. -->

- Exported-API change: <!-- yes (list the new or changed symbols) / no -->
- Behaviour change for existing callers: <!-- e.g. a new opt-in option, a stricter check -->
- Breaking change: <!-- none, or why it needs a new major version (v2) -->
