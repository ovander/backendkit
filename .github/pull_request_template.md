## What and why

<!-- What this changes and why. Link the issue if there is one ("Closes #…"). -->

## How it was tested

<!-- New or changed tests, and anything checked by hand. -->

- [ ] `go build ./...`, `go vet ./...`, `go test -race -count=1 ./...` pass
- [ ] `golangci-lint run ./...` reports no issue
- [ ] `go mod tidy` leaves `go.sum` unchanged
- [ ] A line is added under `## [Unreleased]` in `CHANGELOG.md`

## Compatibility

<!-- Delete what does not apply. -->
- Exported API: <!-- new symbols / changed signatures / none -->
- Behaviour change for existing callers: <!-- e.g. a new default, a stricter check -->
- Breaking change: <!-- none, or why it needs a new major version -->
