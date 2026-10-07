# Contributing to backendkit

Thank you for your interest. backendkit is part of the Socrate suite: it is the shared Go library
that lets a service validate tokens from Socrate, the suite's OAuth 2.1 / OpenID Connect server
(`ovander/go-oauth2`, not public yet), run a Backend-for-Frontend, and enforce Socrate's central
policy decisions. Contributions are accepted under the project's licence,
[Apache-2.0](LICENSE).

## Development setup

Requirements: Go (the `toolchain` line in `go.mod` downloads the exact version, 1.27.1; the
`go` line, 1.26.0, is the floor importers need, and CI also tests on it). The
tests need no database and no network service.

```bash
git clone https://github.com/ovander/backendkit && cd backendkit
go mod download
go test ./...
```

## Design rules

- One package per directory, each with a package doc comment.
- Packages stay loosely coupled. Every package may use the shared primitives `ctxutil` and
  `apierror`. Beyond those, only deliberate layering is allowed: `bff` and `pep` build on
  `socrate`, and `aigateway` builds on `ailang`. Do not add a new cross-package import without
  discussing it first.
- Every exported symbol has a doc comment that begins with its name. Runnable examples go in
  `example_test.go`; they appear on pkg.go.dev.
- A new package gets a package doc comment, a row in the README package tables and a section in
  the README package reference.
- Security-relevant behaviour fails closed by default (for example, `bff.Gateway` answers 401
  without a valid session instead of passing the request through). An opt-out must be an
  explicit, documented option.
- No breaking change to an exported API within a major version. A breaking change needs a new
  major version and import path (`github.com/ovander/backendkit/v2`).

## Tests and checks

Run these before opening a pull request; CI runs the same and all of them are required:

```bash
go mod tidy && git diff --exit-code go.sum
go build ./...
go vet ./...
go test -race -count=1 -timeout=120s ./...
golangci-lint run ./...        # v2.14.0, built with Go 1.27.1
govulncheck ./...
```

- Tests sit next to the code (`*_test.go`), table-driven.
- Do not weaken a check to get green: no skipped or deleted tests, and no `//nolint` or `t.Skip`
  without a one-line reason.

## Pull requests

1. Branch from `main` (`feat/…`, `fix/…`, `chore/…`, `ci/…`, `docs/…`). Keep one change per
   pull request.
2. Commit with [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`,
   `chore:`, `docs:`, `ci:`, `test:`).
3. A bug fix comes with a test that fails without it.
4. Add a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md).
5. Open the PR with the template filled in, including any change to the exported API.
6. CI must be green. The maintainer reviews and merges.

## Releases

The maintainer tags releases `vX.Y.Z` on `main`. The `Release` workflow then publishes the GitHub
release with notes built from the commits since the previous tag. Consumers pin an explicit
version in their `go.mod`.

## Security

Please do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
