# CLAUDE.md — backendkit

Standing instructions for Claude Code in this repository. Read this file and `CONTRIBUTING.md`
before any change. The Socrate identity provider lives in `ovander/go-oauth2`; the admin and
monitoring consoles (`ovander/oauth2-admin`, `ovander/oauth2-monitoring`) and applications such
as `ovander/ascenda-backend` import this library, so an API change reaches all of them.

## Project in one paragraph

backendkit is the shared Go library of the Socrate suite, a single module
(`github.com/ovander/backendkit`) of small packages: `jwtauth` validates Socrate RS256 access
tokens against the JWKS; `bff` is the Backend-for-Frontend runtime (server-side sessions,
cookies, CSRF, PKCE, the fail-closed session→bearer proxy); `socrate` is the client for the
Socrate OAuth and admin APIs; `pep` enforces Socrate's central policy decisions; `httpware`,
`apierror`, `ctxutil`, `tiering`, `pagination`, `gormlogger` and `buildinfo` are service
plumbing; `aigateway`, `ailang` and `ainarration` wrap AI providers.

## Sources of truth, in order

1. The code and its doc comments (`go doc ./<package>`). Read them before proposing changes; do
   not describe code you have not opened.
2. `README.md` (package reference) and `docs/CLIENT-INTEGRATION.md` (end-to-end integration with
   Socrate).
3. `CHANGELOG.md` for what changed and which review findings (`F-n`, `INV-n`) a change closed.

## Hard rules

- **Compatibility.** No breaking change to an exported identifier within `v1`: no removed or
  renamed symbol, no changed signature, no stricter default that breaks a working caller without
  an opt-in. Additive changes only; a breaking one needs `v2`.
- **Coupling.** Packages may import `ctxutil` and `apierror`. The only other intra-module imports
  are `bff`→`socrate`, `pep`→`socrate` and `aigateway`→`ailang`. Do not add another.
- **Fail closed.** Authentication and authorisation paths reject on doubt: no valid session ⇒
  401, unknown key or algorithm ⇒ reject, policy decision unavailable in enforce mode (or before
  the mode is known) ⇒ 503. An opt-out is an explicit, documented option
  (`AllowPassthrough`, `FailOpenWhenModeUnknown`), never the zero value.
- **Documentation.** Every exported symbol has a doc comment starting with its name. A new
  package gets a package doc comment, a row in the README package tables and a section in the
  package reference.
- **Never weaken a gate** to get green: no skipped or deleted tests, no `//nolint` or `t.Skip`
  without a one-line reason, no required check removed.
- **Secrets** never enter the repository: no keys, tokens or real client secrets, including in
  tests and examples.
- **Scope.** One change per PR; do not widen a PR with unrelated fixes (open a separate one).

## Local gate (the same checks as CI)

```bash
go mod tidy && git diff --exit-code go.sum
go build ./...
go vet ./...
go test -race -count=1 -timeout=120s ./...
golangci-lint run ./...        # v2.14.0, built with Go 1.27.1
govulncheck ./...
```

CI also fails if the Go version it runs differs from the `toolchain` line in `go.mod`.

## Git workflow

- Branch from `main`: `feat/…`, `fix/…`, `chore/…`, `ci/…`, `docs/…`. Conventional Commits.
- Open a PR; never push to `main`, never force-push a shared branch, never merge with red CI.
  The owner merges.
- Each PR adds a line under `## [Unreleased]` in `CHANGELOG.md`, and says in its body what it
  changes, how it was tested, and any change to the exported API.

## Releases (the owner runs them)

A release is a tag `vX.Y.Z` on `main`, with the `[Unreleased]` changelog section moved under the
new version. The `Release` workflow publishes the GitHub release. Do not tag unless asked.
