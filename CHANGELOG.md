# Changelog

All notable changes to backendkit are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Build with a patched Go toolchain (`go1.26.4`).** Added a `toolchain go1.26.4`
  directive to `go.mod` and bumped CI to Go 1.26.4, clearing 11 Go standard-library
  vulnerabilities reported by `govulncheck` (GO-2026-4599 … GO-2026-5039 in
  `crypto/x509`, `crypto/tls`, `net`, `net/http`, `net/textproto`, `net/url`),
  reachable through the HTTP/TLS client paths in `aigateway` and `socrate`. No
  library code changed; these were stdlib issues fixed by the toolchain upgrade.
  The `go` directive stays at `1.25.0`, so consumers on Go 1.25 are unaffected (the
  `toolchain` directive applies only when backendkit is the main module).
  ([#10](https://github.com/ovander/backendkit/issues/10))

### Added

- **jwtauth: opt-in JWT audience (`aud`) validation.** New `jwtauth.Option`
  functional-option type and `jwtauth.WithAudience(expectedAudience string)`.
  When supplied, a token is accepted only if its `aud` claim contains the
  expected audience (typically the service's OAuth `client_id`), closing the
  cross-app token-replay exposure where one Socrate-issued token was valid at
  every service sharing the same issuer and JWKS.
  Resolves **F-1 / INV-2** (`SECURITY-AUDIT.md`, `SECURITY-ARCHITECTURE.md`).
  ([#6](https://github.com/ovander/backendkit/issues/6))

### Migration

This change is **backward compatible**. `jwtauth.New` gained a trailing variadic
`opts ...Option` parameter, so existing three-argument calls compile and behave
exactly as before — when no `WithAudience` option is passed, the `aud` claim is
not checked.

To adopt audience validation (recommended for any service sharing a Socrate
issuer with other apps):

```go
// before
auth := jwtauth.New(jwksURL, issuer, logger)

// after
auth := jwtauth.New(jwksURL, issuer, logger,
    jwtauth.WithAudience("my-app-client-id"))
```

Note: once an expected audience is configured, tokens **without** an `aud` claim
are rejected. Confirm your Socrate server populates `aud` before enabling it in
production. Making audience validation required-by-default is deferred to a future
major (v2.0) and tracked separately.

### Notes

- `govulncheck` is part of the required quality gates but could not be executed in
  the CI sandbox for this change because `https://vuln.go.dev` is blocked by the
  environment's network policy. All other gates (`go fmt`, `go vet`,
  `golangci-lint`, `go test`, `go test -race`) pass.
