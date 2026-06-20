# Changelog

All notable changes to backendkit are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **apierror: redact internal message/details on 5xx responses.** `WriteJSON` now
  replaces the dev-facing `Message` with a generic status text and drops `Details`
  for any 5xx response, so internal detail (e.g. `apierror.Internal(err.Error())`)
  can no longer leak to clients. **4xx responses are unchanged.** The full error
  is still available server-side via `Error()` for logging; the struct doc was
  corrected. Addresses **F-17 / INV-9** (`SECURITY-AUDIT.md`,
  `SECURITY-ARCHITECTURE.md`).
  **Behaviour change:** 5xx response bodies no longer echo the supplied message.
  ([#28](https://github.com/ovander/backendkit/issues/28))

- **gormlogger: opt-in SQL redaction.** New `gormlogger.WithSQLRedaction()` option
  omits the SQL statement from log records (logs `sql: "[redacted]"`, keeping
  timing/row-count/caller). GORM hands the logger SQL with bound parameter values
  already interpolated — which can contain PII or secrets — so production loggers
  should enable it. Opt-in; default behaviour unchanged. Addresses **F-9 / INV-10**
  (`SECURITY-AUDIT.md`, `SECURITY-ARCHITECTURE.md`).
  ([#26](https://github.com/ovander/backendkit/issues/26))

- **jwtauth / socrate / aigateway: bound upstream response reads.** All reads of
  upstream HTTP bodies are now capped with `io.LimitReader` — JWKS at 1 MiB,
  Socrate and AI-provider responses at 10 MiB — so a compromised/MITM or oversized
  upstream cannot exhaust memory. `socrate.readBody` returns an explicit error when
  the cap is exceeded. Normal-size responses are unaffected. Addresses
  **F-8 / INV-12** (`SECURITY-AUDIT.md`, `SECURITY-ARCHITECTURE.md`).
  ([#24](https://github.com/ovander/backendkit/issues/24))

- **socrate: path-escape `userID` in request URLs.** `socrate.Client` now wraps the
  caller-supplied `userID` in `url.PathEscape` at every endpoint that interpolates
  it (`GetUser`, `UpdateUserRole`, `DeleteUser`, `ResendVerification`,
  `ForcePasswordReset`, `GetUserAsService`), so an ID containing `/`, `?`, `#`, or
  `..` can no longer rewrite the target route. Addresses **F-7 / INV-11**
  (`SECURITY-AUDIT.md`, `SECURITY-ARCHITECTURE.md`).
  ([#22](https://github.com/ovander/backendkit/issues/22))

## [1.8.0] - 2026-06-20

### Security

- **jwtauth: enforce a minimum RSA key size (2048 bits) for JWKS keys.**
  `parseRSAPublicKey` now rejects moduli below 2048 bits and validates the public
  exponent (odd, > 1, within `int` range) instead of silently truncating it, so a
  JWKS serving an undersized or malformed key is no longer trusted. Backward
  compatible for real deployments (Socrate/RS256 use ≥2048-bit keys). Addresses
  **F-10 / INV-13** (`SECURITY-AUDIT.md`, `SECURITY-ARCHITECTURE.md`).
  ([#18](https://github.com/ovander/backendkit/issues/18))

- **deps: bump `golang-jwt/jwt/v5` `v5.2.1` → `v5.2.2`.** Clears GO-2025-3553
  (excessive memory allocation during JWT header parsing) in backendkit's
  authentication trust-root dependency. The advisory is not on a called path
  (`govulncheck` already exited 0), so this is defense-in-depth; v5.2.2 is an
  API-compatible security patch, no source changes. ([#12](https://github.com/ovander/backendkit/issues/12))

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

- **jwtauth: opt-in token revocation hook.** New `jwtauth.RevocationChecker` type
  and `jwtauth.WithRevocationCheck(fn)` option. The supplied function runs on every
  request after signature/claim validation, receiving the request context and the
  parsed claims; returning an error rejects the request with 401. Use it to enforce
  `token_version` (logout / password-change / admin revocation) or a `jti` denylist
  — checks that local signature validation alone cannot. Opt-in: with none
  configured, a token stays valid until `exp` as before. Addresses **F-2 / INV-3**
  (`SECURITY-AUDIT.md`, `SECURITY-ARCHITECTURE.md`).
  ([#16](https://github.com/ovander/backendkit/issues/16))

- **httpware: `RequireTenant` middleware.** A plain
  `func(http.Handler) http.Handler` that rejects requests with no tenant ID in
  context (`ctxutil.GetTenantID == uuid.Nil`) with 401 Unauthorized, so
  tenant-scoped handlers can never run against the nil tenant. Opt-in; mount it
  after the auth middleware on tenant-scoped route groups. Rejections are logged
  through the request-scoped logger. Addresses **F-3 / INV-6**
  (`SECURITY-AUDIT.md`, `SECURITY-ARCHITECTURE.md`).
  ([#14](https://github.com/ovander/backendkit/issues/14))

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
