# Changelog

All notable changes to backendkit are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.12.0] - 2026-09-03

Shared-gateway hardening from the Socrate suite pass-3 audit
(`CR-socrate-suite-security-pass3.md`, `go-oauth2` repo). Additive except
for one behaviour change called out below.

> **Behaviour change (P3-12):** `Gateway.ProxyWithSession` no longer deletes
> the session on *every* refresh error. Only a refresh the authorization
> server rejects (`*socrate.OAuthError` with `invalid_grant`,
> `invalid_client`, `unauthorized_client` or `invalid_scope`) tears the
> session down with 401; a transport error, timeout or 5xx now answers
> **502** and keeps the session. Consumers with their own `EnsureFresh`
> call sites (e.g. `/bff/elevate`) should switch to `IsFatalRefreshError`
> for the same decision.

### Fixed

- **bff: refreshed tokens are written through to the `SessionStore`
  (P3-10).** `ProxyWithSession` mutated the in-memory `*Session` after a
  refresh and after `Touch` but never called `Store.Put`, which is invisible
  with `MemoryStore` (it hands out the live pointer) and fatal for a durable
  store that rehydrates a fresh `Session` per `Get`: the rotated refresh
  token was lost, the next request re-used the spent one and the session died
  at its first access-token expiry; idle-expiry never slid on real traffic.
  `EnsureFresh` now `Put`s inside the coalesced refresh (written once), and
  `ProxyWithSession` persists `Touch` at most once per `TouchInterval`
  (default 1 min; negative = every request). New `Session.LastSeen()`.

- **bff: the coalesced refresh no longer runs under the first caller's
  request context (P3-11).** Binding the shared refresh to whichever request
  arrived first meant a browser aborting that one request (tab close,
  navigation, `EventSource` teardown) failed the refresh for every coalesced
  waiter and logged all of them out. The refresh now runs under
  `context.WithoutCancel(ctx)` bounded by `RefreshTimeout` (default 10s);
  context values (tracing) are preserved.

### Added

- **socrate: typed `*OAuthError` from the token endpoint** (`StatusCode`,
  RFC 6749 `Code`, `Description`), returned by `ExchangeCode` /
  `RefreshToken` instead of an opaque string. Message text is unchanged.
- **bff: `IsFatalRefreshError(err)`** — the single decision point for
  "session is dead" vs "token endpoint is unreachable".
- **bff: `LoginBinding`** (P3-15) — issues a nonce in a short-lived
  HttpOnly, SameSite=Lax (`__Host-` when Secure) cookie at `/login` and
  requires it back at `/callback`, so only the browser that started a login
  can finish it. Closes the login-CSRF / silent account-swap both consoles
  currently have (state was validated server-side only).
- **bff: `Session.String()` / `GoString()`** redact tokens and the CSRF
  secret so `%v`/`%+v`/`%#v` cannot leak them into logs (P3-14).

### Security

- **bff: `NewSingleHostProxy` strips client-supplied IP-attribution headers**
  (`X-Real-IP`, `True-Client-IP`, `Forwarded`) in its `Director` (P3-16), so a
  browser cannot choose the address the upstream rate-limits, blocks or
  audits it as. `X-Forwarded-For` is left to the edge proxy, which replaces
  client-supplied values for untrusted peers. Consumers that wrap `Director`
  keep the behaviour by calling the original first (as both consoles do).
- **socrate: query-string values are now `url.Values`-encoded** in
  `GetGeoAnalytics`, `GetTokenStats` and `StreamSecurityEvents` (P2-10); a
  caller-supplied `period` of `24h&period=9999d` could previously inject or
  override parameters, and a `#` silently truncated the query.

- **Build with a patched Go toolchain (`go1.26.6`) and `golang.org/x/text`
  `v0.39.0`.** Clears the `govulncheck` findings that appeared since the last
  release: GO-2026-6218 (`net/url`), GO-2026-6090 / GO-2026-5856
  (`crypto/tls`), GO-2026-5972 (`encoding/asn1`), GO-2026-5026 (`net/http`
  idna) and GO-2026-5970 (`x/text`). No library code changed. As before, the
  `go` directive stays at `1.25.0`; the `toolchain` directive applies only
  when backendkit is the main module, so consumers on Go 1.25 are unaffected.

### Notes

- `Gateway` embeds a `singleflight.Group` since 1.11.0 and must be used by
  pointer and never copied (`go vet` copylocks reports it); now documented
  (P3-13).

## [1.11.1] - 2026-07-03

### Fixed

- **bff: `EnsureFresh` no longer returns a stale token from inside the
  proactive-refresh window.** The singleflight coalescing added in 1.11.0
  for P2-8 re-checked token validity inside the coalesced call with a leeway
  of `0` instead of `RefreshLeeway`, so a token that was inside the 30s
  proactive-refresh window but not yet actually expired was handed back
  unrefreshed. The inner check now uses the same `RefreshLeeway` as the
  outer check, matching the documented "refreshed if within `RefreshLeeway`
  of expiry" behaviour. Regression introduced in 1.11.0; no action needed
  beyond upgrading past it.

## [1.11.0] - 2026-07-03

### Security

- **bff: reject an empty stored CSRF token as a match.** `Session.MatchCSRF`
  called `ConstantTimeCompare` directly, so a session that somehow lost its
  CSRF value (`csrf == ""`) matched an empty request token, silently
  disabling CSRF protection for that session. `MatchCSRF` now always returns
  `false` when the stored value is empty. Addresses **P2-6**
  (`CR-socrate-suite-security-pass2.md`, upstream `go-oauth2` repo).

- **bff: `Gateway`'s zero value is now fail-closed.** `Gateway.AuthEnabled`
  defaulted to `false`, so a bare `&Gateway{...}` struct literal — no field
  set — was a fully-open pass-through, contradicting this package's
  documented "fail-closed by default" behaviour. The field is renamed and
  inverted to **`DisableAuth`**, so the zero value now means "auth enforced."
  Addresses **P2-7** (`CR-socrate-suite-security-pass2.md`).

- **bff: coalesce concurrent token refreshes per session.** Concurrent
  `EnsureFresh` calls near token expiry could each independently spend the
  same single-use rotating refresh token; only the first succeeded and the
  rest tore down the session. `EnsureFresh` now coalesces concurrent calls
  per session ID via `singleflight.Group` (mirroring the `jwtauth` H-1 JWKS
  fix), with every waiter re-checking token validity before spending a
  refresh. Addresses **P2-8** (`CR-socrate-suite-security-pass2.md`).

### Migration

**Breaking:** `Gateway.AuthEnabled` no longer exists — it is renamed and
inverted to `Gateway.DisableAuth`. Any caller that set `AuthEnabled: true`
in a struct literal must delete that line (the new zero-value default
already means the same thing); a caller that never set the field is
unaffected in behaviour but must still update to compile against this
version. `AllowPassthrough`, `CSRFHeader`, `RefreshLeeway` and `Now` are
unchanged.

```go
// before
gw := &bff.Gateway{Store: store, Cookie: cookie, Refresher: r, AuthEnabled: true}

// after
gw := &bff.Gateway{Store: store, Cookie: cookie, Refresher: r}
```

## [1.10.0] - 2026-07-02

### Added

- **`bff` package: shared Backend-for-Frontend runtime.** Consolidates the
  session/cookie/CSRF/PKCE/proxy core that the oauth2-admin and
  oauth2-monitoring consoles previously each hand-rolled: a race-safe
  `Session`/`SessionStore` (per-session mutex around the pointer returned by
  the in-memory store), a **fail-closed** `Gateway.ProxyWithSession` (no valid
  session ⇒ 401; never passes a request or client-supplied `Authorization`
  header through unless `AllowPassthrough` is explicitly set), double-submit
  CSRF enforcement on mutating methods, `SanitizeReturnTo` (rejects backslash
  and control-character open-redirect vectors), S256-only PKCE, and `__Host-`
  cookie helpers. Token calls delegate to `socrate.Client` via a
  `TokenRefresher` interface rather than being re-implemented. Both consoles
  migrate onto this package to stop carrying duplicated security-critical
  code.

### Security

- **jwtauth: guard the JWKS refetch against unauthenticated DoS.** A token's
  `kid` is attacker-controlled and checked before signature verification, so an
  unknown `kid` previously forced one synchronous outbound JWKS fetch **per
  request**. Refetches are now (1) coalesced with `golang.org/x/sync/singleflight`
  so N concurrent misses trigger a single fetch, (2) rate-limited by a
  `minRefetchInterval` cooldown (default 15s; `WithMinRefetchInterval`) so a miss
  inside the window returns key-not-found without a network call, and (3) backed
  by a short negative cache (default 30s; `WithNegativeCacheTTL`) for recently-seen
  unknown kids. A legitimately rotated key still resolves: the first miss after the
  cooldown triggers exactly one refetch. Addresses **H-1** (`SECURITY-AUDIT.md`).

- **jwtauth: require `exp` and add clock-skew leeway.** The parser now sets
  `jwt.WithExpirationRequired()`, so a token minted without an `exp` claim (which
  would otherwise never expire) is rejected, plus `jwt.WithLeeway` (default 60s;
  `WithLeeway`) for time-based claim validation. Addresses **M-2**
  (`SECURITY-AUDIT.md`).

- **socrate: complete path-segment escaping (corrects the F-7 ledger).** v1.9.0
  escaped only `client.go`; the remaining admin/monitoring/alerts/reports methods
  still concatenated raw caller-supplied path segments. `url.PathEscape` is now
  applied to every caller-supplied segment across `admin.go`, `monitoring.go`,
  `alerts.go` and `reports.go` (user/app/superadmin/blocked-ip/ip-reputation/log/
  alert-rule/report IDs). Internal server-resolved values (e.g. the app ID) are
  intentionally left unescaped, as in `client.go`. Addresses **M-1** and corrects
  the previously overstated **F-7** "Fixed" claim (`SECURITY-AUDIT.md`).

## [1.9.0] - 2026-06-20

### Security

- **jwtauth: warn when issuer validation is disabled.** `jwtauth.New` now logs a
  warning at construction when the issuer is empty, so a service running without
  `iss` enforcement is visible at startup instead of silently fail-open. No change
  to token validation; making issuer mandatory remains a v2.0 default-flip.
  Addresses **F-5** (`SECURITY-AUDIT.md`).
  ([#30](https://github.com/ovander/backendkit/issues/30))

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
