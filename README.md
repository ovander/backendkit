# backendkit

[![Go Reference](https://pkg.go.dev/badge/github.com/ovander/backendkit.svg)](https://pkg.go.dev/github.com/ovander/backendkit)
[![CI](https://github.com/ovander/backendkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ovander/backendkit/actions/workflows/ci.yml)
[![Latest tag](https://img.shields.io/github/v/tag/ovander/backendkit?sort=semver&label=version)](https://github.com/ovander/backendkit/tags)
[![License: Apache-2.0](https://img.shields.io/github/license/ovander/backendkit)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/ovander/backendkit)](go.mod)

> The shared Go library for services and Backend-for-Frontends that sign users in with Socrate.

backendkit is a single Go module of small packages for teams building on Socrate, the suite's
OAuth 2.1 / OpenID Connect server (`ovander/go-oauth2`, not public yet). It validates Socrate
access tokens (`jwtauth`), runs a Backend-for-Frontend so a browser app never holds a token
(`bff`), enforces Socrate's central policy decisions in your handlers (`pep`), calls the Socrate
OAuth and admin APIs (`socrate`), and provides the service plumbing around them: middleware,
errors, context helpers, plan gating, pagination, build info and AI provider wrappers. It is for
Go developers writing an API or a BFF in the Socrate suite.

---

## Table of contents

- [Why backendkit](#why-backendkit)
- [Packages](#packages)
  - [Which package do I need?](#which-package-do-i-need)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Package reference](#package-reference) —
  [apierror](#apierror) · [ctxutil](#ctxutil) · [httpware](#httpware) ·
  [gormlogger](#gormlogger) · [socrate](#socrate) · [jwtauth](#jwtauth) · [bff](#bff) ·
  [pep](#pep) · [tiering](#tiering) · [aigateway](#aigateway) · [ailang](#ailang) ·
  [ainarration](#ainarration) · [pagination](#pagination) · [buildinfo](#buildinfo)
- [Environment variables](#environment-variables)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Used by](#used-by)
- [Versioning](#versioning)
- [Status](#status)

---

## Why backendkit

Every service that trusts Socrate has to solve the same problems: validate RS256 tokens against a
rotating JWKS, keep tokens out of the browser, ask the central policy decision point before an
action, carry the user's claims through the request, and return consistent errors. Solved once
per service, this code is copied and drifts, and security fixes land in one place but not the
others.

backendkit puts that foundation in one versioned dependency:

- **Token validation in one call.** `jwtauth.New(...)` validates RS256 tokens, caches the JWKS,
  and puts every Socrate claim in the request context.
- **No tokens in the browser.** `bff` is the runtime of a Backend-for-Frontend: server-side
  sessions, `__Host-` cookies, CSRF checks, PKCE, and a fail-closed session→bearer proxy with
  coalesced token refresh. The Socrate admin and monitoring consoles run on it.
- **Central policy, enforced locally.** `pep` asks Socrate's policy decision point about each
  action and follows the mode Socrate reports (`off`, `shadow`, `enforce`), so one switch in
  Socrate moves every application at once.
- **A typed Socrate client.** `socrate.Client` covers the token flows, user management, service
  accounts, magic links, security monitoring and policy decisions.
- **Service plumbing.** Request IDs, structured logrus logging, Prometheus RED metrics, rate
  limiting, plan gates backed by your database, and GORM slow-query logging.
- **Loosely coupled packages.** Import only what you need. Every package may use the shared
  `ctxutil` and `apierror` primitives; beyond those, the only intra-module imports are
  `bff` → `socrate`, `pep` → `socrate` and `aigateway` → `ailang`.

---

## Packages

| Package | Purpose |
|---------|---------|
| [`apierror`](#apierror) | Structured HTTP error types (`AppError`, constructor functions) |
| [`ctxutil`](#ctxutil) | Typed context keys for Socrate claims (tenant, user, role, plan, logger, request-id) |
| [`httpware`](#httpware) | Chi-compatible middlewares: RequestID, Logger, SecurityHeaders, BodyLimit, Recover, Timeout, RateLimiter, RequireTenant, RBAC, Metrics (Prometheus RED) |
| [`gormlogger`](#gormlogger) | GORM → logrus bridge with slow-query detection |
| [`jwtauth`](#jwtauth) | JWT RS256 validation middleware with JWKS cache and stale-key fallback |
| [`bff`](#bff) | Backend-for-Frontend runtime: server-side sessions, `__Host-` cookies, CSRF, PKCE, login binding and a fail-closed session→bearer proxy with coalesced token refresh |
| [`socrate`](#socrate) | Socrate API client: token flows, user CRUD, service-account token, magic links, invites, app and superadmin management, security monitoring, dashboard, audit logs, policy decisions |
| [`tiering`](#tiering) | Plan registry, tier gate middleware, feature policy model and service |
| [`pep`](#pep) | Policy enforcement point: asks Socrate's policy decision point about each action and honours the central `POLICY_MODE` (off / shadow / enforce) and obligations |
| [`aigateway`](#aigateway) | AI provider client (OpenAI and Claude; Ollama through `NewAIClient`), `ExtractJSON` / `ExtractJSONInto` |
| [`ailang`](#ailang) | Language guard for AI output: every response is in the requested locale (fr/en), with retry and translation fallback |
| [`ainarration`](#ainarration) | Generic LRU+TTL narration cache and `CacheKey` helper |
| [`pagination`](#pagination) | Query-param parsing and `PagedResponse` |
| [`buildinfo`](#buildinfo) | Build-time version metadata (`-ldflags`) and a `/version` HTTP handler |

`go get` pulls the whole module, but importing one package brings in only what it builds on: the
shared `ctxutil` and `apierror` primitives, plus `socrate` for the two packages that exist to talk
to Socrate (`bff`, `pep`) and `ailang` for `aigateway`.

### Which package do I need?

| I want to… | Use |
|------------|-----|
| Validate incoming Socrate JWTs and populate the request context | [`jwtauth`](#jwtauth) |
| Serve a browser SPA without ever giving it OAuth tokens (BFF) | [`bff`](#bff) + [`socrate`](#socrate) |
| Authorise actions with Socrate's central, declarative policy (RBAC + ABAC, object-level) | [`pep`](#pep) |
| Read the tenant / user / role / plan of the current request | [`ctxutil`](#ctxutil) |
| Add request IDs, structured logging, panic recovery, timeouts, body limits, security headers | [`httpware`](#httpware) |
| Rate-limit per tenant | [`httpware.RateLimiter`](#httpware) |
| Expose Prometheus RED metrics keyed by route pattern (same metric scheme as Socrate) | [`httpware.Metrics`](#httpware) + `httpware.MetricsHandler` |
| Guarantee a tenant on tenant-scoped routes | [`httpware.RequireTenant`](#httpware) |
| Gate routes by role/permission | [`httpware.RBAC`](#httpware) |
| Gate routes or features by commercial plan | [`tiering`](#tiering) |
| Return consistent JSON errors | [`apierror`](#apierror) |
| Call Socrate to manage users, apps, tokens, or security | [`socrate`](#socrate) |
| Call OpenAI or Claude through one interface | [`aigateway`](#aigateway) |
| Guarantee AI output is in the user's language | [`ailang`](#ailang) |
| Cache AI results to cut latency and cost | [`ainarration`](#ainarration) |
| Parse `?page`/`?per_page` and return paged lists | [`pagination`](#pagination) |
| Log GORM queries through logrus / flag slow queries | [`gormlogger`](#gormlogger) |
| Expose build/version info on a `/version` endpoint | [`buildinfo`](#buildinfo) |

---

## Requirements

- **Go 1.26.0 or later** to import the module (the `go` line in `go.mod`). The floor is the
  oldest supported Go release: a backendkit upgrade never forces a newer Go on its importers, and
  CI builds and tests on the floor itself. backendkit is developed with Go 1.27.1 (the
  `toolchain` line).
- **A Socrate server** for the packages that talk to it: `jwtauth`, `socrate`, `bff` and `pep`.
  They are written for Socrate's API and claims, not as a generic OAuth toolkit. The other
  packages, `ctxutil` included, are plain Go helpers and work without Socrate.
- **A database** only if you back `tiering.PolicyService` with one, through your own
  `tiering.PolicyRepository`.

---

## Installation

```bash
go get github.com/ovander/backendkit@v1.23.0
```

```go
// go.mod
module github.com/your-org/my-service

go 1.26.0

require github.com/ovander/backendkit v1.23.0
```

---

## Quick start

The smallest working setup: JWT validation and a single protected route.

```go
package main

import (
    "net/http"
    "os"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/sirupsen/logrus"

    "github.com/ovander/backendkit/httpware"
    "github.com/ovander/backendkit/jwtauth"
)

func main() {
    log := logrus.WithField("service", "my-service")

    auth := jwtauth.New(
        os.Getenv("SOCRATE_JWKS_URL"),
        os.Getenv("SOCRATE_ISSUER"),
        log,
    )

    r := chi.NewRouter()
    r.Use(httpware.RequestID)
    r.Use(httpware.Recover(log))
    r.Use(httpware.Timeout(30 * time.Second))
    r.Use(auth.Handler)

    r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("ok"))
    })

    http.ListenAndServe(":8080", r)
}
```

### Full middleware stack

The following wires the complete middleware stack, plan-based routing and enterprise-only admin
routes on a chi router. For a browser front end, put a [`bff`](#bff) in front of this API; to
authorise actions centrally, add [`pep`](#pep).

```go
package main

import (
    "os"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/sirupsen/logrus"

    "github.com/ovander/backendkit/httpware"
    "github.com/ovander/backendkit/jwtauth"
    "github.com/ovander/backendkit/tiering"
)

func main() {
    base := logrus.New()                          // *logrus.Logger — for httpware.Logger
    log := base.WithField("service", "my-service") // *logrus.Entry  — for everything else

    // 1. Auth middleware — validates RS256 JWT, injects claims into context.
    auth := jwtauth.New(
        os.Getenv("SOCRATE_JWKS_URL"),
        os.Getenv("SOCRATE_ISSUER"),
        log,
        jwtauth.WithAudience(os.Getenv("SOCRATE_CLIENT_ID")), // reject tokens minted for other apps
    )

    // 2. Per-tenant rate limiter — 20 rps sustained, burst of 40.
    rl := httpware.NewRateLimiter(20, 40)
    defer rl.Stop()

    // 3. Tier gate — uses the default freemium/pro/enterprise hierarchy.
    gate := tiering.NewGate(tiering.DefaultRegistry(), log, "/settings/billing")

    r := chi.NewRouter()

    // Global middleware (runs before auth).
    r.Use(httpware.RequestID)
    r.Use(httpware.Logger(base)) // takes *logrus.Logger, not *logrus.Entry
    r.Use(httpware.SecurityHeaders)
    r.Use(httpware.BodyLimit(4 * 1024 * 1024)) // 4 MB
    r.Use(httpware.Recover(log))
    r.Use(httpware.Timeout(30 * time.Second))

    // Auth + rate limit (after context is populated).
    r.Use(auth.Handler)
    r.Use(rl.Handler)

    // Public routes.
    r.Get("/healthz", healthHandler)

    // Pro-only routes.
    r.Group(func(r chi.Router) {
        r.Use(gate.Require(tiering.PlanPro))
        r.Post("/ai/narrate", narrateHandler)
    })

    // Enterprise-only routes.
    r.Group(func(r chi.Router) {
        r.Use(gate.Require(tiering.PlanEnterprise))
        r.Get("/admin/tenants", listTenantsHandler)
    })
}
```

The [client integration guide](docs/CLIENT-INTEGRATION.md) walks through a complete integration
with Socrate: middleware wiring, the `socrate.Client` auth modes, login flows for browser and
non-browser clients, the BFF, policy enforcement and error handling. Moving an existing
application onto Socrate? Start with [Moving an application onto Socrate](docs/MIGRATING-TO-SOCRATE.md):
the identifiers to ask for, the cut-over order and a symptom index.

---

## Architecture

A browser app reaches your API through a BFF; other clients send a bearer token directly. In the
API, the packages sit in three layers:

```
  Browser (SPA)                              Non-browser client or service
       │ opaque __Host- session cookie                  │
       ▼                                                │
┌───────────────────────────────────────┐               │
│ BFF  (bff + socrate)                  │               │
│ login: PKCE, state, LoginBinding      │               │
│ server-side session store             │               │
│ CSRF check on unsafe methods          │               │
│ ProxyWithSession: cookie → bearer     │               │
└───────────────────┬───────────────────┘               │
                    │ Authorization: Bearer <JWT>       │ Authorization: Bearer <JWT>
                    ▼                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Your API: httpware middleware stack (chi or net/http)               │
│ Metrics → RequestID → Logger → SecurityHeaders → Recover →          │
│ Timeout → jwtauth → RateLimiter                                     │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │ context carries: sub, role, app roles, plan,
                                   │ tenant, auth_time, amr, request id, logger
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Route handlers                                                      │
│ • httpware.RBAC, tiering.Gate       local role and plan gates       │
│ • pep.Enforcer                      Socrate policy decisions        │
│ • socrate.Client                    identity operations             │
│ • aigateway, ailang, ainarration    AI calls, language, cache       │
└──────────────────────────────────┬──────────────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Data layer: GORM + gormlogger, tiering.PolicyService                │
└─────────────────────────────────────────────────────────────────────┘
```

Each layer talks to Socrate through its own package:

- `jwtauth` fetches Socrate's JWKS to verify token signatures.
- `bff` exchanges codes and refreshes tokens at Socrate's token endpoint through `socrate.Client`.
- `pep` asks Socrate's policy decision point through `socrate.Client.Decide`.
- `socrate.Client` calls Socrate's OAuth and admin APIs for identity operations.

---

## Package reference

Each section shows the common use of one package. The complete API, with runnable examples, is on
[pkg.go.dev](https://pkg.go.dev/github.com/ovander/backendkit).

### apierror

Constructor functions for all common HTTP error shapes. Every constructor returns `*AppError`
which implements `error` and serialises itself as JSON when written to an `http.ResponseWriter`
via `WriteJSON`. The wire shape is wrapped in an `error` envelope:

```json
{"error": {"code": "not_found", "message": "user not found: 42"}}
```

```go
user, err := repo.GetByID(id)
if errors.Is(err, gorm.ErrRecordNotFound) {
    apierror.NotFound("user", id).WriteJSON(w)
    return
}
apierror.Internal("database error").WriteJSON(w)
```

> **5xx responses are redacted (since v1.9.0).** For server errors (status ≥ 500), `WriteJSON`
> replaces `message` with a generic status text and drops `details`, so internal detail (e.g.
> `apierror.Internal(err.Error())`) cannot leak to clients. The full message is still available
> server-side via `Error()` for logging, and 4xx responses are unchanged. Clients should key on
> `error.code` for 5xx.

**RFC 9457 problem details.** `WriteProblem` writes the same error as `application/problem+json`
(`type: about:blank`, `title` the status text, `status`, `detail` the message, plus `code`, `key`
and `details` as extension members; 5xx redacted the same way). The middleware that rejects
requests takes an `apierror.ErrorWriter`, so an API can answer in one shape throughout:
`jwtauth.WithErrorWriter(apierror.ProblemWriter)` and
`httpware.RequireTenantWith(apierror.ProblemWriter)`. Without them, the default envelope is
written as before.

Available constructors: `NotFound`, `BadRequest`, `Unauthorized`, `Forbidden`, `Conflict`,
`ValidationError`, `TooManyRequests`, `Internal`, `BadGateway`, `ServiceUnavailable`.

When the status is **dynamic** (e.g. proxying an upstream response) and the typed constructors
don't fit, `New(status, msg)` builds an `AppError` for any status — deriving the same machine code
the typed constructors use — and `Write(w, status, msg)` builds and writes it in one call:

```go
// Identical envelope to the typed constructors, with the caller's status preserved:
apierror.Write(w, resp.StatusCode, "upstream rejected the request")
```

Two fluent helpers refine an error before it is written:

```go
// WithKey attaches an i18n key the frontend can translate (added to the JSON as "key").
apierror.BadRequest("invalid store ID").WithKey("errors.invalidStoreId").WriteJSON(w)

// WithDetails attaches an arbitrary structured payload (serialised as "details").
apierror.ValidationError("validation failed", fieldErrors).WriteJSON(w)
```

Full API: [pkg.go.dev/…/apierror](https://pkg.go.dev/github.com/ovander/backendkit/apierror).

---

### ctxutil

Typed helpers for every Socrate JWT claim that `jwtauth` injects into the context. Every `Get*`
function returns a single value and is safe to call even when the value is absent — it returns
the zero value (`uuid.Nil`, `""`, `0`, or `nil`), except `GetUserPlan`, which defaults to
`"freemium"`, and `GetLogger`, which falls back to the standard logger.

```go
tenantID  := ctxutil.GetTenantID(ctx)    // uuid.UUID — uuid.Nil when absent
tenantStr := ctxutil.GetTenantIDStr(ctx) // string — "" when absent (handy for logging)
userID    := ctxutil.GetUserID(ctx)      // uuid.UUID — uuid.Nil when absent
sub       := ctxutil.GetUserSub(ctx)     // string — raw Socrate subject (e.g. "42")
role      := ctxutil.GetUserRole(ctx)    // string
plan      := ctxutil.GetUserPlan(ctx)    // string — defaults to "freemium"
email     := ctxutil.GetUserEmail(ctx)   // string (ID-token flows only)
name      := ctxutil.GetUserName(ctx)    // string (ID-token flows only)
requestID := ctxutil.GetRequestID(ctx)   // string
logger    := ctxutil.GetLogger(ctx)      // *logrus.Entry — falls back to standard logger
rawJWT    := ctxutil.GetRawJWT(ctx)      // string — bearer token for forwarding (also inside a RevocationChecker)

// Multi-app role claims (app_roles), the monotonic token_version and authentication facts:
roles    := ctxutil.GetAppRoles(ctx)            // map[string]string — clientID → role
role      = ctxutil.GetAppRole(ctx, "my-app-id") // role within a specific app, "" if none
ver      := ctxutil.GetTokenVersion(ctx)        // int — 0 when absent
authTime := ctxutil.GetAuthTime(ctx)            // int64 Unix seconds — 0 when absent
amr      := ctxutil.GetAMR(ctx)                 // []string, e.g. ["pwd", "mfa"] — nil when absent
aud      := ctxutil.GetAudiences(ctx)           // []string — the audiences the token was accepted for
```

> `GetTenantTier`/`WithTenantTier` are deprecated aliases for `GetUserPlan`/`WithUserPlan`; use
> the `*UserPlan` names in new code.

Full API: [pkg.go.dev/…/ctxutil](https://pkg.go.dev/github.com/ovander/backendkit/ctxutil).

---

### httpware

All middleware functions follow the standard `func(http.Handler) http.Handler` signature and work
with any `net/http`-based router.

| Middleware | Constructor |
|-----------|-------------|
| Request ID | `httpware.RequestID` — keeps a valid incoming `X-Request-ID` (≤ 128 chars of `A-Za-z0-9._:-`, see `ValidRequestID`), otherwise generates a UUID |
| Structured logger | `httpware.Logger(logger)` — takes a `*logrus.Logger` |
| Security headers | `httpware.SecurityHeaders` |
| Body size limit | `httpware.BodyLimit(maxBytes)` |
| Panic recovery | `httpware.Recover(entry)` — takes a `*logrus.Entry` |
| Per-route timeout | `httpware.Timeout(d)` |
| Per-tenant rate limit | `httpware.NewRateLimiter(rps, burst)` — mount `rl.Handler`, call `rl.Stop()` on shutdown |
| Require a tenant | `httpware.RequireTenant` — 401 when no tenant is in context |
| Role-based access | `httpware.NewRBAC(roleMap, entry)` |
| Prometheus RED metrics | `httpware.Metrics(service)` — mount first; `httpware.MetricsHandler()` serves the exposition |

> Note the logger types differ: `Logger` takes the base `*logrus.Logger` (it derives a
> request-scoped `*logrus.Entry` per request), while `Recover` and `NewRBAC` take a pre-enriched
> `*logrus.Entry`.

**RBAC — defining permissions:**

```go
const (
    PermReadReport  httpware.Permission = "read:report"
    PermWriteReport httpware.Permission = "write:report"
)

rbac := httpware.NewRBAC(httpware.RoleMap{
    "viewer": {PermReadReport},
    "editor": {PermReadReport, PermWriteReport},
}, logger)

r.With(rbac.Require(PermWriteReport)).Post("/reports", createReport)
```

**Nested timeouts:** `httpware.Timeout` strips the existing deadline before applying the new one,
so inner routes can safely override the global default:

```go
r.Use(httpware.Timeout(10 * time.Second)) // global default

r.Group(func(r chi.Router) {
    r.Use(httpware.Timeout(120 * time.Second)) // replaces the 10 s deadline
    r.Post("/export/pdf", exportPDF)
})
```

**Metrics.** `Metrics(service)` records
`backendkit_http_requests_total{service,route,method,status}` (status as a class such as `2xx`)
and `backendkit_http_request_duration_seconds{service,route,method}`. The `route` label is the
`net/http` `ServeMux` pattern that matched (`r.Pattern`, Go 1.22+), never the raw path; a request
without one is labelled `unmatched`. Mount it first so refused requests are counted, and serve
`MetricsHandler()` on a loopback listener or an admin-only route, never on a public host:

```go
mux := http.NewServeMux()
mux.HandleFunc("GET /api/orders/{id}", getOrder) // route="GET /api/orders/{id}"
go http.ListenAndServe("127.0.0.1:9090", httpware.MetricsHandler())
http.ListenAndServe(":8080", httpware.Metrics("orders")(mux))
```

Full API: [pkg.go.dev/…/httpware](https://pkg.go.dev/github.com/ovander/backendkit/httpware).

---

### gormlogger

Bridges GORM's internal logger to logrus. Slow queries (above the threshold) are logged at
`Warn`; when `ignoreNotFound` is true, `ErrRecordNotFound` is demoted to `Debug` to avoid log noise
in normal operation.

`New` takes positional arguments — `New(entry, level, slowThreshold, ignoreNotFound)` — where
`level` is a `gorm.io/gorm/logger.LogLevel`:

```go
import glogger "gorm.io/gorm/logger"

db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
    Logger: gormlogger.New(
        log.WithField("component", "db"), // *logrus.Entry
        glogger.Warn,                     // minimum level (Silent/Error/Warn/Info)
        200*time.Millisecond,             // slow-query threshold; 0 disables
        true,                             // demote ErrRecordNotFound to Debug
        gormlogger.WithSQLRedaction(),    // production: keep SQL values out of logs
    ),
})
```

GORM hands the logger SQL with bound parameter values already interpolated, which can contain PII
or secrets. In production pass `gormlogger.WithSQLRedaction()` so log records show
`sql: "[redacted]"` while keeping timing, row count, and caller.

Full API: [pkg.go.dev/…/gormlogger](https://pkg.go.dev/github.com/ovander/backendkit/gormlogger).

---

### socrate

The client for the Socrate OAuth and admin APIs. It is written for Socrate's API surface (separate
OAuth and admin ports, the `client_credentials` service-account flow, magic links, the policy
decision point) and will not work against Keycloak, Auth0 or other providers.

The client uses a dual-auth strategy: user-scoped calls forward the caller's JWT; service-account
calls acquire a `client_credentials` token automatically and cache it until near-expiry. Every call
forwards the request id (`ctxutil.GetRequestID`, set by `httpware.RequestID`) as
`X-Correlation-ID`, the header Socrate logs, so one request can be followed across both services.
`ServiceToken(ctx)` returns that token and its expiry, for calling another service that accepts
Socrate tokens as the application itself. When that service refuses the token with 401 before its
expiry (a token revoked at Socrate), `InvalidateServiceToken()` drops the cached token so the next
call exchanges a new one.

> **`AppID` is required for all service-account methods.** Service-account tokens carry
> `sub=app:{id}` and the Socrate admin routes cannot resolve the app ID at runtime without it.
> Always set `AppID` in `ClientConfig`; omitting it causes an immediate error on the first
> service-account call (`InviteUserAsService`, `RegisterUser`, `GetUserAsService`,
> `UpdateUserAsService`, `SendMagicLink`, `Decide`).

```go
client, err := socrate.NewClient(socrate.ClientConfig{
    BaseURL:      os.Getenv("SOCRATE_BASE_URL"),
    ClientID:     os.Getenv("SOCRATE_CLIENT_ID"),
    ClientSecret: os.Getenv("SOCRATE_CLIENT_SECRET"),
    AppID:        os.Getenv("SOCRATE_APP_ID"), // required for service-account calls
})

// User-scoped — attach the caller's raw JWT first:
ctx = socrate.WithJWT(ctx, rawJWT)
users, err := client.ListUsers(ctx, "", 1, 20)
user, err  := client.GetUser(ctx, userID)

// Service-account — token acquired and cached automatically:
inv, err := client.InviteUserAsService(ctx, socrate.ServiceInviteRequest{
    Email: "new@example.com",
    Role:  "editor",
})

// Conflict handling:
if errors.Is(err, socrate.ErrUserAlreadyExists) {
    // handle duplicate registration
}
```

Beyond user management (including `Signup` with the user's own password, and
`UpdateUserAsService` for a member's profile fields and avatar URL), the client wraps the token
flows a BFF needs (`ExchangeCode`, `RefreshToken`, `VerifyMagicLink`, `Logout`), token
introspection and revocation, magic links,
app and superadmin management, security monitoring and alerts, reports, the dashboard and audit
logs, and policy decisions (`Decide`). The
[client integration guide](docs/CLIENT-INTEGRATION.md#6-backend-the-socrateclient) explains the
auth modes and port routing and has the method reference, with the auth mode and port of each
call.

#### Client attribution

A BFF calls Socrate's token and revoke endpoints server-to-server, so Socrate would audit a login,
refresh or logout as the BFF (`127.0.0.1`, `Go-http-client/1.1`). Put the browser's address and
User-Agent on the context and the calls made on a user's behalf — `ExchangeCode`, `RefreshToken`,
`RevokeToken`, `VerifyMagicLink`, `AdminLogin`, `Logout`, `Signup` — send them as `X-Forwarded-For` and
`User-Agent`. Service-account calls (the `client_credentials` grant), `IntrospectToken` and
`GetCurrentUserProfile` never do. Without attribution on the context nothing changes.

```go
// ip comes from YOUR resolver (trust X-Forwarded-For only from your own edge proxy),
// never from a raw request header.
ctx := socrate.WithClientAttribution(r.Context(), socrate.ClientAttribution{
    IP:        ip,
    UserAgent: r.UserAgent(),
})
ts, err := client.ExchangeCode(ctx, code, redirectURI, verifier)

// A BFF building its own token/revoke requests applies it itself:
req, _ := http.NewRequestWithContext(ctx, http.MethodPost, revokeURL, body)
socrate.ApplyClientAttribution(req)
```

| Symbol | Purpose |
|---|---|
| `ClientAttribution{IP, UserAgent}` | The browser a call is made for |
| `WithClientAttribution(ctx, a)` / `ClientAttributionFrom(ctx)` | Store / read it on a context |
| `ApplyClientAttribution(req)` | Set the headers on a request from its context |

`X-Forwarded-For` is **replaced** with exactly the one address (and `X-Real-IP` removed), never
appended to: Socrate takes the leftmost entry from a trusted proxy, so appending to a
browser-supplied value would let the browser choose its logged address. An address that does not
parse sends nothing; the User-Agent loses its control characters and is capped at 512 bytes. In a
`bff` BFF, [`bff.WithClientAttribution`](#bff) sets this from the incoming request.

Full API: [pkg.go.dev/…/socrate](https://pkg.go.dev/github.com/ovander/backendkit/socrate).

---

### jwtauth

Validates RS256 JWTs issued by Socrate, caches JWKS public keys for 1 hour, and injects all
Socrate claims into the request context. Stale keys are retained as a fallback when the JWKS
endpoint is temporarily unreachable, so a Socrate restart does not immediately break live
requests.

```go
auth := jwtauth.New(
    "https://socrate.example.com/.well-known/jwks.json",
    "https://socrate.example.com",
    logger,
)
r.Use(auth.Handler)

// Downstream handlers read claims without importing jwtauth:
tenantID := ctxutil.GetTenantID(r.Context()) // uuid.Nil if the token carried no tenant_id
plan     := ctxutil.GetUserPlan(r.Context()) // "freemium" when absent
```

Two opt-in options harden it; new services should set the first:

```go
auth := jwtauth.New(jwksURL, issuer, logger,
    // Accept a token only when its aud claim contains this service's client ID,
    // so a token minted for another app on the same Socrate is refused.
    jwtauth.WithAudience("my-app-client-id"),

    // Per-request revocation check after validation; an error rejects with 401.
    jwtauth.WithRevocationCheck(func(ctx context.Context, c *jwtauth.SocrateClaims) error {
        if c.TokenVersion < store.CurrentTokenVersion(ctx, c.Subject) {
            return errors.New("token_version superseded")
        }
        return nil
    }))
```

- **Audience.** Without `WithAudience` the `aud` claim is not checked, for backward
  compatibility, and `New` logs a warning at startup: a token issued to another application on
  the same Socrate would validate, with that application's `role`. Once it is set, a token
  without `aud` is rejected. A route group that serves several applications uses
  `WithAudiences(a, b, …)`: the token's `aud` must contain at least one of them; called with no
  non-empty audience it rejects every token (fail closed). `ctxutil.GetAudiences` then tells the
  handler which of them the token was accepted for (its `aud` values in the configured set; every
  `aud` value when no audience check is configured), so a route group that derives behaviour from
  the audience can require exactly one (`len(aud) == 1`) without decoding the token again.
- **Revocation.** Local signature validation alone keeps a token valid until its `exp`, even
  after logout or a password change. The check typically compares `token_version` with the
  user's current value; with none configured, behaviour is unchanged. The checker's context
  already carries the raw token (`ctxutil.GetRawJWT`), so it can also introspect the token at
  Socrate (`/oauth/introspect`); the identity values are set only after the check passes.
- **Tenant claim.** The tenant is read from `tenant_id` by default. A stock Socrate has no tenant
  model: a tenant reaches tokens only through a client's claim mapping
  (`"tenant_id": "user.attributes.tenant_id"`), under Socrate's claims namespace, as
  `https://socrate/tenant_id`. `WithTenantClaim("https://socrate/tenant_id")` reads that claim
  instead; a plain `tenant_id` is then ignored. The value must be a UUID string (anything else
  is a 401); without the claim no tenant is set and `httpware.RequireTenant` rejects the request.
  An empty name rejects every token (fail closed).
- **Authentication facts.** `auth_time` and `amr` (when and how the user authenticated) are
  exposed as `ctxutil.GetAuthTime` / `ctxutil.GetAMR`. They are what a step-up or MFA check needs;
  `pep` uses them to honour policy obligations.

Full API: [pkg.go.dev/…/jwtauth](https://pkg.go.dev/github.com/ovander/backendkit/jwtauth).

---

### bff

The runtime of a Backend-for-Frontend. In a BFF the browser never holds OAuth tokens: the BFF is
the confidential client, runs Authorization Code + PKCE server-side, keeps the tokens in a
server-side session and gives the browser only an opaque `HttpOnly` cookie. The token calls
themselves come from the [`socrate`](#socrate) package — `*socrate.Client` is the gateway's
refresher. The Socrate admin and monitoring consoles run on this package.

```go
store := bff.NewMemoryStore(30*time.Minute, 8*time.Hour) // idle, absolute; call store.Sweep() on a ticker
gw := &bff.Gateway{
	Store:     store,
	Cookie:    bff.CookieConfig{Name: "app_session", Secure: true}, // sent as __Host-app_session
	Refresher: client,                                             // *socrate.Client refreshes the tokens
}

// Every API call: session cookie in, bearer out. No valid session ⇒ 401, never a pass-through.
// Unsafe methods must carry the session's CSRF token in X-CSRF-Token.
mux.HandleFunc("/api/", gw.ProxyWithSession(bff.NewSingleHostProxy(apiURL)))

// Optional: attribute token calls to the browser; serve this instead of mux.
// clientIP is your own resolver (X-Forwarded-For only from your edge proxy).
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	mux.ServeHTTP(w, bff.WithClientAttribution(r, clientIP(r)))
})
log.Fatal(http.ListenAndServe("127.0.0.1:8080", handler))
```

The login and callback handlers that create the session (`NewPKCE`, `LoginBinding`,
`SanitizeReturnTo`, `socrate.Client.ExchangeCode`, `NewSession`) are shown end to end in the
[client integration guide](docs/CLIENT-INTEGRATION.md#71-browser-apps-use-a-backend-for-frontend-bff).
[`oauth2-admin/bff`](https://github.com/ovander/oauth2-admin/tree/main/bff) is a complete BFF
built this way.

**Safe by default.**

| Concern | Behaviour |
|---|---|
| No or expired session | `ProxyWithSession` answers **401**; it never forwards the request (opt-out: `AllowPassthrough`) |
| CSRF | Unsafe methods need the session's token in `X-CSRF-Token` (constant-time compare), else **403** |
| Cookie | `HttpOnly`, `SameSite=Strict`, and `__Host-` prefixed when `Secure` |
| Login CSRF / session swap | `LoginBinding` accepts a callback only from the browser that started the login |
| Open redirect | `SanitizeReturnTo` keeps only same-site paths such as `/dashboard?x=1`; absolute URLs, `//host`, backslash and control-character tricks all become `/` |
| Token refresh | Proactive, coalesced per session, detached from the triggering request, and written through to the store so the rotated refresh token is kept. Only a refresh the server rejects (`IsFatalRefreshError`) ends the session; a transient failure answers 502 and keeps it |
| Upstream attribution | `NewSingleHostProxy` strips client-supplied IP-attribution headers (`X-Real-IP`, `True-Client-IP`, `Forwarded`), so the browser cannot steer Socrate's rate limits, IP blocks or audit trail; `X-Forwarded-For` is left to the edge proxy |
| Token-call attribution | Opt-in: `WithClientAttribution(r, ip)` puts the browser's address (as **your** resolver found it) and User-Agent on the request context, so the code exchange, the gateway's refresh and revocation are audited by Socrate as the browser rather than as the BFF (see [client attribution](#client-attribution)) |

**Sessions that survive a restart, or several instances.** `MemoryStore` is per process: a
restart signs everyone out. `PostgresStore` keeps sessions in PostgreSQL, through a `*sql.DB` you
open with the driver of your choice (backendkit imports none):

```go
db, _ := sql.Open("pgx", os.Getenv("BFF_SESSION_DSN")) // import _ "github.com/jackc/pgx/v5/stdlib"
key, _ := base64.StdEncoding.DecodeString(os.Getenv("BFF_SESSION_KEY")) // 32 bytes: openssl rand -base64 32
store, err := bff.NewPostgresStore(ctx, db, key, 30*time.Minute, 8*time.Hour) // creates its table
```

The session data, tokens included, is encrypted with AES-256-GCM under that key, bound to the
session ID; changing the key signs everyone out. A logout wipes the data and keeps a tombstone
for an hour, so a request racing it cannot bring the session back. Expiry is the same as
`MemoryStore`; call `Sweep` on a ticker. Statement errors read as "no session" and go to the error
handler (`WithPostgresErrorHandler`; default: the standard logger). For another database,
implement `SessionStore` (`Get`, `Put`, `Delete`, `Sweep`) with `Session.Snapshot` /
`NewSessionFromSnapshot`. A `Gateway` must be used by pointer and never copied.

**Least-privilege database role.** By default `NewPostgresStore` runs `CREATE TABLE IF NOT EXISTS`
and `CREATE INDEX IF NOT EXISTS`, which PostgreSQL refuses to a role without `CREATE` on the schema
and ownership of the table, even when both already exist. When your migrations own the table, pass
`bff.WithPostgresManagedSchema()`: the store runs no DDL, checks at start-up that the table has its
columns and that the role holds `SELECT`, `INSERT`, `UPDATE` and `DELETE` on it, and fails
otherwise. The `CREATE TABLE` and `CREATE INDEX` your migration must run are in its doc comment;
the table name (`WithPostgresTable`) is unqualified, so put the schema in the role's `search_path`.

Full API: [pkg.go.dev/…/bff](https://pkg.go.dev/github.com/ovander/backendkit/bff).

---

### pep

The policy enforcement point for Socrate's policy decision point: the Socrate endpoint that
evaluates an application's action against the central policy. Rules live in Socrate — RBAC over
roles, ABAC over user attributes, resource attributes and request context — and every
application asks the same decision point:

```go
client, _ := socrate.NewClient(socrate.ClientConfig{ /* BaseURL, ClientID, ClientSecret, AppID */ })
enf, _ := pep.New(pep.Config{Decider: client, Logger: logger})

r.Use(auth.Handler) // jwtauth first: the user's own token is the decision's subject

// Route-level: one decision before the handler.
r.With(enf.Middleware(func(r *http.Request) (string, socrate.PolicyResource, bool) {
    return "invoice.read", socrate.PolicyResource{Type: "invoice"}, true
})).Get("/invoices", listInvoices)
```

For object-level checks inside a handler (`Enforcer.Check` with the loaded resource's
attributes, then `pep.WriteDenial`), see the
[client integration guide](docs/CLIENT-INTEGRATION.md#10-enforcing-central-policy-decisions-pep).

**Who decides what.** Socrate resolves the user — role, attributes, role in *this* application,
and from the token how and when they authenticated — so nothing about the user is taken on the
application's word. The application supplies the action, the resource and the request context.

**The mode comes from Socrate** with every decision, so one switch there (`POLICY_MODE`) moves
every application at once, with no redeploy:

| Mode | A denial… |
|---|---|
| `off` | is ignored |
| `shadow` | is logged (`pep: policy would deny`) and the request proceeds |
| `enforce` | is refused: `403 {"error": "policy_denied"}` |

An allow can carry **obligations**, honoured here against the verified token:
`require_fresh_auth` (within `FreshAuthMaxAge`, default 5 min) → `403 elevation_required`;
`require_mfa` (`amr` contains `mfa`) → `403 mfa_required`. An obligation this version does not
know is treated as unmet, never dropped.

**When Socrate cannot be reached** the last mode seen decides: proceed in `off`/`shadow` (a
shadow rollout can never take the application down), refuse `503 policy_unavailable` in
`enforce`. Before any decision has told the process the mode it refuses too, unless
`FailOpenWhenModeUnknown` is set. A request with no user token in context (pep mounted before
jwtauth) is refused with 401, never decided as the application.

**A floor under Socrate's mode.** `POLICY_MODE` is server-wide. An application that must enforce
its rules while Socrate is still `off` or `shadow` for others sets `MinimumMode`: the effective
mode is the stricter of the two (`off` < `shadow` < `enforce`). With `MinimumMode: "enforce"`, in
every server mode, a deny is `403 policy_denied`, an unmet obligation is `elevation_required` or
`mfa_required`, and an unreachable Socrate is `503 policy_unavailable`, even before any decision
has reported a mode. `New` refuses `MinimumMode: "enforce"` combined with
`FailOpenWhenModeUnknown`. With `"shadow"`, a server in `off` is treated as `shadow`. Socrate
evaluates its rules in every mode, so these are real decisions; while `POLICY_MODE=off` Socrate
does not record them in its decision log (ovander/go-oauth2#323).

`ContextFor` sends the request's peer address as `context.ip`: behind a proxy, resolve
`RemoteAddr` with a trusted real-IP middleware first — a spoofable `X-Forwarded-For` must never
reach a policy. `CheckAsApp` decides for the application itself (no user), e.g. in a background
job. `OnDecision` is a hook for metrics.

Full API: [pkg.go.dev/…/pep](https://pkg.go.dev/github.com/ovander/backendkit/pep).

---

### tiering

Three components that work together for plan-based feature gating.

**PlanRegistry** — an ordered plan hierarchy with tier comparison:

```go
reg := tiering.DefaultRegistry() // freemium < pro < enterprise

reg.TierAtLeast("pro", "freemium") // true
reg.TierAtLeast("freemium", "pro") // false
reg.Normalise("UNKNOWN")           // "freemium" (lowest tier)

// Custom hierarchy:
reg = tiering.NewPlanRegistry("starter", "growth", "enterprise")
```

**Gate** — HTTP middleware that rejects requests below a plan threshold with a structured JSON
error:

```go
gate := tiering.NewGate(tiering.DefaultRegistry(), logger, "/billing")

r.With(gate.Require(tiering.PlanPro)).Post("/ai/narrate", handler)
// Freemium users receive 403 with the standard error envelope:
// {"error":{"code":"upgrade_required",
//           "message":"This feature requires the pro plan or above",
//           "details":{"plan":"freemium","requiredPlan":"pro","upgradeUrl":"/billing"}}}
```

**PolicyService** — per-feature rules stored in your database, cached in-process for 5 minutes.
Implement `tiering.PolicyRepository` with your GORM repository to plug in persistence, then
construct the service with
`tiering.NewPolicyService(repo, registry, tiering.DefaultPlanSelector, logger)`. Every method
takes a `context.Context` so cancellation and tracing propagate to the DB.

```go
// Seed baseline rules at startup:
svc.SeedDefaults(ctx, []tiering.FeaturePolicy{
    {
        Feature: "ai_narration", Category: "ai", Label: "AI Narration",
        FeatureType: tiering.FeatureTypeAccess,
        Freemium:    tiering.MarshalAccess(false),
        Pro:         tiering.MarshalAccess(true),
        Enterprise:  tiering.MarshalAccess(true),
    },
    {
        Feature: "export_limit", Category: "exports", Label: "Monthly Exports",
        FeatureType: tiering.FeatureTypeNumericLimit,
        Freemium:    tiering.MarshalLimit(5),
        Pro:         tiering.MarshalLimit(50),
        Enterprise:  tiering.MarshalLimit(-1), // -1 = unlimited
    },
})

// In a handler:
plan    := ctxutil.GetUserPlan(ctx)
allowed := svc.IsAllowed(ctx, "ai_narration", plan) // false on deny or error
limit   := svc.NumericLimit(ctx, "export_limit", plan) // -1 = unlimited, 0 if absent
```

Full API: [pkg.go.dev/…/tiering](https://pkg.go.dev/github.com/ovander/backendkit/tiering).

---

### aigateway

Normalises OpenAI and Anthropic Claude into a single `Call(ctx, prompt) (string, error)`
interface. Provider-specific configuration is handled at construction time; callers are
provider-agnostic.

```go
ai := aigateway.New(aigateway.Config{
    Provider:   "claude",  // "claude" or "openai"
    APIKey:     os.Getenv("ANTHROPIC_API_KEY"),
    Model:      "claude-sonnet-4-6",
    MaxTokens:  2000,
    TimeoutSec: 30,
}, logger)

result, err := ai.Call(ctx, prompt)

// Override the token ceiling for a single call:
result, err = ai.CallWithMaxTokens(ctx, prompt, 4000)

// Parse a JSON object embedded in an AI prose response:
var data MyStruct
err = aigateway.ExtractJSONInto(result, &data) // or ExtractJSON(result) for the raw string
```

Set `Config.AllowedModels` to restrict which Claude models may be used; a call with an
out-of-list model returns an error. `Client.IsConfigured()` reports whether an API key is present
(handy for feature-flagging AI endpoints), and `Client.Provider()` returns the configured provider
name. `NewAIClient` builds a language-safe client (wrapped with [`ailang`](#ailang)) and also
accepts `"ollama"` for a local model.

For tests, `aigateway.ClientForTest(provider, apiKey, serverURL)` points both provider base URLs
at an `httptest.Server` so AI-dependent handlers can be exercised without a live API key.

Full API: [pkg.go.dev/…/aigateway](https://pkg.go.dev/github.com/ovander/backendkit/aigateway).

---

### ailang

A language guard for AI output: every `AIResponse.Text` is in the requested locale (`fr` or
`en`). It prepends a language directive to the prompt, checks the answer with a fast stopword
heuristic, retries once with a reinforced prompt, and as a last resort translates the answer with
the same model.

```go
guard := ailang.New(aiClient, ailang.DefaultAIConfig(), nil, logger) // aiClient: *aigateway.Client; nil reporter = no-op

resp, err := guard.Generate(ctx, ailang.PromptInput{
    Prompt:   "Explique les résultats du plan.",
    Locale:   "fr",
    Metadata: map[string]any{"module": "insight"},
})
```

Mismatches, retries and translation fallbacks are reported through the optional `EventReporter`
(for example a Sentry adapter), so language drift is observable rather than silent.

Full API: [pkg.go.dev/…/ailang](https://pkg.go.dev/github.com/ovander/backendkit/ailang).

---

### ainarration

A generic LRU+TTL cache for AI narration results, keyed by tenant and a content-addressed
`CacheKey`. `NarrationCacher` is an interface — implement it with a DB-backed layer for
persistence across restarts.

```go
cache := ainarration.NewNarrationCache(ainarration.DefaultCacheConfig())
// DefaultCacheConfig: MaxSize = 200 entries, TTL = 2 h

// Same inputs always produce the same key (content-addressed):
key := ainarration.CacheKey("plan_narration", userRole, myContextStruct)

if out, ok := cache.Get(tenantID, key); ok {
    return out.Narrative // served from cache
}

text, _ := ai.Call(ctx, prompt)
cache.Put(tenantID, key, &ainarration.NarrationOutput{
    Narrative: text,
    Metadata:  map[string]any{"model": "claude-sonnet-4-6", "latency_ms": 340},
})
```

Full API: [pkg.go.dev/…/ainarration](https://pkg.go.dev/github.com/ovander/backendkit/ainarration).

---

### pagination

Query-parameter parsing for `page` and `per_page`, with defaults and upper-bound clamping
(`DefaultPerPage = 20`, `MaxPerPage = 100`). Returns a `PagedResponse` envelope for consistent
list API shapes.

```go
params := pagination.Parse(r)   // reads ?page & ?per_page; page=1, perPage=20 by default
offset := params.Offset         // field (not a method): (page-1) * perPage

resp := pagination.NewPagedResponse(items, params, total) // (data, params, totalItems)
// {"data": [...], "page": 1, "perPage": 20, "totalItems": 142, "totalPages": 8}
```

Full API: [pkg.go.dev/…/pagination](https://pkg.go.dev/github.com/ovander/backendkit/pagination).

---

### buildinfo

Exposes build-time metadata injected via `-ldflags` and a ready-to-mount version handler. The
`Version`, `BuildTime`, and `GitCommit` package variables are link-time targets; they fall back
to safe defaults (`Version = "dev"`) when unset.

```makefile
LDFLAGS := \
    -X github.com/ovander/backendkit/buildinfo.Version=$(VERSION) \
    -X github.com/ovander/backendkit/buildinfo.BuildTime=$(BUILD_TIME) \
    -X github.com/ovander/backendkit/buildinfo.GitCommit=$(GIT_COMMIT)
```

```go
// Mount on an unauthenticated route so monitoring tools can read it tokenless.
r.Get("/api/v1/version", buildinfo.Handler())

// Or read the struct directly (adds GoVersion from runtime.Version()):
info := buildinfo.Get()
// {"version":"v1.2.3","buildTime":"...","gitCommit":"a1b2c3d","goVersion":"go1.25"}
```

Full API: [pkg.go.dev/…/buildinfo](https://pkg.go.dev/github.com/ovander/backendkit/buildinfo).

---

## Environment variables

backendkit **reads no environment variables itself** — you pass configuration explicitly to each
constructor. The variables below are the conventions used in this README's examples; name them
however you like in your own service.

| Variable | Consumed by | Purpose |
|----------|-------------|---------|
| `SOCRATE_JWKS_URL` | `jwtauth.New` | JWKS endpoint used to validate RS256 signatures, e.g. `https://socrate.example.com/.well-known/jwks.json` |
| `SOCRATE_ISSUER` | `jwtauth.New` | Expected `iss` claim — optional; enforced only when non-empty (an empty value logs a warning at startup) |
| `SOCRATE_BASE_URL` | `socrate.NewClient` | Socrate OAuth port base URL (e.g. `https://socrate.example.com`) |
| `SOCRATE_ADMIN_BASE_URL` | `socrate.NewClient` | Socrate admin API base URL, e.g. `http://127.0.0.1:8081` (the server's `ADMIN_PORT`; 8082 where a legacy server holds 8081). Set it in production: the value derived from `SOCRATE_BASE_URL` (port 8081, same scheme and host) is wrong behind a TLS proxy |
| `SOCRATE_CLIENT_ID` | `socrate.NewClient`, `jwtauth.WithAudience` | OAuth client ID |
| `SOCRATE_CLIENT_SECRET` | `socrate.NewClient` | Client secret — required for service-account calls, `Decide`, `RevokeToken`, `IntrospectToken` and a BFF's token exchange |
| `SOCRATE_APP_ID` | `socrate.NewClient` | Pre-resolved numeric app ID — **required** for every service-account method, including `Decide` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | `aigateway.New` | Provider API key for the configured provider |

---

## Testing

Because every claim helper reads from `context.Context`, you can exercise gated handlers without
minting real JWTs — just seed the context the way `jwtauth` would:

```go
import (
    "net/http/httptest"

    "github.com/ovander/backendkit/ctxutil"
    "github.com/ovander/backendkit/tiering"
)

req := httptest.NewRequest(http.MethodGet, "/ai/narrate", nil)
ctx := req.Context()
ctx = ctxutil.WithUserPlan(ctx, tiering.PlanPro) // pretend a pro user
ctx = ctxutil.WithUserRole(ctx, "editor")
req = req.WithContext(ctx)
// ...serve req through your gate/RBAC middleware and assert on the recorder.
```

The AI gateway ships a test constructor so handlers that call a provider can run against an
`httptest.Server` with no real API key:

```go
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(`{"content":[{"type":"text","text":"hello"}]}`)) // mock Claude response
}))
defer srv.Close()

ai := aigateway.ClientForTest("claude", "test-key", srv.URL)
out, _ := ai.Call(context.Background(), "ping") // → "hello"
```

The Socrate-facing seams are interfaces, so tests need no Socrate server: `pep.Config.Decider`
takes any `pep.Decider` (seed the token with `ctxutil.WithRawJWT`), and `bff.Gateway.Refresher`
takes any `bff.TokenRefresher`; `bff.Gateway.Now` fixes the clock.
`ainarration.NarrationCache.Flush()` resets the cache between test cases, and each package ships
runnable `Example*` functions (visible on
[pkg.go.dev](https://pkg.go.dev/github.com/ovander/backendkit)) that double as usage docs.

---

## Troubleshooting

| Symptom | Likely cause & fix |
|---------|--------------------|
| **Every request returns 401** | No `Authorization: Bearer <token>` header, an `iss` that doesn't match `SOCRATE_ISSUER`, an `aud` that doesn't contain the `WithAudience` value (or any `WithAudiences` value), or the JWKS URL is unreachable. Stale keys are reused on a *transient* fetch failure, but a wrong/empty JWKS URL fails closed. |
| **`GetTenantID` is `uuid.Nil` / `GetUserPlan` is always `"freemium"`** | `tenant_id` and `plan` are **custom** claims. A stock Socrate server does not emit them — configure Socrate to include them, or these helpers return their zero/default values by design. Socrate's claim mappings issue them under its namespace (`https://socrate/tenant_id`): pass `jwtauth.WithTenantClaim("https://socrate/tenant_id")`. |
| **`GetUserEmail` / `GetUserName` are empty** | Email and name live in the **ID token**, not the access token. For access-token requests, fetch them via `socrate.Client.GetCurrentUserProfile`. |
| **Compile error passing a logger to `httpware.Logger`** | `Logger` takes the base `*logrus.Logger`; `Recover`, `NewRBAC`, `jwtauth.New`, and `tiering.NewGate` take a `*logrus.Entry`. See the [httpware](#httpware) note. |
| **Service-account call errors with "AppID must be set"** | Set `AppID` in `ClientConfig` (`SOCRATE_APP_ID`). The `/api/admin/apps` lookup needs a human-admin JWT, so a service token cannot resolve the app ID at runtime. |
| **Rate limiter never limits** | `RateLimiter` keys on the tenant UUID and lets requests through when none is present. Place `rl.Handler` **after** `auth.Handler` so `tenant_id` is already in context. |
| **`tiering.Gate` always allows / always denies** | The gate reads the plan from context (`ctxutil.GetUserPlan`); confirm auth runs before the gate and that your `PlanRegistry` contains the plan names you check. Unknown plans normalise to the lowest tier. |
| **BFF answers 403 on `POST`/`PUT`/`DELETE`** | The request lacks the session's CSRF token in `X-CSRF-Token`. Give the SPA the token (for example in your `/bff/session` response) and send it on every unsafe request. |
| **Every `pep` check answers 401** | `pep` runs before `jwtauth`, so there is no user token in context. Mount `auth.Handler` first. |
| **`pep` answers `503 policy_unavailable` at startup** | Socrate's decision point was unreachable before any decision told the process the mode. Check `SOCRATE_BASE_URL`, `SOCRATE_CLIENT_SECRET` and `SOCRATE_APP_ID`; set `FailOpenWhenModeUnknown` only if proceeding is acceptable while the mode is unknown. |

---

## Used by

- [ovander/oauth2-admin](https://github.com/ovander/oauth2-admin) — the Socrate superadmin
  console; its BFF (`bff/`) is built on `bff` and `socrate`.
- [ovander/oauth2-monitoring](https://github.com/ovander/oauth2-monitoring) — the Socrate
  security monitoring console; its BFF (`bff/`) is built on `bff` and `socrate`.
- [ovander/ascenda-backend](https://github.com/ovander/ascenda-backend) — a multi-tenant
  financial planning API using `jwtauth`, `httpware`, `ctxutil`, `apierror`, `socrate`,
  `tiering`, `pagination`, `gormlogger`, `ainarration` and `buildinfo`.

---

## Versioning

backendkit follows [Semantic Versioning](https://semver.org), with no breaking change within a
major version:

- **Patch** (`v1.x.y`) — bug fixes and non-breaking internal changes.
- **Minor** (`v1.x.0`) — new exported symbols, new packages, backward-compatible additions.
- **Major** (`v2.0.0`) — breaking changes to existing exported APIs. A new major version requires
  updating the import path (`github.com/ovander/backendkit/v2`).

Always pin an explicit version in `go.mod` rather than using `@latest` to keep builds
reproducible.

---

## Status

backendkit is in active use as part of the Socrate suite. Current focus:

- Rolling out `pep` so applications enforce Socrate's central policy decisions.
- Keeping `v1` backward compatible: hardening such as audience validation stays opt-in, and
  making it the default waits for a `v2`.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the checks CI runs, and the pull-request
workflow; changes are listed in [CHANGELOG.md](CHANGELOG.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

---

## License

Copyright © 2026 Olivier Vandermoten. Licensed under the Apache License, Version 2.0; see
[LICENSE](LICENSE). SPDX-License-Identifier: Apache-2.0
