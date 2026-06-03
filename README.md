# backendkit

[![Go Reference](https://pkg.go.dev/badge/github.com/ovander/backendkit.svg)](https://pkg.go.dev/github.com/ovander/backendkit)
[![CI](https://github.com/ovander/backendkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ovander/backendkit/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ovander/backendkit)](https://goreportcard.com/report/github.com/ovander/backendkit)

Shared Go library for backend services that use [Socrate](https://github.com/ovander/socrate) as their OAuth2/OIDC provider.

---

## Contents

- [Why backendkit?](#why-backendkit)
- [Requirements](#requirements)
- [Installation](#installation)
- [Environment variables](#environment-variables)
- [Quick start](#quick-start)
- [Packages](#packages) · [Which package do I need?](#which-package-do-i-need)
- [Architecture overview](#architecture-overview)
- [Full integration example](#full-integration-example)
- [Package reference](#package-reference)
  — [apierror](#apierror) · [ctxutil](#ctxutil) · [httpware](#httpware) · [gormlogger](#gormlogger) · [socrate](#socrate) · [jwtauth](#jwtauth) · [tiering](#tiering) · [aigateway](#aigateway) · [ainarration](#ainarration) · [pagination](#pagination) · [buildinfo](#buildinfo)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Production usage](#production-usage)
- [Versioning](#versioning)
- [Contributing](#contributing)

---

## Why backendkit?

Building a new Socrate-backed service means solving the same problems every time: validating RS256 JWTs from a JWKS endpoint, propagating tenant/user/plan claims through context, enforcing plan-based feature gates, wiring a structured middleware stack, and normalising AI provider calls. Without a shared library, this logic gets copy-pasted and diverges.

backendkit packages that foundation into a single, versioned dependency so every service starts from the same production-grade baseline:

- **Zero boilerplate auth** — one `jwtauth.New(...)` call validates JWTs, caches JWKS keys, and injects all Socrate claims into the request context.
- **Consistent observability** — structured logrus logging, request IDs, and GORM slow-query detection are wired in from day one.
- **Plan-based access control** — `tiering` gives you a plan hierarchy, HTTP middleware gates, and per-feature policy rules backed by Postgres.
- **Socrate API client** — a single `socrate.Client` covers user CRUD, service-account token management, magic-link flows, and invite emails.
- **Decoupled packages** — import only what you need; there are no forced transitive dependencies between packages except the shared primitives (`ctxutil`, `apierror`).

---

## Requirements

- **Go 1.25** or later
- **Socrate** — backendkit is not a generic OAuth2 toolkit. It is designed specifically for services that use Socrate as their identity provider. Without a running Socrate instance, `jwtauth`, `socrate`, and `ctxutil` will not function correctly.
- A PostgreSQL database is required if you use `tiering.PolicyService` for persistent feature policies.

---

## Installation

```bash
go get github.com/ovander/backendkit@v1.5.1
```

```go
// go.mod
module github.com/your-org/my-service

go 1.25

require github.com/ovander/backendkit v1.5.1
```

---

## Environment variables

backendkit **reads no environment variables itself** — you pass configuration explicitly to each constructor. The variables below are the conventions used throughout this README's examples; name them however you like in your own service.

| Variable | Consumed by | Purpose |
|----------|-------------|---------|
| `SOCRATE_JWKS_URL` | `jwtauth.New` | JWKS endpoint used to validate RS256 signatures |
| `SOCRATE_ISSUER` | `jwtauth.New` | Expected `iss` claim — optional; enforced only when non-empty |
| `SOCRATE_BASE_URL` | `socrate.NewClient` | Socrate OAuth port base URL (e.g. `https://auth.example.com`) |
| `SOCRATE_CLIENT_ID` | `socrate.NewClient` | OAuth client ID |
| `SOCRATE_CLIENT_SECRET` | `socrate.NewClient` | Client secret — required for service-account calls, `RevokeToken`, `IntrospectToken` |
| `SOCRATE_APP_ID` | `socrate.NewClient` | Pre-resolved numeric app ID — **required** for every service-account method |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | `aigateway.New` | Provider API key for the configured provider |

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

---

## Packages

| Package | Purpose |
|---------|---------|
| [`apierror`](#apierror) | Structured HTTP error types (`AppError`, constructor functions) |
| [`ctxutil`](#ctxutil) | Typed context keys for Socrate claims (tenant, user, role, plan, logger, request-id) |
| [`httpware`](#httpware) | Chi-compatible middlewares: RequestID, Logger, SecurityHeaders, BodyLimit, Recover, Timeout, RateLimiter, RBAC |
| [`gormlogger`](#gormlogger) | GORM → logrus bridge with slow-query detection |
| [`jwtauth`](#jwtauth) | JWT RS256 validation middleware with JWKS cache and stale-key fallback |
| [`socrate`](#socrate) | Full Socrate API client: user CRUD, service-account token, magic links, invite, app & superadmin management, security monitoring, dashboard, audit logs, token introspection/revocation |
| [`tiering`](#tiering) | Plan registry, tier gate middleware, feature policy model and service |
| [`aigateway`](#aigateway) | Multi-provider AI client (OpenAI + Claude), `ExtractJSON`/`ExtractJSONInto` |
| [`ainarration`](#ainarration) | Generic LRU+TTL narration cache and `CacheKey` helper |
| [`pagination`](#pagination) | Query-param parsing and `PagedResponse` |
| [`buildinfo`](#buildinfo) | Build-time version metadata (`-ldflags`) and a `/version` HTTP handler |

Every package is independent — `go get` pulls the whole module, but importing one package never drags in another (the only internal dependencies are the shared `ctxutil` and `apierror` primitives).

### Which package do I need?

| I want to… | Use |
|------------|-----|
| Validate incoming Socrate JWTs and populate the request context | [`jwtauth`](#jwtauth) |
| Read the tenant / user / role / plan of the current request | [`ctxutil`](#ctxutil) |
| Add request IDs, structured logging, panic recovery, timeouts, body limits, security headers | [`httpware`](#httpware) |
| Rate-limit per tenant | [`httpware.RateLimiter`](#httpware) |
| Gate routes by role/permission | [`httpware.RBAC`](#httpware) |
| Gate routes or features by commercial plan | [`tiering`](#tiering) |
| Return consistent JSON errors | [`apierror`](#apierror) |
| Call Socrate to manage users, apps, tokens, or security | [`socrate`](#socrate) |
| Call OpenAI or Claude through one interface | [`aigateway`](#aigateway) |
| Cache AI results to cut latency and cost | [`ainarration`](#ainarration) |
| Parse `?page`/`?per_page` and return paged lists | [`pagination`](#pagination) |
| Log GORM queries through logrus / flag slow queries | [`gormlogger`](#gormlogger) |
| Expose build/version info on a `/version` endpoint | [`buildinfo`](#buildinfo) |

---

## Architecture overview

A typical service wires the packages in three layers:

```
HTTP request
    │
    ▼
┌────────────────────────────────────────────┐
│  httpware middleware stack (chi router)    │
│  RequestID → Logger → SecurityHeaders →   │
│  Recover → Timeout → jwtauth → RateLimiter│
└───────────────────┬────────────────────────┘
                    │  context carries:
                    │  tenant, user, role, plan, request-id, logger
                    ▼
┌────────────────────────────────────────────┐
│  Route handlers                            │
│  • tiering.Gate.Require(plan)              │
│  • httpware.RBAC.Require(permission)       │
│  • socrate.Client  (identity operations)   │
│  • aigateway.Client (AI calls)             │
│  • ainarration.NarrationCache (cache AI)   │
└───────────────────┬────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────┐
│  Data layer                                │
│  • GORM + gormlogger                       │
│  • tiering.PolicyService (feature flags)   │
└────────────────────────────────────────────┘
```

---

## Full integration example

The following bootstraps a production chi router with the complete middleware stack, plan-based routing, and enterprise-only admin routes.

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

---

## Package reference

### apierror

Constructor functions for all common HTTP error shapes. Every constructor returns `*AppError` which implements `error` and serialises itself as JSON when written to an `http.ResponseWriter` via `WriteJSON`. The wire shape is wrapped in an `error` envelope:

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

Available constructors: `NotFound`, `BadRequest`, `Unauthorized`, `Forbidden`, `Conflict`, `ValidationError`, `TooManyRequests`, `Internal`, `BadGateway`, `ServiceUnavailable`.

When the status is **dynamic** (e.g. proxying an upstream response) and the typed constructors don't fit, `New(status, msg)` builds an `AppError` for any status — deriving the same machine code the typed constructors use — and `Write(w, status, msg)` builds and writes it in one call:

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

---

### ctxutil

Typed helpers for every Socrate JWT claim that `jwtauth` injects into the context. Every `Get*` function returns a single value and is safe to call even when the value is absent — it returns the zero value (`uuid.Nil`, `""`, `0`, or `nil`), except `GetUserPlan`, which defaults to `"freemium"`, and `GetLogger`, which falls back to the standard logger.

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
rawJWT    := ctxutil.GetRawJWT(ctx)      // string — bearer token for forwarding to socrate.Client

// Multi-app role claims (app_roles) and the monotonic token_version:
roles := ctxutil.GetAppRoles(ctx)             // map[string]string — clientID → role
role  = ctxutil.GetAppRole(ctx, "my-app-id")  // role within a specific app, "" if none
ver   := ctxutil.GetTokenVersion(ctx)         // int — 0 when absent
```

> `GetTenantTier`/`WithTenantTier` are deprecated aliases for `GetUserPlan`/`WithUserPlan`; use the `*UserPlan` names in new code.

---

### httpware

All middleware functions follow the standard `func(http.Handler) http.Handler` signature and work with any `net/http`-based router.

| Middleware | Constructor |
|-----------|-------------|
| Request ID | `httpware.RequestID` |
| Structured logger | `httpware.Logger(logger)` — takes a `*logrus.Logger` |
| Security headers | `httpware.SecurityHeaders` |
| Body size limit | `httpware.BodyLimit(maxBytes)` |
| Panic recovery | `httpware.Recover(entry)` — takes a `*logrus.Entry` |
| Per-route timeout | `httpware.Timeout(d)` |
| Per-tenant rate limit | `httpware.NewRateLimiter(rps, burst)` |
| Role-based access | `httpware.NewRBAC(roleMap, entry)` |

> Note the logger types differ: `Logger` takes the base `*logrus.Logger` (it derives a request-scoped `*logrus.Entry` per request), while `Recover` and `NewRBAC` take a pre-enriched `*logrus.Entry`.

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

**Nested timeouts:** `httpware.Timeout` strips the existing deadline before applying the new one, so inner routes can safely override the global default:

```go
r.Use(httpware.Timeout(10 * time.Second)) // global default

r.Group(func(r chi.Router) {
    r.Use(httpware.Timeout(120 * time.Second)) // replaces the 10 s deadline
    r.Post("/export/pdf", exportPDF)
})
```

---

### gormlogger

Bridges GORM's internal logger to logrus. Slow queries (above the threshold) are logged at `Warn`; when `ignoreNotFound` is true, `ErrRecordNotFound` is demoted to `Debug` to avoid log noise in normal operation.

`New` takes positional arguments — `New(entry, level, slowThreshold, ignoreNotFound)` — where `level` is a `gorm.io/gorm/logger.LogLevel`:

```go
import glogger "gorm.io/gorm/logger"

db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
    Logger: gormlogger.New(
        log.WithField("component", "db"), // *logrus.Entry
        glogger.Warn,                     // minimum level (Silent/Error/Warn/Info)
        200*time.Millisecond,             // slow-query threshold; 0 disables
        true,                             // demote ErrRecordNotFound to Debug
    ),
})
```

---

### socrate

> 📘 **Integrating an app?** See the [Socrate + backendkit Client Integration Guide](docs/CLIENT-INTEGRATION.md) — an end-to-end walkthrough for backend and frontend teams (middleware wiring, the two auth modes, login flows, error handling, and a full method reference).

> **Socrate dependency note.** This client is purpose-built for Socrate and is not a generic OAuth2 or OIDC library. It assumes Socrate's specific API surface (dual user/admin ports, `client_credentials` service-account flow, magic-link endpoint). It will not work against Keycloak, Auth0, or other providers.

The client uses a dual-auth strategy: user-scoped calls forward the caller's JWT; service-account calls acquire a `client_credentials` token automatically and cache it until near-expiry.

> **`AppID` is required for all service-account methods.** Service-account tokens carry `sub=app:{id}` and the Socrate admin routes cannot resolve the app ID at runtime without it. Always set `AppID` in `ClientConfig`; omitting it causes an immediate error on the first service-account call (`InviteUserAsService`, `RegisterUser`, `GetUserAsService`, `SendMagicLink`).

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

**Magic-link (passwordless) authentication**

Only the app backend may trigger magic-link emails — the endpoint is on the Socrate admin port and is M2M-only. `SendMagicLink` uses the service-account token automatically.

```go
resp, err := client.SendMagicLink(ctx, "user@example.com")
if err != nil {
    if errors.Is(err, socrate.ErrMagicLinkRateLimited) {
        // 5 requests / hour per email + app pair
    }
    return err
}
// resp.Message is always the same opaque string (enumeration resistance).
// resp.MagicURL is non-empty in development mode only.
//
// The verify endpoint is POST-only (GET would let email scanners consume
// the single-use token before the user clicks). Your frontend reads
// ?token= and ?client_id= from the clicked URL and POSTs them:
//
//   POST /api/auth/magic-link/verify
//   {"token": "<raw>", "client_id": "<client_id>"}
//
// On success Socrate returns an access_token, refresh_token, and id_token.
```

**Beyond user CRUD**

The client also wraps the full Socrate admin and OAuth surface. All admin methods forward the caller's JWT and require an admin/superadmin token; the OAuth/token methods authenticate with the client credentials.

| Area | Methods |
|------|---------|
| App-scoped users | `ListUsers`, `GetUser`, `CreateUser`, `UpdateUserRole`, `DeleteUser`, `ResendVerification`, `ForcePasswordReset` |
| Service-account (M2M) | `RegisterUser`, `InviteUserAsService`, `GetUserAsService`, `SendMagicLink` |
| OAuth / OIDC | `GetCurrentUserProfile`, `RevokeToken`, `IntrospectToken` |
| BFF token flows | `ExchangeCode`, `RefreshToken`, `VerifyMagicLink`, `AdminLogin`, `Logout` |
| User self-service profile | `GetProfile`, `UpdateProfile` |
| App management | `ListApps`, `GetApp`, `CreateApp`, `UpdateApp`, `DeleteApp`, `RotateSecret` |
| App activity logs | `GetAppLogs` |
| Global user admin | `AdminListUsers`, `AdminGetUser`, `AdminDeleteUser`, `GetUserApps`, `BlockUser`, `UnlockUser`, `RevokeUserTokens` |
| Sessions | `ListSessions`, `GetUserSessions` |
| Superadmins | `ListSuperadmins`, `GetSuperadmin`, `CreateSuperadmin`, `UpdateSuperadmin`, `DeleteSuperadmin` |
| Security monitoring | `GetThreatMetrics`, `ListBlockedIPs`, `BlockIP`, `UnblockIP`, `GetIPReputation`, `GetActivityLogs`, `GetGeoAnalytics`, `GetTokenStats`, `StreamSecurityEvents` |
| Alerts | `ListAlertRules`, `CreateAlertRule`, `UpdateAlertRule`, `DeleteAlertRule`, `GetAlertHistory`, `AcknowledgeAlert` |
| Reports | `GenerateSecurityReport`, `GetReportStatus`, `DownloadReport` |
| Dashboard & audit | `GetDashboardStats`, `GetDashboardHealth`, `GetDashboardActivity`, `GetLoginTrends`, `GetAppUsage`, `ListAdminLogs`, `GetAdminLog`, `GetAdminActivity`, `ExportAdminLogs`, `GetAdminProfile`, `GetAdminStats` |
| Server settings | `GetServerConfig`, `TestDB`, `TestCache` |

---

### jwtauth

Validates RS256 JWTs issued by Socrate, caches JWKS public keys for 1 hour, and injects all Socrate claims into the request context. Stale keys are retained as a fallback when the JWKS endpoint is temporarily unreachable, so a Socrate restart does not immediately break live requests.

```go
auth := jwtauth.New(
    "https://auth.example.com/.well-known/jwks.json",
    "https://auth.example.com",
    logger,
)
r.Use(auth.Handler)

// Downstream handlers read claims without importing jwtauth:
tenantID := ctxutil.GetTenantID(r.Context()) // uuid.Nil if the token carried no tenant_id
plan     := ctxutil.GetUserPlan(r.Context()) // "freemium" when absent
```

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

**Gate** — HTTP middleware that rejects requests below a plan threshold with a structured JSON error:

```go
gate := tiering.NewGate(tiering.DefaultRegistry(), logger, "/billing")

r.With(gate.Require(tiering.PlanPro)).Post("/ai/narrate", handler)
// Freemium users receive 403 with the standard error envelope:
// {"error":{"code":"upgrade_required",
//           "message":"This feature requires the pro plan or above",
//           "details":{"plan":"freemium","requiredPlan":"pro","upgradeUrl":"/billing"}}}
```

**PolicyService** — per-feature rules stored in Postgres, cached in-process for 5 minutes. Implement `tiering.PolicyRepository` with your GORM repository to plug in persistence, then construct the service with `tiering.NewPolicyService(repo, registry, tiering.DefaultPlanSelector, logger)`. Every method takes a `context.Context` so cancellation and tracing propagate to the DB.

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

---

### aigateway

Normalises OpenAI and Anthropic Claude into a single `Call(ctx, prompt) (string, error)` interface. Provider-specific configuration is handled at construction time; callers are provider-agnostic.

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

Set `Config.AllowedModels` to restrict which Claude models may be used; a call with an out-of-list model returns an error. `Client.IsConfigured()` reports whether an API key is present (handy for feature-flagging AI endpoints), and `Client.Provider()` returns the configured provider name.

For tests, `aigateway.ClientForTest(provider, apiKey, serverURL)` points both provider base URLs at an `httptest.Server` so AI-dependent handlers can be exercised without a live API key.

---

### ainarration

A generic LRU+TTL cache for AI narration results, keyed by tenant and a content-addressed `CacheKey`. `NarrationCacher` is an interface — implement it with a DB-backed layer for persistence across restarts.

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

---

### pagination

Query-parameter parsing for `page` and `per_page`, with defaults and upper-bound clamping (`DefaultPerPage = 20`, `MaxPerPage = 100`). Returns a `PagedResponse` envelope for consistent list API shapes.

```go
params := pagination.Parse(r)   // reads ?page & ?per_page; page=1, perPage=20 by default
offset := params.Offset         // field (not a method): (page-1) * perPage

resp := pagination.NewPagedResponse(items, params, total) // (data, params, totalItems)
// {"data": [...], "page": 1, "perPage": 20, "totalItems": 142, "totalPages": 8}
```

---

### buildinfo

Exposes build-time metadata injected via `-ldflags` and a ready-to-mount version handler. The `Version`, `BuildTime`, and `GitCommit` package variables are link-time targets; they fall back to safe defaults (`Version = "dev"`) when unset.

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
// {"version":"v1.5.1","buildTime":"...","gitCommit":"a1b2c3d","goVersion":"go1.25"}
```

---

## Testing

Because every claim helper reads from `context.Context`, you can exercise gated handlers without minting real JWTs — just seed the context the way `jwtauth` would:

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

The AI gateway ships a test constructor so handlers that call a provider can run against an `httptest.Server` with no real API key:

```go
srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(`{"content":[{"type":"text","text":"hello"}]}`)) // mock Claude response
}))
defer srv.Close()

ai := aigateway.ClientForTest("claude", "test-key", srv.URL)
out, _ := ai.Call(context.Background(), "ping") // → "hello"
```

`ainarration.NarrationCache.Flush()` resets the cache between test cases, and each package ships runnable `Example*` functions (visible on [pkg.go.dev](https://pkg.go.dev/github.com/ovander/backendkit)) that double as living usage docs.

---

## Troubleshooting

| Symptom | Likely cause & fix |
|---------|--------------------|
| **Every request returns 401** | No `Authorization: Bearer <token>` header, an `iss` that doesn't match `SOCRATE_ISSUER`, or the JWKS URL is unreachable. Stale keys are reused on a *transient* fetch failure, but a wrong/empty JWKS URL fails closed. |
| **`GetTenantID` is `uuid.Nil` / `GetUserPlan` is always `"freemium"`** | `tenant_id` and `plan` are **custom** claims. A stock Socrate server does not emit them — configure Socrate to include them, or these helpers return their zero/default values by design. |
| **`GetUserEmail` / `GetUserName` are empty** | Email and name live in the **ID token**, not the access token. For access-token requests, fetch them via `socrate.Client.GetCurrentUserProfile`. |
| **Compile error passing a logger to `httpware.Logger`** | `Logger` takes the base `*logrus.Logger`; `Recover`, `NewRBAC`, `jwtauth.New`, and `tiering.NewGate` take a `*logrus.Entry`. See the [httpware](#httpware) note. |
| **Service-account call errors with "AppID must be set"** | Set `AppID` in `ClientConfig` (`SOCRATE_APP_ID`). The `/api/admin/apps` lookup needs a human-admin JWT, so a service token cannot resolve the app ID at runtime. |
| **Rate limiter never limits** | `RateLimiter` keys on the tenant UUID and lets requests through when none is present. Place `rl.Handler` **after** `auth.Handler` so `tenant_id` is already in context. |
| **`tiering.Gate` always allows / always denies** | The gate reads the plan from context (`ctxutil.GetUserPlan`); confirm auth runs before the gate and that your `PlanRegistry` contains the plan names you check. Unknown plans normalise to the lowest tier. |

---

## Production usage

backendkit is extracted from and actively used in production by:

- **Kerplan** — a multi-tenant enterprise SaaS platform. The full middleware stack, tiering, Socrate client, and aigateway packages are in use.
- **ParaShift** — a backend service using jwtauth, httpware, and gormlogger for structured observability.

The library follows a conservative compatibility policy: no breaking changes within a major version.

---

## Versioning

backendkit follows [Semantic Versioning](https://semver.org):

- **Patch** (`v1.x.y`) — bug fixes and non-breaking internal changes.
- **Minor** (`v1.x.0`) — new exported symbols, new packages, backward-compatible additions.
- **Major** (`v2.0.0`) — breaking changes to existing exported APIs. A new major version requires updating the import path (`github.com/ovander/backendkit/v2`).

Always pin an explicit version in `go.mod` rather than using `@latest` to keep builds reproducible.

---

## Contributing

**Local development** — after cloning:

```bash
go mod tidy          # resolve and pin all dependencies into go.sum
go test ./...        # run all tests
go test -race ./...  # race-detector pass
go vet ./...         # static analysis
```

**Guidelines:**

1. Add your package under its own directory with a package-level doc comment.
2. Write table-driven tests; place `_test.go` files in the same package directory.
3. Add runnable examples in `example_test.go` — they appear on pkg.go.dev.
4. All exported symbols must have Go doc comments that begin with the symbol name.
5. Run `go test -race ./...` and `go vet ./...` before opening a PR.
6. Keep packages decoupled — the only allowed cross-package imports within the library are `ctxutil` and `apierror` (shared primitives). All other cross-package imports are prohibited.
