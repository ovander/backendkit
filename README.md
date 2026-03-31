# backendkit

Shared Go library for backend services that use [Socrate](https://github.com/your-org/socrate) as their OAuth2 provider.

All packages are battle-tested — extracted from the Kerplan production backend and generalised for reuse across any Socrate-backed multi-tenant service.

[![Go Reference](https://pkg.go.dev/badge/github.com/ovander/backendkit.svg)](https://pkg.go.dev/github.com/ovander/backendkit)
[![CI](https://github.com/ovander/backendkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ovander/backendkit/actions/workflows/ci.yml)

---

## Getting started

```bash
go get github.com/ovander/backendkit@latest
```

```go
// go.mod
module github.com/your-org/my-service

require github.com/ovander/backendkit v0.1.0
```

---

## Packages

| Package | Purpose |
|---------|---------|
| [`apierror`](#apierror) | Structured HTTP error types (`AppError`, constructor functions) |
| [`pagination`](#pagination) | Query-param parsing and `PagedResponse` |
| [`ctxutil`](#ctxutil) | Typed context keys for Socrate claims (tenant, user, role, plan, logger, request-id) |
| [`httpware`](#httpware) | Chi-compatible middlewares: Timeout, BodyLimit, SecurityHeaders, Recover, RequestID, Logger, RateLimiter, RBAC |
| [`gormlogger`](#gormlogger) | GORM → logrus bridge with slow-query detection |
| [`socrate`](#socrate) | Full Socrate API client (user CRUD, service-account token, magic links) |
| [`jwtauth`](#jwtauth) | JWT RS256 validation middleware with JWKS cache and stale-key fallback |
| [`tiering`](#tiering) | Plan registry, tier gate middleware, feature policy model and service |
| [`aigateway`](#aigateway) | Multi-provider AI client (OpenAI + Claude), `ExtractJSON` |
| [`ainarration`](#ainarration) | Generic LRU+TTL narration cache and `CacheKey` helper |

---

## Architecture overview

A typical service wires the packages in three layers:

```
HTTP request
    │
    ▼
┌────────────────────────────────────────────┐
│  httpware middleware stack (chi router)     │
│  RequestID → Logger → SecurityHeaders →    │
│  Recover → Timeout → jwtauth → RateLimiter │
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

The following shows how to bootstrap a production chi router using the full middleware stack.

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
    log := logrus.WithField("service", "my-service")

    // 1. Auth middleware — validates RS256 JWT, injects claims into context.
    auth := jwtauth.New(
        os.Getenv("SOCRATE_JWKS_URL"),
        os.Getenv("SOCRATE_ISSUER"),
        log,
    )

    // 2. Per-tenant rate limiter — 20 rps sustained, burst of 40.
    rl := httpware.NewRateLimiter(20, 40)
    defer rl.Stop()

    // 3. Tier gate — uses the default freemium/pro/enterprise registry.
    gate := tiering.NewGate(tiering.DefaultRegistry(), log, "/settings/billing")

    r := chi.NewRouter()

    // Global middleware (runs before auth).
    r.Use(httpware.RequestID)
    r.Use(httpware.Logger(log))
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

Constructor functions for all common HTTP error shapes. Every constructor returns `*AppError` which implements `error` and writes itself as JSON.

```go
// In a handler:
user, err := repo.GetByID(id)
if errors.Is(err, gorm.ErrRecordNotFound) {
    apierror.NotFound("user", id).WriteJSON(w)
    return
}
apierror.Internal("database error").WriteJSON(w)
```

Available constructors: `NotFound`, `BadRequest`, `Unauthorized`, `Forbidden`, `Conflict`, `ValidationError`, `Internal`, `ServiceUnavailable`.

---

### ctxutil

All Socrate JWT claims injected by `jwtauth` are available through typed helpers. Every `Get*` function is safe to call even when the value is absent — they return zero values (or `"freemium"` for plan).

```go
tenantID, ok := ctxutil.GetTenantID(ctx)   // uuid.UUID
userID, ok   := ctxutil.GetUserID(ctx)     // uuid.UUID
role         := ctxutil.GetUserRole(ctx)   // string
plan         := ctxutil.GetUserPlan(ctx)   // string, default "freemium"
email        := ctxutil.GetUserEmail(ctx)
name         := ctxutil.GetUserName(ctx)
requestID    := ctxutil.GetRequestID(ctx)
logger       := ctxutil.GetLogger(ctx)     // *logrus.Entry, falls back to standard logger
```

---

### httpware

All middleware functions follow the standard `func(http.Handler) http.Handler` signature and are compatible with any `net/http`-based router.

| Middleware | Constructor |
|-----------|-------------|
| Request ID | `httpware.RequestID` |
| Structured logger | `httpware.Logger(entry)` |
| Security headers | `httpware.SecurityHeaders` |
| Body size limit | `httpware.BodyLimit(bytes)` |
| Panic recovery | `httpware.Recover(logger)` |
| Per-route timeout | `httpware.Timeout(d)` |
| Per-tenant rate limit | `httpware.NewRateLimiter(rps, burst)` |
| Role-based access | `httpware.NewRBAC(roleMap, logger)` |

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

**Nested timeouts:** `httpware.Timeout` strips the existing deadline before applying the new one, so inner routes can override the global default safely:

```go
r.Use(httpware.Timeout(10 * time.Second)) // global default

r.Group(func(r chi.Router) {
    r.Use(httpware.Timeout(120 * time.Second)) // safe: replaces the 10 s deadline
    r.Post("/export/pdf", exportPDF)
})
```

---

### gormlogger

Bridges GORM's internal logger to logrus. Slow queries are logged at Warn; `ErrRecordNotFound` is suppressed to Debug so it doesn't pollute production logs.

```go
db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
    Logger: gormlogger.New(
        log.WithField("component", "db"),
        gormlogger.Config{
            SlowThreshold:  200 * time.Millisecond,
            IgnoreNotFound: true,
        },
    ),
})
```

---

### socrate

The client uses a dual-auth strategy. User-scoped calls forward the caller's JWT; service-account calls acquire a `client_credentials` token automatically and cache it until near-expiry.

> **⚠️ `AppID` is required for all service-account methods.**
> Service-account tokens carry `sub=app:{id}` and cannot authenticate against
> the admin-user routes that would normally resolve the app ID at runtime.
> Always set `AppID` in `ClientConfig`; omitting it causes an immediate error
> on the first service-account call (`InviteUserAsService`, `RegisterUser`,
> `GetUserAsService`, `SendMagicLink`).

```go
client, err := socrate.NewClient(socrate.ClientConfig{
    BaseURL:      os.Getenv("SOCRATE_BASE_URL"),
    ClientID:     os.Getenv("SOCRATE_CLIENT_ID"),
    ClientSecret: os.Getenv("SOCRATE_CLIENT_SECRET"),
    AppID:        os.Getenv("SOCRATE_APP_ID"), // required for service-account calls
})

// User-scoped — store the JWT first:
ctx = socrate.WithJWT(ctx, rawJWT) // raw token from jwtauth context
users, err := client.ListUsers(ctx, "", 1, 20)
user, err  := client.GetUser(ctx, userID)

// Service-account — token acquired automatically:
err = client.InviteUserAsService(ctx, socrate.ServiceInviteRequest{
    Email: "new@example.com",
    Role:  "editor",
})

// Conflict handling:
if errors.Is(err, socrate.ErrUserAlreadyExists) {
    // handle duplicate registration
}
```

**Magic-link (passwordless) authentication**

Only the app backend may trigger magic-link emails — end users cannot call this endpoint directly. `SendMagicLink` uses the service-account token and hits the M2M-only route on the Admin port (`POST /api/apps/{id}/service/magic-link`).

```go
// Trigger a passwordless login email from your backend (e.g. when the user
// clicks "send me a login link" on your frontend).
resp, err := client.SendMagicLink(ctx, "user@example.com")
if err != nil {
    if errors.Is(err, socrate.ErrMagicLinkRateLimited) {
        // per-address limit: 5 requests / hour per email + app pair
    }
    return err
}
// resp.Message is always the same opaque string (enumeration resistance).
//
// resp.MagicURL is non-empty in development mode only.
// Its format is: {issuer}/api/auth/magic-link/verify?token=<raw>&client_id=<id>
// The verify endpoint is POST-only (GET would let email scanners consume the
// single-use token before the user clicks). Your frontend must read the
// ?token= and ?client_id= query parameters from the clicked URL and POST them:
//
//   POST /api/auth/magic-link/verify
//   {"token": "<raw>", "client_id": "<client_id>"}
//
// On success Socrate returns the same token set as a normal login
// (access_token, refresh_token, id_token).
```

---

### jwtauth

Validates RS256 JWTs, caches JWKS keys for 1 hour, and injects all Socrate claims into the request context. Stale keys are retained as fallback when the JWKS endpoint is temporarily unreachable.

```go
auth := jwtauth.New(
    "https://auth.example.com/.well-known/jwks.json",
    "https://auth.example.com",
    logger,
)
r.Use(auth.Handler)

// Downstream handlers read claims without importing jwtauth:
tenantID, _ := ctxutil.GetTenantID(r.Context())
plan        := ctxutil.GetUserPlan(r.Context())
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

**Gate** — HTTP middleware that blocks requests below a plan threshold:

```go
gate := tiering.NewGate(tiering.DefaultRegistry(), logger, "/billing")

r.With(gate.Require(tiering.PlanPro)).Post("/ai/narrate", handler)
// Freemium users receive 403 with {"error":"plan_required","upgradeUrl":"/billing"}
```

**PolicyService** — per-feature rules stored in Postgres, cached in-process for 5 minutes:

```go
// Seed baseline rules at startup:
svc.SeedDefaults([]tiering.FeaturePolicy{
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
allowed := svc.IsAllowed("ai_narration", plan)
limit   := svc.NumericLimit("export_limit", plan)
```

Implement `tiering.PolicyRepository` with your GORM repository to plug in persistence.

---

### aigateway

Normalises OpenAI and Anthropic Claude into a single `Call(ctx, prompt) (string, error)` interface.

```go
ai := aigateway.New(aigateway.Config{
    Provider:   "claude",  // "claude" or "openai"
    APIKey:     os.Getenv("ANTHROPIC_API_KEY"),
    Model:      "claude-sonnet-4-6",
    MaxTokens:  2000,
    TimeoutSec: 30,
}, logger)

result, err := ai.Call(ctx, prompt)

// Parse JSON embedded in an AI prose response:
var data MyStruct
err = aigateway.ExtractJSONInto(result, &data)
```

For tests, `aigateway.ClientForTest(provider, apiKey, serverURL)` points both base URLs at an `httptest.Server` so AI-dependent handlers can be tested without a live API key.

---

### ainarration

A generic LRU+TTL cache for AI narration results. `NarrationCacher` is an interface — implement it with a DB-backed layer for persistence across restarts.

```go
cache := ainarration.NewNarrationCache(ainarration.DefaultCacheConfig())
// DefaultCacheConfig: capacity=1000, TTL=15min

// Content-addressed key — same inputs always produce the same key:
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

## First-time setup after cloning

```bash
go mod tidy          # resolve and pin all dependencies into go.sum
go test ./...        # run all tests
go test -race ./...  # race-detector pass
go vet ./...         # static analysis
```

---

## Contributing

1. Add your package under its own directory with a package-level doc comment.
2. Write table-driven tests; place `_test.go` files in the same package directory.
3. Add runnable examples in `example_test.go` — they appear on pkg.go.dev.
4. All exported symbols must have Go doc comments that begin with the symbol name.
5. Run `go test -race ./...` and `go vet ./...` before opening a PR.
6. Keep packages decoupled — the only allowed cross-package imports within the library are: anything may import `ctxutil` and `apierror` (shared primitives). All other cross-package imports are prohibited.
