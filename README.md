# backendkit

Shared Go library for backend services that use [Socrate](https://github.com/your-org/socrate) as their OAuth2 provider.

All packages are battle-tested — extracted verbatim from the Kerplan production backend and generalised for reuse.

---

## Getting started

```bash
go get github.com/ovander/backendkit@latest
```

Then replace the module path placeholders in your new project's `go.mod`:

```go
module github.com/your-org/my-new-backend

require github.com/ovander/backendkit v0.1.0
```

---

## Packages

| Package | Purpose |
|---------|---------|
| `apierror` | Structured HTTP error types (`AppError`, `WriteJSON`) |
| `pagination` | Query-param parsing and `PagedResponse` |
| `ctxutil` | Typed context keys for Socrate claims (tenant, user, role, plan, logger, request-id) |
| `httpware` | Chi-compatible middlewares: Timeout, BodyLimit, SecurityHeaders, Recover, RequestID, Logger, RateLimiter, RBAC |
| `gormlogger` | GORM → logrus bridge |
| `socrate` | Full Socrate API client (user CRUD, service-account token, magic links, activity logs) |
| `jwtauth` | JWT RS256 validation middleware with JWKS cache |
| `tiering` | Plan registry, tier gate middleware, feature policy model and service |
| `aigateway` | Multi-provider AI client (OpenAI + Claude), `ExtractJSON` |
| `ainarration` | Generic LRU+TTL narration cache and `CacheKey` helper |

---

## Quick examples

### Auth + rate limiting (chi router)

```go
import (
    "github.com/go-chi/chi/v5"
    "github.com/ovander/backendkit/httpware"
    "github.com/ovander/backendkit/jwtauth"
    "github.com/ovander/backendkit/tiering"
)

auth := jwtauth.New(cfg.JWKSEndpoint, cfg.Issuer, logger)
rl   := httpware.NewRateLimiter(20, 40)      // 20 rps, burst 40
gate := tiering.NewGate(tiering.DefaultRegistry(), logger, "/settings/billing")

r := chi.NewRouter()
r.Use(httpware.RequestID)
r.Use(httpware.Logger(baseLogger))
r.Use(httpware.SecurityHeaders)
r.Use(httpware.Recover(baseLogger))
r.Use(auth.Handler)
r.Use(rl.Handler)

r.Group(func(r chi.Router) {
    r.Use(gate.Require(tiering.PlanPro))
    r.Post("/ai/narrate", narrateHandler)
})
```

### Socrate client

```go
client, _ := socrate.NewClient(socrate.ClientConfig{
    BaseURL:      "https://auth.example.com",
    ClientID:     os.Getenv("SOCRATE_CLIENT_ID"),
    ClientSecret: os.Getenv("SOCRATE_CLIENT_SECRET"),
    AppID:        os.Getenv("SOCRATE_APP_ID"),
})

// List users (forwards caller's JWT):
ctx = socrate.WithJWT(ctx, rawJWT)
users, err := client.ListUsers(ctx, "", 1, 20)

// Invite user (uses service-account token automatically):
resp, err := client.InviteUserAsService(ctx, socrate.ServiceInviteRequest{
    Email: "new@example.com",
    Role:  "editor",
})
```

### AI gateway

```go
ai := aigateway.New(aigateway.Config{
    Provider:   "claude",
    APIKey:     os.Getenv("ANTHROPIC_API_KEY"),
    Model:      "claude-sonnet-4-6",
    MaxTokens:  2000,
    TimeoutSec: 30,
}, logger)

result, err := ai.Call(ctx, prompt)
```

### Narration cache

```go
cache := ainarration.NewNarrationCache(ainarration.DefaultCacheConfig())

key := ainarration.CacheKey("plan_narration", userRole, myContext)
if out, ok := cache.Get(tenantID, key); ok {
    return out // cached
}
// … call AI …
cache.Put(tenantID, key, &ainarration.NarrationOutput{Narrative: text})
```

---

## First-time setup after cloning

```bash
go mod tidy        # resolves and pins all dependencies into go.sum
go test ./...      # run all tests
go vet ./...       # static analysis
```

---

## Contributing

1. Add your package under its own directory.
2. Write table-driven tests with `*_test.go` files in the same package directory.
3. Run `go test -race ./...` before opening a PR.
4. All exported symbols need Go doc comments.
