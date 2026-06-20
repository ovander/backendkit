# Fifth Pass — Framework Evolution Review (backendkit → v2.0 and beyond)

**Subject:** `github.com/ovander/backendkit` (single module, Go 1.25, commit `46105b1`)
**Lens:** Principal engineer preparing a v2.0 and a five-year roadmap.
**Scope:** long-term framework quality only. No security-defect hunting; security
findings from `SECURITY-AUDIT.md` / `SECURITY-ARCHITECTURE.md` are referenced only
where they shape an API decision.
**Deliverable:** RFC-style proposals, each with Motivation, Current design,
Proposed design, Migration, Backward compatibility, Breaking changes, Risk,
Effort, Expected benefits.

> **Status note (post v1.8.0, 2026-06-20).** The RFCs below (slog, module split,
> auth/authz abstraction, …) are **still all open** — v1.8.0 was a *security
> hardening* release, not a structural one. The one overlap: RFC-003's intent that
> "audience/revocation become first-class options" was partly down-paid by the
> opt-in `jwtauth.WithAudience` (#7) and `jwtauth.WithRevocationCheck` (#17),
> which are option-shaped seams the future `TokenVerifier`/`RevocationChecker`
> interfaces can absorb. No RFC here is yet implemented.

---

## North-Star Thesis

backendkit today is a **Socrate-coupled, logrus-coupled, single-module toolkit**.
Every concrete strength it has — clean middleware, typed context, fail-closed
gates — is wrapped around two hard assumptions that a general framework cannot
make: *"the IdP is Socrate"* and *"the logger is logrus."* The v2.0 program is, in
one sentence: **turn the concrete toolkit into a set of small interfaces with
Socrate/logrus/gorm as the default adapters, split along module lines so a
consumer pays only for what it imports.**

The RFCs below are ordered by leverage. RFC-001 and RFC-002 are foundational;
the rest depend on them.

---

## RFC Index

| RFC | Title | Tier | Breaking? |
|-----|-------|------|-----------|
| 001 | Logging abstraction: adopt `log/slog`, drop the logrus dependency | Foundational | Yes (v2) |
| 002 | Module decomposition: core vs. integration modules | Foundational | Yes (import paths) |
| 003 | Authentication abstraction: `TokenVerifier` / `ClaimsMapper` / `Principal` | Core | Yes (v2) |
| 004 | Authorization abstraction: `Authorizer` interface + object-level/ABAC | Core | Additive→default-flip |
| 005 | Identity & context: generic typed context, drop Socrate-specific keys | Core | Yes (v2) |
| 006 | Middleware composition: a router-agnostic `Chain`/`Stack` | Core | Additive |
| 007 | Configuration model: functional options + `Validate()` everywhere | Core | Additive→default-flip |
| 008 | Generics: pagination, response envelopes, typed handlers, context store | Quality | Additive |
| 009 | Event system: security/audit event bus with observers | Capability | Additive |
| 010 | Observability: slog + OpenTelemetry traces & metrics | Capability | Additive |
| 011 | Pluggable stores: rate-limit / JWKS / audit-sink interfaces | Extensibility | Additive |
| 012 | Testing infrastructure: doubles, fixtures, conformance suite | Quality | Additive |
| 013 | SemVer, deprecation & release governance | Process | n/a |

---

## RFC-001 — Logging abstraction (`log/slog`)

**Motivation.** logrus is in maintenance mode and is a *hard, transitive*
dependency forced on every consumer. The framework leaks it through public
signatures (`jwtauth.New(..., *logrus.Entry)` `middleware.go:92`;
`httpware.Logger(*logrus.Logger)` `logger.go:31`; `Recover(*logrus.Entry)`
`recover.go:14`; `ctxutil` imports logrus `context.go:17`; `tiering`, `aigateway`,
`gormlogger`, `socrate` all the same). A consumer standardised on zap or slog
cannot use backendkit without dragging in logrus.

**Current design.** logrus types appear in 9+ exported signatures and in
`ctxutil.GetLogger`/`WithLogger` (`context.go:204-218`). The logger *is* the
public contract.

**Proposed design.** Depend only on the standard library `log/slog` (`*slog.Logger`).
Every signature that takes `*logrus.Entry`/`*logrus.Logger` takes `*slog.Logger`.
`ctxutil` stores/returns `*slog.Logger`. Ship `backendkit/adapters/logrusslog`
(a `slog.Handler` that writes to an existing logrus pipeline) so teams still on
logrus lose nothing.

**Migration.** v1.x: add `*slog.Logger`-accepting variants (`jwtauth.NewWithSlog`,
etc.) alongside the logrus ones; mark logrus variants `// Deprecated`. v2.0: remove
logrus variants; provide the logrus→slog adapter.

**Backward compatibility.** Source-breaking at v2 only; the v1.x window gives a
no-rush path and the adapter preserves output formatting.

**Breaking changes.** All logger parameter types change at v2.

**Risk.** Low-medium. slog field semantics differ slightly from logrus
`WithField`; mitigated by the adapter and a field-mapping doc.

**Effort.** M (≈1–2 weeks). Mechanical across packages + one adapter + tests.

**Expected benefits.** Zero forced logging dependency; std-lib idiom; smaller
dependency graph; instant compatibility with any `slog.Handler` (zap, zerolog,
OTel logs).

---

## RFC-002 — Module decomposition

**Motivation.** One module means importing `apierror` (190 LoC, zero deps)
transitively offers `gorm`, `golang-jwt`, `x/time`, and `logrus` to the build
graph. The "core" primitives and the "integration" clients have wildly different
dependency footprints and release cadences.

**Current design.** Single `go.mod` (`module github.com/ovander/backendkit`) with
gorm + jwt + logrus + uuid + x/time as direct deps, consumed wholesale.

**Proposed design.** Split into a small set of modules under one repo
(multi-module repo + `go.work` for development):

```
backendkit/                      (core; std-lib + uuid only)
  apierror  ctxutil  httpware  pagination  buildinfo
backendkit/auth                  (golang-jwt)        — jwtauth, authz interfaces
backendkit/tiering               (gorm)
backendkit/integrations/socrate  (Socrate adapter)
backendkit/integrations/gorm     (gormlogger)
backendkit/integrations/ai       (aigateway)
backendkit/otel                  (OTel adapters, RFC-010)
```

Core depends on nothing heavy; each integration pulls only its own client.

**Migration.** Import paths change per moved package; provide a `go fix`-style
sed map and a `MIGRATION.md`. Tag all modules in lock-step for v2.0.0.

**Backward compatibility.** Import paths break (the only mechanical break in this
RFC). Behaviour unchanged.

**Breaking changes.** New import paths for everything outside core.

**Risk.** Medium — multi-module versioning discipline (each module needs its own
tag `auth/v2.0.0`, etc.); CI must build the workspace.

**Effort.** M-L (≈2–3 weeks incl. CI/release retooling).

**Expected benefits.** `import apierror` costs nothing; gorm/jwt only where used;
independent release cadence; clearer ownership; smaller blast radius per CVE.

---

## RFC-003 — Authentication abstraction

**Motivation.** `jwtauth` is hardwired to Socrate: `SocrateClaims`
(`middleware.go:45-60`), RS256-only, JWKS-only, Socrate's `sub`/`role`/`plan`/
`app_roles` semantics baked into the middleware body (`middleware.go:120-169`). A
framework must support other IdPs (Auth0, Cognito, Keycloak, Okta), opaque-token
introspection, and HS/ES algorithms — and, per the security pass, **audience and
revocation** belong at this seam.

**Current design.** One concrete `*Middleware` struct doing extraction +
verification + Socrate claim→context mapping in a single method.

**Proposed design.** Decompose into interfaces:

```go
type Principal interface {                 // replaces scattered ctx getters
    Subject() string
    Tenant() (uuid.UUID, bool)
    Roles() []string
    Claim(name string) (any, bool)
}
type TokenVerifier interface {             // verification only
    Verify(ctx context.Context, raw string) (Claims, error)
}
type ClaimsMapper interface {              // claims → Principal (IdP-specific)
    Map(Claims) (Principal, error)
}
type RevocationChecker interface{ Live(context.Context, Claims) (bool, error) }
```

`auth.Middleware(verifier, mapper, opts...)` composes them. Ship:
`jwks.RS256Verifier` (today's logic, plus required `aud`/min-key-size hooks),
`introspect.Verifier` (RFC 7662), and `socrate.Mapper` (the current Socrate
semantics, now an *adapter*, not the core).

**Migration.** v1.x: add the interfaces and a `socrate.Mapper` that reproduces
current behaviour; `jwtauth.New` delegates to them internally (no behaviour
change). v2.0: `jwtauth.New` is deprecated in favour of `auth.Middleware`.

**Backward compatibility.** Fully preserved through v1.x via the Socrate adapter.

**Breaking changes.** v2 removes the Socrate-specific exported claim struct from
core auth; it lives in the Socrate integration module.

**Risk.** Medium — the seam must not regress the (correct) alg-pinning at
`middleware.go:193,199-201`; conformance tests (RFC-012) guard this.

**Effort.** L (≈3–4 weeks).

**Expected benefits.** Multi-IdP support; audience/revocation become first-class
options; verifier and mapper independently testable and swappable.

---

## RFC-004 — Authorization abstraction

**Motivation.** Authorization today is a flat role→permission map
(`RoleMap`/`hasPermission` `rbac.go:25,57-67`) and a plan tier (`tiering`). There
is no object-level / ownership / ABAC seam, and authz is opt-in per route. A
framework needs a single `Authorizer` contract that RBAC, plan-gating, and
object-level checks all implement and that can be *composed*.

**Current design.** `RBAC.Require(perm)` and `Gate.Require(plan)` are two separate
concrete middlewares reading two separate context values.

**Proposed design.**

```go
type Decision int // Allow, Deny, Abstain
type Authorizer interface {
    Authorize(ctx context.Context, p Principal, req Request) (Decision, error)
}
// Combinators:
func All(...Authorizer) Authorizer   // AND
func Any(...Authorizer) Authorizer   // OR
func Require(Authorizer) Middleware  // 403 on Deny/Abstain (fail-closed)
```

`rbac.New(roleMap)`, `tiering.PlanGate(reg)`, and a new
`obj.OwnerOf(func(ctx) (ownerID, error))` all return `Authorizer`. Object-level
authz (the OWASP API1/BOLA gap) finally has a home.

**Migration.** v1.x: introduce `Authorizer`; make existing `RBAC`/`Gate` implement
it while keeping their current `Require` methods. v2.0: unify under
`authz.Require`.

**Backward compatibility.** Existing `RBAC.Require`/`Gate.Require` keep working
through v1.x and can remain as thin wrappers in v2.

**Breaking changes.** None required until a v2 cleanup that collapses duplicate
middleware.

**Risk.** Low-medium. Combinator semantics (Abstain vs Deny) must be specified
precisely; default is fail-closed.

**Effort.** M (≈2–3 weeks).

**Expected benefits.** Composable, testable authz; object-level support; one
mental model for role, plan, and ownership checks.

---

## RFC-005 — Identity & context (generics)

**Motivation.** `ctxutil` hardcodes a fixed, Socrate-shaped set of keys
(`tenantIDKey`…`rawJWTKey` `context.go:26-39`) with one bespoke getter/setter
pair each (≈12 pairs). Adding a claim means editing the core package. The
`GetUserPlan→"freemium"` default (`context.go:101-106`) bakes a business default
into a generic library.

**Current design.** ~250 lines of near-identical `With*/Get*` helpers over
unexported string keys.

**Proposed design.** A generic typed-context primitive plus a `Principal` stored
once:

```go
type Key[T any] struct{ name string }
func NewKey[T any](name string) Key[T]
func With[T any](ctx context.Context, k Key[T], v T) context.Context
func Value[T any](ctx context.Context, k Key[T]) (T, bool)
```

Core ships `ctxauth.PrincipalKey` and `ctxobs.LoggerKey`/`RequestIDKey`.
Socrate-specific plan/role defaults move to the Socrate adapter.

**Migration.** v1.x: implement the existing `With*/Get*` on top of the generic
primitive (no API change). v2.0: keep the common getters as convenience wrappers;
move plan/role business defaults out of core.

**Backward compatibility.** Source-preserving in v1.x; the deprecated-alias model
already in `context.go:235-247` is the template.

**Breaking changes.** v2 relocates the "freemium" default and Socrate keys to the
adapter.

**Risk.** Low. Generic context keys are a well-trodden pattern.

**Effort.** S-M (≈1 week).

**Expected benefits.** Extensible without editing core; type-safe; no business
defaults in a generic library; ~60% less boilerplate.

---

## RFC-006 — Middleware composition

**Motivation.** The framework relies on chi's `r.Use` for ordering and documents a
required order in prose (`README.md:177-179`) — an unenforced convention.
Mis-ordering (e.g. Recover after auth) is a silent footgun. There is no
first-class, router-agnostic composition primitive.

**Current design.** Each middleware is `func(http.Handler) http.Handler`
(`README.md:342`); composition is the consumer's `r.Use(...)` calls.

**Proposed design.** A tiny `Chain` with an opinionated, validated default stack:

```go
type Chain []func(http.Handler) http.Handler
func (c Chain) Then(http.Handler) http.Handler
func (c Chain) Append(...) Chain
func RecommendedStack(opts StackOptions) Chain // RequestID→…→auth→authz, ordered correctly
```

`RecommendedStack` encodes the security-correct order once, so consumers get
defense-in-depth ordering for free and can still drop down to raw functions.

**Migration.** Purely additive; existing `r.Use` usage unaffected.

**Backward compatibility.** Full.

**Breaking changes.** None.

**Risk.** Very low.

**Effort.** S (≈3–5 days).

**Expected benefits.** Ordering becomes code, not docs; one-line correct stack;
still router-agnostic (works with chi, stdlib `http.ServeMux`, Gin via shim).

---

## RFC-007 — Configuration model

**Motivation.** Constructors are inconsistent: positional
(`jwtauth.New(jwksURL, issuer, logger)` `middleware.go:92`,
`tiering.NewGate(registry, logger, upgradeURL)` `gate.go:34`) vs. config structs
(`socrate.ClientConfig` `client.go:71`, `aigateway.Config` `client.go:34`). None
fail-fast on insecure/invalid config (e.g. empty issuer is silently accepted).

**Current design.** Mixed positional/struct constructors, no `Validate()`.

**Proposed design.** Standardise on **functional options + a `Validate()` that
refuses insecure boot**:

```go
m, err := auth.New(verifier,
    auth.WithAudience(clientID),     // required by default in v2
    auth.WithIssuer(iss),
    auth.WithLogger(slogger),
)                                    // returns error; validates
```

Every constructor returns `(_, error)` and validates. Provide `MustNew` for tests.

**Migration.** v1.x: add option-based constructors next to existing ones;
`Validate()` warns. v2.0: positional constructors removed; `Validate()` errors.

**Backward compatibility.** Preserved through v1.x.

**Breaking changes.** Constructor signatures at v2; `New` returns an error where it
previously could not.

**Risk.** Low-medium; the value is partly in *failing closed at startup*, which is
intentional friction.

**Effort.** M (≈1.5 weeks).

**Expected benefits.** One idiom; safe-by-default boot; forward-compatible option
addition without signature churn.

---

## RFC-008 — Generics

**Motivation.** The codebase predates/avoids generics; several APIs hand back
`any`/untyped shapes. Go 1.25 generics enable type-safe pagination, response
envelopes, and handlers with no runtime cost.

**Current design.** `pagination` returns concrete page math; `apierror.Details` is
`any` (`errors.go:17`); handlers decode/encode by hand.

**Proposed design.**
- `pagination.Page[T any]` — typed page envelope.
- `apierror.Problem[T any]` — typed `details`.
- `web.JSON[Req, Res any](fn func(ctx, Req) (Res, error)) http.HandlerFunc` —
  decode→validate→call→encode, routing errors through `apierror` consistently.
- `ctxutil` generic keys (RFC-005).

**Migration.** Additive new generic APIs; legacy helpers retained and deprecated.

**Backward compatibility.** Full (new symbols).

**Breaking changes.** None.

**Risk.** Low. Avoid over-generifying (no generic "service" base classes).

**Effort.** M (≈2 weeks).

**Expected benefits.** Less per-handler boilerplate; compile-time safety on
request/response shapes; consistent error envelope.

---

## RFC-009 — Event system

**Motivation.** There is no hook for security/audit events — auth success/failure,
authz denial, rate-limit trip, panic. The security pass flagged the absence of a
native audit writer (INV-14). An in-process event bus is the clean seam that feeds
audit sinks, metrics, and alerting without coupling middleware to any of them.

**Current design.** Each middleware logs directly via logrus
(`rbac.go:46`, `ratelimit.go` 429 path, `recover.go:19`); no structured event,
no subscription.

**Proposed design.** A typed, synchronous-by-default event hub:

```go
type Event struct { Type EventType; Principal Principal; At time.Time; Attrs map[string]any }
type Observer interface{ Observe(context.Context, Event) }
type Bus struct{ ... }   // Subscribe(EventType, Observer); thread-safe; non-blocking option
```

Middlewares emit `AuthFailed`, `AuthzDenied`, `RateLimited`, `PanicRecovered`.
Ship observers: `slogObserver`, `otelObserver` (RFC-010), `AuditSink` adapter
(RFC-011).

**Migration.** Additive; default bus is a no-op so existing behaviour is unchanged
until a consumer subscribes.

**Backward compatibility.** Full.

**Breaking changes.** None.

**Risk.** Medium — must not become a hot-path bottleneck; default synchronous with
an explicit async/bounded-buffer mode, and observers must be panic-isolated.

**Effort.** M (≈2 weeks).

**Expected benefits.** First-class audit/alerting seam; decouples policy from
sink; enables SOC2/ISO audit-trail story without baking a writer into core.

---

## RFC-010 — Observability (slog + OpenTelemetry)

**Motivation.** Today: logrus lines only. No tracing, no metrics. `RequestID`
generates a UUID unrelated to W3C trace context (`requestid.go:19-24`). Enterprise
adopters expect OTel traces/metrics out of the box.

**Current design.** `httpware.Logger` emits one completion line
(`logger.go:46-49`); `RequestID` is a bespoke correlation id.

**Proposed design.** `backendkit/otel` module: middleware that starts a server
span, propagates W3C `traceparent`, makes `RequestID` derive from / fall back to
the trace ID, and records RED metrics (rate/errors/duration) plus auth/authz
counters fed by the RFC-009 bus. Logging via slog with trace/span IDs auto-injected.

**Migration.** Additive opt-in module; core stays dependency-light (OTel lives only
in the `otel` module, consistent with RFC-002).

**Backward compatibility.** Full.

**Breaking changes.** None (RequestID semantics enrich, not change).

**Risk.** Low-medium; OTel API churn is mitigated by isolating it in one module.

**Effort.** M-L (≈2–3 weeks).

**Expected benefits.** Drop-in distributed tracing and metrics; correlation ties
logs↔traces↔events; competitive parity with Kratos/go-kit observability.

---

## RFC-011 — Pluggable stores (extension points)

**Motivation.** Stateful pieces are hardcoded to in-process maps: the rate limiter
is an in-memory `map[uuid.UUID]*tenantLimiter` (`ratelimit.go:43`) — wrong for
multi-instance (security pass F-4); the JWKS cache is an in-struct map
(`middleware.go:86`); there is no audit sink. These need interfaces with the
in-memory version as the default adapter.

**Current design.** Concrete in-memory state inside each middleware; `tiering`
already shows the right pattern with `PolicyRepository` (`policy.go:63`).

**Proposed design.** Define and depend on interfaces:

```go
type RateStore interface { Allow(ctx, key string, limit Rate) (bool, error) }
type KeySetCache interface { Get(kid string) (crypto.PublicKey, bool); Put(...) }
type AuditSink   interface { Write(ctx, Event) error }
```

Ship `memory.RateStore` (today's behaviour) and `redis.RateStore` (new module).
Rate limiter keys on a pluggable `KeyFunc` (tenant→subject→IP fallback), fixing
the nil-tenant bypass at the architecture level.

**Migration.** v1.x: add interfaces, default to current in-memory impls. v2.0:
constructors take a store option.

**Backward compatibility.** Preserved via default in-memory adapters.

**Breaking changes.** Constructor options at v2.

**Risk.** Low-medium; interface must cover atomic check-and-decrement for
distributed correctness.

**Effort.** M (≈2 weeks core + per-backend adapters).

**Expected benefits.** Horizontal-scale-correct rate limiting; swappable JWKS
cache; pluggable durable audit — the operational gaps closed by extension, not
fork.

---

## RFC-012 — Testing infrastructure

**Motivation.** Tests exist but are thin on the security-critical negative paths
(`jwtauth/middleware_test.go` covers valid/missing/tampered only) and there is no
public test-support surface for *consumers* to test their wiring.

**Current design.** Per-package `_test.go`; private test helpers (e.g.
`aigateway.ClientForTest` `client.go:254`).

**Proposed design.**
- `backendkit/.../authtest`: token mint/sign helpers, fake JWKS server, a fake
  `Principal`, and context-injection helpers so apps can unit-test handlers
  without a live IdP.
- A **conformance suite**: a table-driven `VerifierConformance(t, v)` /
  `AuthorizerConformance(t, a)` any adapter must pass (alg-pinning, aud, expiry,
  fail-closed) — locks the invariants from the architecture pass.
- Golden-file helpers for `apierror` envelopes.

**Migration.** Additive new packages.

**Backward compatibility.** Full.

**Breaking changes.** None.

**Risk.** Very low.

**Effort.** M (≈1.5–2 weeks).

**Expected benefits.** Third-party adapters provably correct; consumer apps get
turnkey test doubles; the security invariants become executable and
non-regressing.

---

## RFC-013 — SemVer, deprecation & release governance

**Motivation.** The repo already practices deprecation discipline
(`ctxutil.go:235-247`) but has no written policy, and a multi-module v2 (RFC-002)
needs explicit governance.

**Current design.** Ad-hoc tags; README references v1.7.0; deprecation by doc
comment only.

**Proposed design.**
- Written **compatibility policy**: exported API stable within a major; `//
  Deprecated:` required one minor before removal; security-default flips only at
  majors and pre-announced.
- **Per-module SemVer** with synchronized majors (`core/v2`, `auth/v2`, …) and a
  release matrix in CI.
- Tooling: `deprecated`/`staticcheck` lint gate (already have golangci
  `.golangci.yml`), `apidiff` in CI to flag accidental breaks, a `CHANGELOG.md`
  and `MIGRATION.md` per major.
- Support window: latest major fully supported, previous major security-only for
  12 months.

**Migration.** Process change; no code impact.

**Backward compatibility.** This RFC *is* the backward-compatibility guarantee.

**Breaking changes.** None.

**Risk.** Low; cost is ongoing discipline.

**Effort.** S ongoing.

**Expected benefits.** Predictable upgrades; `apidiff` prevents silent breaks;
clear support contract for enterprise adopters.

---

## Five-Year Sequencing

| Horizon | Theme | RFCs |
|---------|-------|------|
| **v1.x (0–6 mo)** | Seams in, defaults unchanged | 001, 003, 004, 005, 006, 007, 011 (all additive: interfaces + adapters land, old APIs deprecated) |
| **v2.0 (6–12 mo)** | Decompose + flip safe defaults | 002 (modules), remove logrus, audience/issuer/store required, governance 013 |
| **v2.x (1–2 yr)** | Capabilities | 008 (generics), 009 (events), 010 (OTel), 012 (conformance) |
| **v3 (3–5 yr)** | Ecosystem | adapter zoo (Auth0/Cognito/Keycloak verifiers, Redis/Dynamo stores, OTel-native), optional transport beyond `net/http` (gRPC interceptors mirroring the HTTP middleware) |

---

## Final Answer

> **If backendkit were to compete with Gin/Echo middleware, go-kit, or Kratos,
> what architectural changes would make it a first-class reusable Go framework?**

backendkit is currently a *very good internal toolkit* and a *not-yet* general
framework, for one root reason visible throughout the code: **it hardcodes its two
most replaceable dependencies — the identity provider (Socrate) and the logger
(logrus) — into its public API.** `SocrateClaims` lives in the auth middleware
(`middleware.go:45-60`); `*logrus.Entry`/`*logrus.Logger` are in nearly every
constructor (`middleware.go:92`, `logger.go:31`, `recover.go:14`, `gate.go:34`,
`aigateway client.go:66`). No competitor could adopt it without adopting Socrate
and logrus. That, not any single feature gap, is what disqualifies it today.

The changes required, in priority order:

1. **Invert the IdP and logger dependencies (RFC-001, 003, 005).** Replace
   `*logrus.*` with `*slog.Logger`, and replace `SocrateClaims`-in-core with
   `TokenVerifier`/`ClaimsMapper`/`Principal` interfaces, with Socrate demoted to
   an *adapter*. This is the single highest-leverage change and the price of entry
   to "framework."
2. **Decompose the module (RFC-002).** Gin/Echo win partly because importing them
   is cheap; a framework whose `apierror` package transitively pulls gorm and jwt
   cannot compete. Core must be std-lib-plus-uuid; integrations pay their own way.
3. **Make authorization composable and object-level-capable (RFC-004).** go-kit
   and Kratos expose authz as pluggable; a flat role map is not enough. An
   `Authorizer` interface with `All`/`Any` combinators and an ownership seam is
   table stakes.
4. **Pluggable stateful stores (RFC-011).** In-memory rate limiting
   (`ratelimit.go:43`) is fine for one binary; a framework must offer a
   `RateStore` with a Redis adapter, or it is unusable at scale.
5. **First-class observability (RFC-010) and an event/audit seam (RFC-009).**
   Kratos/go-kit ship OTel and middleware hooks; parity requires traces, RED
   metrics, and an event bus that audit sinks subscribe to.
6. **A configuration idiom and a conformance test kit (RFC-007, 012).** Functional
   options with fail-closed `Validate()`, plus a published conformance suite so
   third-party adapters are provably correct — this is what turns a library into
   an *ecosystem*.

What it does **not** need to change — and should protect — is its genuine
differentiator: it is **opinionated about security defaults** in a way Gin/Echo
deliberately are not. Gin gives you a router and leaves auth/z, tenancy, and error
shaping to you; backendkit already ships fail-closed auth, a tiering model, typed
errors, and a security-correct middleware order. If the v2.0 program lands the six
changes above **while keeping those opinionated, secure defaults**, backendkit
occupies a real, defensible niche the incumbents leave open: **"the batteries-
included, secure-by-default backend framework for multi-tenant SaaS"** — Kratos's
structure with Rails-like security ergonomics.

**Verdict:** the distance to first-class is an *abstraction and packaging*
program, not a rewrite. Every concrete behaviour worth keeping already exists; v2.0
is about putting interfaces where Socrate and logrus are wired in, and splitting
the module so adopters pay only for what they use. Execute RFC-001/002/003 and
backendkit graduates from internal toolkit to a framework I would put on the same
shortlist as Kratos.
