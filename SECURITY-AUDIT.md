# Deep Security & Architecture Audit — `backendkit`

**Scope:** `github.com/ovander/backendkit` (Go 1.25, commit `46105b1`)
**Method:** Full read of every exported package. Every conclusion below cites
`file:line` evidence from this repository. Where a conclusion cannot be reached
from code in this repository, that is stated explicitly.
**Auditor framing:** This package is treated as the shared security foundation
for multiple production SaaS apps (README §"Used by" — Kerplan, a multi-tenant
enterprise SaaS, `README.md:711`). Every exported package is assumed
security-critical until proven otherwise.

---

## 1. Executive Summary

`backendkit` is a **well-engineered set of building blocks**, not a turnkey
secure framework. Its cryptographic core (RS256 JWT verification) is implemented
correctly and fails closed on the cases it handles. The Go is idiomatic, context
propagation is type-safe, and panic recovery / error shaping are clean.

However, **as a *security foundation* it has structural gaps that matter at
enterprise scale.** The most serious are not bugs in the code that exists, but
**security controls a buyer would assume are present and that are not**:

| # | Severity | Finding | Origin |
|---|----------|---------|--------|
| F-1 | **High** | JWT **audience (`aud`) is never validated** — tokens are reusable across every app sharing the Socrate issuer | Framework |
| F-2 | **High** | **Token revocation / `token_version` is never enforced** on the hot path | Framework gap |
| F-3 | **High** | **Tenant isolation is fail-open and absent by default** (`tenant_id` not issued by default server; `uuid.Nil` flows downstream) | Framework + Config |
| F-4 | **High** | **Per-tenant rate limiter is a no-op in the default configuration** and fails open | Framework + Config |
| F-5 | Medium | Issuer validation is optional and silently disabled when empty | Framework |
| F-7 | Medium | **Path-parameter injection** in `socrate.Client` (unescaped `userID` in URLs) | Framework |
| F-8 | Medium | Unbounded body reads (JWKS, Socrate, AI gateway) — memory-exhaustion vector | Framework |
| F-9 | Medium | `gormlogger` logs **full SQL with bound parameter values** (PII/secrets in logs) | Framework |
| F-10 | Medium | JWKS parser accepts **weak RSA keys** (no min modulus, exponent truncated) | Framework |
| F-17 | Medium | `apierror.Message` documented "logs only" but **serialized to clients** | Framework |

**Bottom line:** the pieces that exist are mostly sound; the framework is
**incomplete relative to its own marketing** ("complete middleware stack",
`README.md:178`, `205`). It can be a *trusted dependency* once the gaps below are
closed and the shared-responsibility boundary is documented. It cannot today be
relied on as the *sole* security layer of a regulated multi-tenant SaaS.

---

## 2. Phase 1 — Security Boundary Map

Packages participating in security, ranked by criticality:

| Package | Security role | Trust boundary |
|---------|---------------|----------------|
| `jwtauth` | **Authentication** — RS256 JWT verification, JWKS fetch/cache, claim→context | The primary boundary: converts an untrusted bearer token into trusted identity |
| `ctxutil` | **Identity propagation** — typed, unexported context keys for tenant/user/role/plan/jwt | Internal; integrity depends on only `jwtauth` writing it |
| `httpware/rbac.go` | **Authorization** — role→permission gate | Per-route, opt-in |
| `httpware/ratelimit.go` | **Abuse control** — per-tenant token bucket | Post-auth |
| `httpware/security.go` | **Security headers** | Response hardening |
| `httpware/recover.go` | **Panic containment** | Prevents stack leakage / crash |
| `httpware/{requestid,logger,timeout,bodylimit}.go` | Correlation, audit surface, DoS limits | Supporting |
| `tiering` | **Plan-based authorization** (Gate + PolicyService) | Commercial entitlement, treated as authz |
| `socrate` | **Identity-provider client** — forwards JWT / service creds to Socrate | Outbound trust to IdP |
| `aigateway` | Outbound calls to OpenAI/Anthropic; holds API keys | Secret handling, egress |
| `gormlogger` | DB log routing | Sensitive-data sink |
| `apierror` | Error shaping → client | Information-disclosure boundary |
| `buildinfo` | Public version endpoint | Intentionally unauthenticated (`buildinfo.go:51`) |

**Not present anywhere in the package** (confirmed by exhaustive grep): **CORS,
CSRF, TLS configuration, session/cookie handling, password hashing, encryption
at rest, secrets management, signed audit log.** These are therefore *outside*
backendkit's trust boundary — see Phase 15.

---

## 3. Phase 2 — Authentication Audit (`jwtauth`)

### Controls that are correct (evidence)

- **Algorithm confusion / `alg=none` blocked — twice.**
  `jwt.WithValidMethods([]string{"RS256"})` (`middleware.go:193`) **and** an
  explicit `t.Method.(*jwt.SigningMethodRSA)` assertion in the keyfunc
  (`middleware.go:199-201`). An attacker cannot downgrade to HMAC-using-public-key
  or `none`.
- **`kid` required** (`middleware.go:202-205`) — no key-guessing.
- **Signature, `exp`, `nbf` validated** — golang-jwt v5 enforces `exp`/`nbf` by
  default; signature via the JWKS key. Tampered token → 401 (test
  `middleware_test.go:141-166`).
- **Fail-closed**: missing/invalid token → `401` via `apierror.Unauthorized`
  (`middleware.go:106-118`). No anonymous fallthrough.
- **JWKS availability**: stale-cache fallback on refresh failure
  (`middleware.go:225-231`) — good for uptime.
- **Identity cannot be spoofed via headers**: all identity in `ctxutil` is written
  *only* from validated claims (`middleware.go:120-169`); context keys are an
  unexported type (`ctxutil.go:20-39`), so a client header cannot inject them.

### Findings

**F-1 (HIGH) — No audience (`aud`) validation.**
`validateToken` sets only `WithValidMethods` and *optionally* `WithIssuer`
(`middleware.go:191-207`). There is **no `jwt.WithAudience`**. Because the design
explicitly states *"All backends sharing Socrate as their OAuth2 provider"*
(`ctxutil.go:5`) use the same issuer and JWKS, a token minted for App A is
cryptographically valid at App B. This is a classic **confused-deputy / cross-service
token-replay** exposure. In a fleet of SaaS apps behind one IdP, this is the
single most important missing check.
*Fix:* add a required-audience parser option keyed on each app's client_id.

**F-2 (HIGH) — Revocation / `token_version` never enforced.**
The middleware extracts `token_version` and stores it in context
(`middleware.go:163-165`) and the type doc claims it is *"incremented on password
change / token revocation"* (`middleware.go:36`). **Nothing ever compares it to a
current value.** `validateToken` checks only signature + standard claims. A stolen
or post-logout access token remains valid until `exp`. `socrate.IntrospectToken`
(RFC 7662, `client.go:741`) exists but is **never wired into the auth path**.
Net: the framework offers no revocation, no token binding, no replay protection.
*Fix:* optional introspection or a `token_version` callback hook on the hot path.

**F-5 (MEDIUM) — Issuer validation optional, fail-open on misconfig.**
Issuer is enforced only when non-empty (`middleware.go:194-196`).
`jwtauth.New(jwksURL, "", logger)` silently disables it, and the constructor does
not warn/reject (`middleware.go:92-101`). A copy-paste of the quickstart, which
passes `""`, ships with issuer checking off.

**F-10 (MEDIUM) — Weak-key acceptance in JWKS parsing.**
`parseRSAPublicKey` (`middleware.go:285-298`) builds the key with
`E: int(new(big.Int).SetBytes(eBytes).Int64())` (truncates a large exponent) and
accepts **any modulus size** — no rejection of <2048-bit keys. Safety rests
entirely on TLS integrity of the JWKS endpoint; a mis-served or downgraded key is
trusted. *Fix:* enforce `pub.N.BitLen() >= 2048` and sane exponent.

**F-8 (part) (MEDIUM) — Unbounded JWKS body.**
`fetchJWKS` decodes `resp.Body` with no size cap (`middleware.go:255-258`). The
HTTP client has a 10s timeout (good, `middleware.go:97`) but no
`http.MaxBytesReader`; a compromised/MITM JWKS endpoint can feed a huge body.

**F-18 (LOW) — No single-flight on JWKS refresh.**
On cache expiry, every concurrent request that misses calls `fetchJWKS`
(`middleware.go:215-240`) — a thundering herd toward the IdP. Functionally safe,
operationally noisy.

**Clock skew (LOW):** no `jwt.WithLeeway` configured — default 0s. Tight clocks
across services can cause spurious 401s; not a vulnerability.

**Test coverage gap (Testability):** negative-path tests cover missing header and
tampered token only (`middleware_test.go:122-166`). **No tests for `alg=none`,
algorithm confusion, expiry, issuer enforcement, or missing `kid`** — the exact
controls a security reviewer most wants pinned.

---

## 4. Phase 3 — Authorization Audit (`httpware/rbac.go`, `tiering`)

- **Centralised?** Partially. RBAC and the tiering Gate are middleware, but they
  are **opt-in per route** (`r.Use(rbac.Require(...))`, `README.md:259-265`).
  Nothing forces a route to carry an authz check — **a handler can silently ship
  with no authorization** ("missing function-level access control" is a
  *structural* possibility, not prevented by the framework).
- **Fail-closed:** unknown/empty role → `false` → 403 (`rbac.go:57-67`). Unknown
  plan → lowest tier (`plan.go:67-83`, `gate.go:50`). Good defaults.
- **Object-level / tenant-scoped authorization:** **none.** RBAC is purely
  role→permission (`rbac.go:41-68`); there is no resource-ownership or
  per-object check. **IDOR / BOLA prevention is entirely the application's job.**
- **Role source confusion (MEDIUM-ish):** `RBAC.Require` reads only the top-level
  `Role` claim via `GetUserRole` (`rbac.go:44`). The token also carries a richer
  `app_roles` map (`middleware.go:160-162`, `ctxutil.go:149-171`). An app that
  *thinks* it is enforcing the per-app role but uses `Require` is actually keying
  on the global `role` — a latent **role-confusion** bug the API shape invites.
- **Composability:** permissions are a flat `[]Permission` per role; no
  inheritance, no permission composition, no wildcard. Simple and predictable, but
  every role must enumerate every permission (`rbac.go:25`, `57-67`).
- **Testability:** RBAC is a pure function of context + map — easily unit-tested.

`PolicyService` (entitlement authz) is sound: DB-backed, cached, **busts cache on
write** (`policy_service.go:97`), and **denies on any error** (`policy_service.go:104-119`).
It serves stale on DB outage (`policy_service.go:165-172`) — an availability vs.
correctness trade that is acceptable for *entitlements* but would be wrong for
*security* authz.

---

## 5. Phase 4 — Multi-Tenant Security

**F-3 (HIGH) — Tenant isolation is absent by default and fails open.**

- Tenant ID is set **only when the `tenant_id` claim is present**
  (`middleware.go:122-131`).
- The code's own documentation states the **default Socrate server does not issue
  `tenant_id`** (`middleware.go:38-40`, `51-53`).
- When absent, `GetTenantID` returns `uuid.Nil` (`ctxutil.go:49-54`) with no error.
- **No middleware requires a tenant.** Any downstream query that trusts
  `GetTenantID` will silently scope to the *nil* tenant — i.e. potentially **all
  tenants share one bucket**.

Consequences chain into F-4 (rate limiter keyed on the nil tenant). Spoofing of
the tenant *value* by a client is not possible (it comes from the signed JWT), but
**the absence of the value is the danger**, and there is no
guard rail. The framework provides **no tenant-scoped repository, no
"require tenant" middleware, and no background-job context propagation** — all of
that is the application's responsibility, undocumented as such.

Context can also be **overwritten** by any code holding the `ctx`
(`ctxutil.WithTenantID` is exported, `ctxutil.go:44`); there is no write-once
guarantee. Within a single trusted binary this is acceptable, but it means tenant
integrity is a *convention*, not an *invariant*.

---

## 6. Phase 5 — Middleware Review

Documented chain (`README.md:177-179`, `243-252`):
`RequestID → Logger → SecurityHeaders → BodyLimit → Recover → Timeout → auth → RateLimiter`.

- **Order is mostly correct:** `Recover` wraps `Timeout`, `auth`, and
  `RateLimiter`, so panics in those are caught. **But `RequestID`, `Logger`,
  `SecurityHeaders` sit *outside* `Recover`** — a panic in those three is *not*
  contained (low risk; they are trivial).
- **F-11 (LOW) — `Timeout` drops cancellation.** `context.WithoutCancel`
  (`timeout.go:25`) strips the parent deadline **and client-disconnect / shutdown
  cancellation**. Documented as intentional for slow AI endpoints
  (`timeout.go:14-20`), but it means a disconnected client's work runs to the full
  timeout, and graceful-shutdown cancellation won't propagate. It is also
  **advisory only** — it never forces a response (no `http.TimeoutHandler`), so a
  handler ignoring `ctx` runs unbounded.
- **`BodyLimit`** (`bodylimit.go:14-21`) correctly uses `http.MaxBytesReader` —
  good DoS control. No *response*-size limit (not usually needed).
- **`RequestID`** (`requestid.go:17-27`) accepts a client-supplied
  `X-Request-ID` verbatim and echoes it — fine for correlation, but a client can
  set arbitrary values (log-forging is mitigated by structured logging).
- **`Recover`** (`recover.go:14-28`) logs panic + stack **server-side only** and
  returns a generic 500 — **no stack trace leaked to the client.** Correct.
- **`SecurityHeaders`** — see Phase 7.
- **Missing middleware:** **no CORS, no CSRF, no gzip/compression bomb guard, no
  concurrency limiter.** For a bearer-token API, CSRF is largely N/A, but CORS is a
  real omission relative to the "complete stack" claim.

---

## 7. Phase 6 — Cryptography Review

- **No password hashing, encryption, HMAC, or nonce/IV handling in this package.**
  Comment in `socrate/admin.go:51` references server-side bcrypt — that is the
  *Socrate server's* concern, not backendkit.
- **Randomness:** identifiers use `github.com/google/uuid` (`requestid.go:22`,
  `middleware.go:138`), which draws from `crypto/rand` for v4 — adequate. The only
  `math/rand`/`crypto/rand` import is in a *test* (`middleware_test.go:4`).
- **Deterministic UUID from `sub`** (`middleware.go:138`) uses `uuid.NewSHA1`
  (namespaced) — a stable identifier mapping, **not** a security token; SHA-1 use
  here is benign.
- **No constant-time comparisons needed** — no secret comparisons happen in this
  package (token verification is delegated to golang-jwt, which is constant-time
  for signatures).
- **No hardcoded secrets** (confirmed by grep): API keys/secrets are injected via
  config structs (`aigateway` Config `client.go:34-48`; `socrate` ClientConfig
  `client.go:70-78`) and **never logged** — `aigateway` logs only
  `"configured"/"not configured"` (`client.go:91-95`).

Cryptography verdict: **correct by delegation and omission.** No weak primitives.

---

## 8. Phase 7 — Configuration Security

- **No environment variables read inside any package** (by design — `aigateway`
  doc `client.go:5-7`); config is injected. Good for testability and 12-factor.
- **Safe-ish defaults:** HTTP timeouts default (`socrate` 30s `client.go:89-92`,
  `aigateway` 30s `client.go:67-70`, JWKS 10s `middleware.go:97`).
- **Dangerous default:** `jwtauth.New` accepts empty issuer with **no validation**
  (F-5). `NewClient` validates `BaseURL`/`ClientID` (`client.go:82-87`) but not
  much else.
- **No production/startup validation harness** — there is no `Validate()` that
  refuses to boot on insecure config (e.g. empty issuer, missing audience). For an
  enterprise framework this is a notable gap.
- **`MagicLinkResponse.MagicURL`** is populated by the *server* in dev mode only
  (`client.go:780-785`) — backendkit merely passes it through; no client-side debug
  bypass exists here.

---

## 9. Phase 8 — Logging & Audit

- **No JWT, password, secret, or Authorization header is logged** anywhere
  (grep-confirmed). `jwtauth` logs only error context (`middleware.go:108,115`);
  `Logger` logs method, **path only (not query string)**, status, duration,
  tenant_id, request_id (`logger.go:34-49`) — query strings (which may carry
  tokens) are deliberately excluded. Good.
- **F-9 (MEDIUM) — `gormlogger` logs full SQL with bound values.**
  `Trace` logs `sql` from GORM's callback, which includes **interpolated parameter
  values** (`gormlogger/logger.go:88-95`), at Warn for slow queries (the
  *production* default level, doc `logger.go:31`) and at Error. This routinely
  writes **PII (emails, names) and any secret stored in a row** to logs. No
  redaction hook. This is the most likely real source of a "sensitive data in
  logs" application finding.
- **Audit trail:** backendkit has **no audit-log writer of its own.** It can
  *read* Socrate's audit events (`socrate.GetActivityLogs`, `client.go:835`) but
  provides **no tamper-evident, append-only, durable audit log**. Audit integrity,
  completeness, and durability are entirely Socrate's / the app's responsibility.
- **Correlation:** `request_id` propagation is solid (`requestid.go`, `logger.go`,
  `ctxutil.go:220-233`).

---

## 10. Phase 9 — Error Handling

- **No stack traces or internal errors leak to clients** from `Recover`
  (`recover.go:18-23`). 500s are generic.
- **F-17 (MEDIUM) — `apierror.Message` contradicts its own contract.**
  The struct comment says `Message` is the *"English dev-facing message
  (logs only)"* (`errors.go:15`), but `WriteJSON` **serializes `Message` directly
  to the client** (`errors.go:13`, `186-190`). A developer trusting the comment who
  writes `apierror.Internal(err.Error())` will leak the internal error to the
  caller. The misleading doc makes information disclosure *likely*. Several
  constructors already embed identifiers in the message (`NotFound` →
  `entity + " not found: " + id`, `errors.go:43-49`).
- HTTP status mapping is consistent and correct (`errors.go:154-183`).
- Errors are consistently structured (`ErrorResponse{Error: AppError}`),
  i18n-keyable (`WithKey`, `errors.go:26-29`), good DX.

---

## 11. Phase 10 — API Security

- **SQL construction:** **none in backendkit.** `tiering` defines GORM models and a
  `PolicyRepository` *interface* (`policy.go:31-37`, `policy_service.go:20-24`); the
  concrete SQL lives in the app. No injection surface here, but no parameterisation
  guarantee provided either.
- **F-7 (MEDIUM) — Path-parameter injection in `socrate.Client`.** Caller-supplied
  `userID` is interpolated into request paths with `fmt.Sprintf` and **no
  escaping**: `client.go:443, 503, 524, 545, 566, 592`. A `userID` containing
  `/`, `?`, or `..` rewrites the target endpoint (e.g. `userID = "1/reset-password"`
  hits a different route, or `?role=admin` injects a query). Note the contrast:
  `search` *is* `url.QueryEscape`d (`client.go:415`), so the omission on path
  segments is inconsistent. *Fix:* `url.PathEscape` every dynamic path segment.
- **SSRF:** base URLs are operator-config, not user-input (`client.go:55-60`,
  `aigateway.go:79-80` are hardcoded to the real providers) — low SSRF risk, but
  F-7 allows partial path control.
- **F-8 (MEDIUM) — Unbounded response reads** in `socrate.readBody`
  (`client.go:172-175`, `io.ReadAll`) and `aigateway` (`client.go:173, 227`). A
  compromised upstream can exhaust memory.
- **Mass assignment / deserialization:** request/response structs are explicit and
  typed (`socrate` data types `client.go:309-401`); no `map[string]interface{}`
  binding of client input, no `encoding/xml`, no unsafe reflection.
- **No open redirect / template / command injection** surfaces in this package.

---

## 12. Phase 11 — Go Security & Concurrency

- **Mutex/RWMutex usage correct:** `jwtauth` (`middleware.go:85, 216-235, 276-279`),
  `RateLimiter` (`ratelimit.go:42, 92-102`), `PolicyService` double-checked cache
  (`policy_service.go:149-177`), `socrate` service-token (`client.go:258-263`). No
  obvious data races; the package doc even claims "no shared mutable state between
  requests" (`timeout.go:1-4`).
- **Goroutine lifecycle:** `RateLimiter` starts a cleanup goroutine
  (`ratelimit.go:58, 68-79`) with a `Stop()` (`ratelimit.go:64-66`). **`Stop()`
  closes the channel with no guard — calling it twice panics** (`close` of closed
  channel). Minor (LOW).
- **`socrate.getServiceToken` holds the mutex across the HTTP round-trip**
  (`client.go:258-302`) — correctness-safe but serializes all callers behind one
  network call (perf, not security).
- **No `unsafe`, no `reflect` misuse, no pointer aliasing, no obvious resource
  leaks** — response bodies are consistently closed (`readBody` `client.go:172-175`,
  `defer resp.Body.Close()` throughout). `defer cancel()` paired correctly
  (`timeout.go:26-27`).

---

## 13. Phase 12 — Framework Architecture

- **Package organization:** clean, single-responsibility packages; dependency
  direction is acyclic (`ctxutil` and `apierror` are leaves; everything depends
  inward on them). Good.
- **Coupling:** low. Middleware are plain `func(http.Handler) http.Handler`,
  router-agnostic (`README.md:342`). `ctxutil` is the one shared coupling point and
  it is deliberately the *single source of truth* for keys (`ctxutil.go:5-11`) —
  the right call.
- **Public API:** small, idiomatic, well-documented with runnable examples
  (`example_test.go` in most packages).
- **Extensibility:** `tiering.PolicyRepository`/`PlanSelector` interfaces
  (`policy.go:63-91`) and pluggable `RoleMap` are good seams. But **no seam to
  inject audience/revocation policy into `jwtauth`** — the auth core is closed to
  the most security-relevant extension.
- **Versioning/compat:** module is pre-1.0 in spirit but README references v1.7.0
  installs; deprecated aliases are kept (`ctxutil.go:235-247`) — backward-compat
  discipline is present.
- **Dependencies:** minimal and reputable (`golang-jwt/v5`, `google/uuid`,
  `logrus`, `golang.org/x/time`, `gorm`) — `go.mod` is lean.

---

## 14. Phase 13 — Framework Quality Scores

| Dimension | Score /10 | Justification (evidence) |
|-----------|:--------:|--------------------------|
| Architecture | 8 | Acyclic, low-coupling, clean seams; closed auth core (Phase 12) |
| **Security** | **5** | Correct crypto core, but F-1/F-2/F-3/F-4 are structural gaps |
| Go idioms | 9 | Type-safe context, correct sync, no `unsafe`, bodies closed |
| API design | 8 | Small, documented, runnable examples; F-17 doc/behaviour mismatch |
| Maintainability | 8 | Readable, consistent, deprecation discipline |
| Extensibility | 6 | Good repo/selector seams; no auth-policy seam |
| Operational readiness | 5 | In-memory-only rate limit, no startup validation, stale-cache trades |
| Documentation | 7 | Excellent prose; but overstates completeness ("complete stack") |
| Testability | 7 | Pure functions; thin negative-path auth tests |
| **Overall** | **6** | Solid components, incomplete as a security foundation |

---

## 15. Phase 14 — Production Readiness

| Target | Verdict | Why (evidence) |
|--------|---------|----------------|
| Startup production (single-tenant) | **Conditional yes** | Auth core is sound; fix F-5/F-17, accept in-memory rate limit |
| **Enterprise SaaS (multi-tenant)** | **No, not as-is** | F-1 (cross-app token reuse), F-3 (tenant fail-open) are disqualifying without app-side compensation |
| Healthcare (HIPAA) | **No** | F-9 (PII in SQL logs), F-2 (no revocation), no audit durability |
| Financial services | **No** | F-2 (no revocation/replay), F-1 (audience), F-9 |
| Government | **No** | Missing key-size enforcement (F-10), no FIPS posture, no revocation |
| **SOC 2** | **Partial** | Logging/correlation good; but no native audit trail, F-9 leakage, revocation gap are auditor findings |
| ISO 27001 | **Partial** | Same as SOC 2 |
| PCI DSS | **No** | Revocation, key strength, log-data-minimisation (F-9) all required and unmet |
| Multi-region | **No (rate limit)** | `RateLimiter` is in-memory per-instance (`ratelimit.go:43`) → limit = instances × rps; not coordinated |
| Multi-tenant SaaS | **No, not alone** | F-3 + F-1 + F-4 must be closed or compensated app-side |

These verdicts are about **backendkit as the *sole* control layer**. With a
correctly configured Socrate server (issuing `tenant_id`, scoped audiences) and
app-side compensating controls, several upgrade to "yes" — see Phase 15.

---

## 16. Phase 15 — Trust Boundary Verification

Mapping each application-audit finding category to its true origin:

| Application finding | Origin | Why (evidence) |
|---------------------|--------|----------------|
| JWT validation weak / no `aud` | **Framework bug** | `middleware.go:191-207` — no `WithAudience` |
| `alg=none` / alg confusion | **False positive** | Double-blocked `middleware.go:193, 199-201` |
| Tokens valid after logout/password change | **Framework gap** | `token_version` captured, never checked `middleware.go:163-165` |
| Cross-app token reuse | **Framework bug** | F-1, shared issuer `ctxutil.go:5` |
| Missing authorization on a route | **Application bug** | RBAC is opt-in `README.md:259`; framework can't force it |
| IDOR / object-level access | **Application bug** | No object-level authz exists in framework (Phase 4) |
| Role/permission confusion (app vs global role) | **Shared** | API invites it: `Require` uses global `Role` `rbac.go:44` while `app_roles` exists |
| Cross-tenant data access | **Shared / Config** | F-3: framework fail-open + server not issuing `tenant_id` |
| Rate limiting ineffective | **Framework + Config** | F-4: nil-tenant bypass `ratelimit.go:108-112`; in-memory only |
| PII / secrets in logs | **Framework bug** | F-9 `gormlogger/logger.go:88-95` |
| Internal error leaked to client | **Framework bug (latent)** | F-17 `errors.go:15` vs `186-190` |
| Stack trace in response | **False positive** | `Recover` returns generic 500 `recover.go:18-23` |
| Missing security headers | **False positive** | `SecurityHeaders` present and strong `security.go:17-29` |
| CORS misconfiguration | **Application bug** | No CORS in framework — entirely app-owned |
| CSRF | **Mostly N/A** | Bearer-token API, no cookie handling in framework |
| SSRF / path manipulation in IdP calls | **Framework bug** | F-7 unescaped path params `client.go:443…592` |
| Weak randomness | **False positive** | `crypto/rand`-backed UUIDs (Phase 6) |
| Hardcoded secrets | **False positive** | Injected config, never logged `aigateway client.go:91-95` |
| Panic crashes service | **False positive** | `Recover` middleware `recover.go` |
| Audit trail missing/tamperable | **Shared (Socrate/app)** | Framework only reads logs `client.go:835`; no writer |

---

## 17. Phase 16 — Remediation Roadmap

### Critical (do before any multi-tenant enterprise use)
1. **F-1** Enforce audience: add required `aud` (per-app client_id) to
   `validateToken` — *breaking* for tokens lacking `aud`; ship behind a config flag,
   default-on in a new major.
2. **F-3** Add a `RequireTenant` middleware that 401s when `GetTenantID == uuid.Nil`,
   and document that tenant-scoped repos must filter on it. *Non-breaking* (additive).
3. **F-2** Add a revocation hook: optional `IntrospectToken` on the auth path or a
   `token_version` validation callback. *Non-breaking* (opt-in).

### High
4. **F-4** Document the nil-tenant bypass; offer an IP/subject fallback key and a
   pluggable distributed store (Redis) for multi-instance correctness.
5. **F-5** Make `jwtauth.New` reject an empty issuer, or add `NewWithConfig` that
   validates. *Minor breaking.*
6. **F-17** Either redact `Message` from `WriteJSON` for 5xx, or fix the doc and add
   a separate `PublicMessage`. *Behaviour change — version carefully.*

### Medium
7. **F-7** `url.PathEscape` all dynamic path segments in `socrate.Client`.
8. **F-9** Add a redaction/disable hook to `gormlogger`; default to **not** logging
   bound values in production.
9. **F-8** Wrap all upstream `io.ReadAll`/JSON decodes with `io.LimitReader` /
   `http.MaxBytesReader`.
10. **F-10** Enforce `pub.N.BitLen() >= 2048` and exponent sanity in JWKS parsing.

### Architecture / non-breaking
11. Add a `Config.Validate()` that refuses insecure boot (empty issuer, missing
    audience, debug flags).
12. Add `singleflight` to JWKS refresh (F-18); guard `RateLimiter.Stop()` against
    double-close.
13. Expand negative-path auth tests (alg=none, expiry, issuer, kid).
14. Provide first-class **CORS** middleware and an **audit-log writer** interface, or
    explicitly document them as out-of-scope.

### Versioning & migration strategy
- F-1/F-5/F-17 are **breaking** → bundle into a single **v2.0.0**; ship the
  audience/issuer/revocation features as opt-in in a **v1.x** minor first
  (default-off), with a deprecation window, then flip defaults in v2.
- F-2/F-3/F-7/F-8/F-9/F-10 are **additive/non-breaking** → ship in the next minor.
- Keep the existing deprecated-alias discipline (`ctxutil.go:235-247`) as the model.

---

## 18. Final Recommendation

> **Would I recommend `backendkit` as the security foundation for multiple
> enterprise SaaS applications?**

**Not in its current state — but it is close, and the gaps are well-defined.**

The evidence is two-sided and I will not overstate either half:

- **What it does, it largely does correctly.** RS256 verification blocks `alg=none`
  and algorithm confusion at two layers (`middleware.go:193, 199-201`), auth fails
  closed (`middleware.go:106-118`), panics are contained without leaking stacks
  (`recover.go:18-23`), security headers are strong (`security.go:17-29`), context
  identity is type-safe and unspoofable via headers (`ctxutil.go:20-39`), and the Go
  is clean and race-free. As a *library of trustworthy components*, it earns its
  place.

- **What a security foundation *must* guarantee, it does not yet.** It has **no
  audience validation** (F-1), **no token revocation** (F-2), **fail-open tenant
  isolation that is absent by default** (F-3), a **rate limiter that no-ops in the
  default configuration** (F-4), **PII-leaking SQL logs** (F-9), and a **client/doc
  mismatch that invites internal-error disclosure** (F-17). For a *single* app these
  are manageable; across a *fleet of multi-tenant enterprise apps behind one IdP*,
  F-1 and F-3 in particular are disqualifying until fixed or compensated.

**Verdict:** Adopt it as a **dependency**, not as the **sole security layer**.
Approve it for production **only after** the three Critical items (F-1, F-2, F-3)
are closed or explicitly compensated in each application, and **only with** a
documented shared-responsibility model that states plainly what backendkit does
*not* cover (CORS, object-level authz, tenant enforcement, audit durability,
distributed rate limiting). With the Phase-16 roadmap applied — a realistic
v1.x-then-v2.0 effort — it can become a framework I *would* recommend as an
enterprise security foundation.

### Evidence gaps (stated explicitly, no speculation)
Conclusions I **could not** reach from this repository alone, and what is needed:
- Whether the **Socrate server actually issues `tenant_id`, scoped `aud`, and
  honours `token_version`** — requires the Socrate server source / token samples.
- Whether **TLS, secret storage, and network segmentation** (Admin port 8081 is
  "internal; restrict at network level", `client.go:19-21`) are enforced —
  requires deployment/infra config.
- Whether applications **actually apply** RBAC/Gate/`RequireTenant` on every
  sensitive route — requires the consuming applications' router wiring.
