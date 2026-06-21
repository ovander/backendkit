# Fourth Pass — Security Architecture Verification

**Subject:** `github.com/ovander/backendkit` (Go 1.25, commit `46105b1`)
**Lens:** Security Architect. The vulnerability hunt is assumed complete
(see `SECURITY-AUDIT.md`). This document **verifies whether the framework
enforces the correct security invariants** and maps the already-known findings
onto architecture, threat, compliance, and evolution.
**Rule of engagement:** no new coding defects are raised unless they violate a
declared architectural security invariant. Every verdict cites `file:line`.

---

## 1. Threat Model

### 1.1 Assets
| Asset | Where it lives in backendkit |
|-------|------------------------------|
| User identity & claims | `jwtauth` → `ctxutil` context values |
| Tenant boundary | `ctxutil` tenant ID, `httpware/ratelimit`, `tiering` |
| Bearer JWT (raw) | `ctxutil.WithRawJWT` (`ctxutil.go:191`), forwarded by `socrate` |
| Service-account secret | `socrate.Client.clientSecret` (`client.go:59`) |
| AI provider API keys | `aigateway.Client.apiKey` (`client.go:53`) |
| Entitlement / plan state | `tiering.PolicyService` (DB-backed cache) |

### 1.2 Actors / trust levels
- **T0 Anonymous internet** — controls request bytes, headers, body, and the
  bearer token *string*.
- **T1 Authenticated user** — holds a Socrate-issued JWT for *some* app.
- **T2 Tenant admin / elevated role** — higher RBAC role / plan.
- **T3 Service account (M2M)** — `client_credentials` holder.
- **T4 The service binary itself** — fully trusted; shares one `context.Context`.
- **TX Socrate IdP + JWKS endpoint** — external trust anchor.
- **TY External AI providers** — egress dependency.

### 1.3 STRIDE summary (mapped to verified invariants in §6)
| STRIDE | Primary exposure | Invariant | Status |
|--------|------------------|-----------|--------|
| **S**poofing | Cross-app token reuse; tenant absence | INV-2, INV-6 | **Violated** (F-1, F-3) |
| **T**ampering | Token signature; context injection | INV-4, INV-5 | **Enforced** |
| **R**epudiation | No native audit writer | INV-14 | **Not provided** |
| **I**nfo disclosure | Error body; SQL logs | INV-9, INV-10 | **Partial** (F-17, F-9) |
| **D**enial of service | Rate-limit bypass; unbounded reads | INV-8, INV-12 | **Violated/Partial** (F-4, F-8) |
| **E**levation | Stale token after revoke; opt-in authz | INV-3, INV-7 | **Violated/Partial** (F-2) |

---

## 2. Trust Boundary Diagram

```
            T0/T1 Internet (untrusted)
                  │  HTTP request + "Authorization: Bearer <jwt>"
                  ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  TLS-terminating proxy (NOT in backendkit — operator owned)  │
   └─────────────────────────────────────────────────────────────┘
                  │
 ╔════════════════▼══════════════════════════════════════════════╗  TRUST
 ║  Service binary (T4)                                           ║  BOUNDARY #1
 ║                                                                ║  (token→identity)
 ║  RequestID → Logger → SecurityHeaders → BodyLimit →            ║
 ║  Recover → Timeout → [ jwtauth.Handler ] ──── verifies sig,    ║
 ║                         alg, exp, (iss?) against JWKS          ║
 ║                              │ writes ctxutil identity         ║
 ║                              ▼                                 ║
 ║      RateLimiter → RBAC.Require → tiering.Gate → Handler       ║
 ║                              │                                 ║
 ║   ┌──────────────────────────┼──────────────────────────────┐ ║
 ║   │ ctxutil (in-process identity store, unexported keys)     │ ║
 ║   └──────────────────────────┼──────────────────────────────┘ ║
 ╚══════════════════════════════┼════════════════════════════════╝
        │ socrate.Client (Bearer fwd / M2M)   │ aigateway (api key)
        ▼  TRUST BOUNDARY #2                  ▼  TRUST BOUNDARY #3
 ┌──────────────────────────┐        ┌──────────────────────────────┐
 │ TX Socrate IdP           │        │ TY OpenAI / Anthropic        │
 │  :8080 OAuth  :8081 Admin│        │  (egress, holds API key)     │
 │  JWKS endpoint (anchor)  │        └──────────────────────────────┘
 └──────────────────────────┘
```

**Boundary #1** is the one backendkit owns and is judged on. Boundaries #2/#3 are
*delegated* trust (Socrate, AI providers). The **root of all identity trust is the
JWKS endpoint at TX** — a single anchor with no key-pinning or min-strength check
(F-10 / INV-13).

---

## 3. Authentication Flow Diagram

```
 client ──Bearer──▶ jwtauth.Handler (middleware.go:104)
                       │
                       ├─ extractBearer            (middleware.go:179)  ──fail──▶ 401 (fail-closed) ✔INV-1
                       │
                       ├─ ParseWithClaims          (middleware.go:198)
                       │     ├─ WithValidMethods{"RS256"}  (193)  ─── alg pinned ✔INV-4
                       │     ├─ keyfunc: assert *SigningMethodRSA (199) ─ blocks alg=none ✔INV-4
                       │     ├─ require kid header  (202)
                       │     ├─ getKey(kid)         (215) ──▶ JWKS cache (TTL 1h) / fetch / STALE fallback (225)
                       │     ├─ WithIssuer  ONLY IF iss!="" (194) ─── ✗ optional  ▲F-5/INV-2partial
                       │     └─ exp / nbf  (golang-jwt default)        ─── ✔ INV-3(exp)
                       │            ✗ NO WithAudience anywhere          ─── ▲F-1/INV-2 VIOLATED
                       │            ✗ token_version captured, never checked (163) ─ ▲F-2/INV-3 VIOLATED
                       │
                       ├─ on any failure ─────────▶ 401 (115)  ✔ fail-closed
                       │
                       └─ success: write identity to ctx (120-169)
                             tenant(if present) user role plan app_roles raw_jwt
                             keys are unexported type ─── client cannot forge ✔INV-5
```

Verified properties: **fail-closed** (`middleware.go:106-118`), **algorithm
pinning at two layers** (`193`, `199-201`), **identity un-forgeable via headers**
(`ctxutil.go:20-39`). Missing properties: **audience binding** and **revocation**.

---

## 4. Authorization Flow Diagram

```
 authenticated ctx
      │
      ▼
 RateLimiter.Handler (ratelimit.go:106)
      │  tenantID := GetTenantID(ctx)
      ├─ tenantID == uuid.Nil ─────────────▶ PASS THROUGH (108-112) ▲F-4/INV-8 VIOLATED
      └─ else getLimiter(tenant).Allow() ── 429 on exceed
      │
      ▼
 RBAC.Require(perm) (rbac.go:41)              ── OPT-IN per route ▲INV-7 PARTIAL
      │  role := GetUserRole(ctx)             ── global role, NOT app_roles ▲role-confusion
      ├─ role∉map OR perm∉role ─────────────▶ 403 (49)  ✔ fail-closed
      └─ allow
      │
      ▼
 tiering.Gate.Require(minPlan) (gate.go:46)   ── OPT-IN per route
      │  plan := Normalise(GetUserPlan(ctx))  ── unknown→lowest tier ✔ fail-closed (plan.go:78)
      ├─ !TierAtLeast ─────────────────────▶ 403 upgrade_required (58)
      └─ allow
      │
      ▼
 Handler  ── object-level / ownership / tenant-row filter: NOT PROVIDED ▲INV-6/INV-7 (app-owned)
```

Verified: every gate that *is mounted* fails closed. **Not verified / not
enforceable by the framework:** that a gate is mounted at all (opt-in), and that
the handler performs object-level and tenant-row authorization.

---

## 5. Defense-in-Depth Analysis

| Layer | Control present | Evidence | Depth verdict |
|-------|-----------------|----------|---------------|
| Network | (delegated) TLS/segmentation | `client.go:19-21` notes :8081 "restrict at network level" | Out of scope |
| Request hygiene | BodyLimit, RequestID | `bodylimit.go:14`, `requestid.go:17` | ✔ thin but real |
| Crash containment | Recover (no stack leak) | `recover.go:18-23` | ✔ solid |
| Transport headers | SecurityHeaders (CSP/HSTS/nosniff/frame-deny) | `security.go:17-29` | ✔ strong |
| **AuthN** | RS256 verify, alg pin, fail-closed | `middleware.go:193,199-201,106-118` | ◑ no aud/revocation |
| **AuthZ** | RBAC + plan Gate, fail-closed | `rbac.go:49`, `gate.go:58` | ◑ opt-in, no object-level |
| Tenant isolation | tenant from claim | `middleware.go:122-131` | ✗ fail-open default |
| Abuse control | per-tenant rate limit | `ratelimit.go:106` | ✗ nil-tenant bypass, in-memory |
| Output safety | apierror shaping | `errors.go:186-190` | ◑ Message leaks to client |
| Observability | structured logs, correlation | `logger.go:34-49` | ◑ SQL value logging |

**Architectural read:** the **outer** layers (hygiene, crash, headers) are
complete and correct. The **core** layers (authN/authZ/tenant/abuse) are each
*individually* fail-closed *when invoked* but have **no redundancy** — there is
exactly one check per concern and several of those single checks are either
optional (RBAC/Gate/issuer), bypassable (rate limit on nil tenant), or absent
(audience, revocation, object-level). Defense-in-depth is **shallow at the core**:
a single missing `r.Use(...)` or a default-config token removes the only barrier.

---

## 6. Security Invariants — Verification Matrix

The spine of this pass. Each invariant is what an architect *expects* the
framework to guarantee, with VERIFIED / VIOLATED / DELEGATED status and evidence.

> **Updated post v1.8.0 (2026-06-20).** Status reflects the shipped remediation
> (#7, #15, #17, #19, #11, #13). The legend `✱ (opt-in)` marks an invariant the
> framework now **provides a control for** but does **not** enforce by default —
> verified once the app configures it; a by-default guarantee is the v2.0
> default-flip. The original (pre-remediation) statuses are shown struck for
> traceability.

| ID | Invariant | Status (v1.8.0) | Evidence / Finding |
|----|-----------|-----------------|--------------------|
| INV-1 | No protected handler runs without a verified identity | **VERIFIED** (where mounted) | fail-closed 401 `middleware.go:106-118` |
| INV-2 | A token is accepted only by the audience it was issued for | ~~VIOLATED~~ → **VERIFIED ✱ (opt-in)** | `WithAudience` shipped #7 (F-1); default-off |
| INV-3 | Expired/revoked credentials are rejected | ~~PARTIAL~~ → **VERIFIED ✱ (opt-in)** | exp ✔ default; `WithRevocationCheck` shipped #17 (F-2) |
| INV-4 | Signature algorithm & key are attacker-uninfluenceable | **VERIFIED** | `193`, `199-201` |
| INV-5 | Context identity derives only from verified claims; client cannot inject | **VERIFIED** | unexported keys `ctxutil.go:20-39`; written only in `middleware.go:120-169` |
| INV-6 | Every tenant-scoped op is bound to a non-nil verified tenant | ~~VIOLATED~~ → **VERIFIED ✱ (opt-in)** | `RequireTenant` shipped #15 (F-3) |
| INV-7 | Authorization is mandatory for protected resources | **PARTIAL** | opt-in middleware `README.md:259-265` |
| INV-8 | Abuse controls cannot be bypassed by omitting identity | ~~VIOLATED~~ → **PARTIAL** | `RequireTenant` (#15) blocks nil-tenant upstream; limiter still in-memory/per-tenant (F-4) |
| INV-9 | Errors/panics never disclose internal state to clients | ~~PARTIAL~~ → **VERIFIED** | Recover ✔; 5xx Message/Details redacted shipped #29 (F-17, v1.9.0) |
| INV-10 | Secrets are never logged or serialized | **VERIFIED** | no secret logging; opt-in `gormlogger.WithSQLRedaction` for SQL values shipped #27 (F-9, v1.9.0) |
| INV-11 | Untrusted input cannot restructure outbound requests | ~~VIOLATED~~ → **VERIFIED** | `url.PathEscape` on socrate userID shipped #23 (F-7, v1.9.0) |
| INV-12 | Resource consumption is bounded | ~~PARTIAL~~ → **VERIFIED** | BodyLimit ✔; upstream reads bounded shipped #25 (F-8, v1.9.0); stdlib CVEs cleared via Go 1.26.4 (#11) |
| INV-13 | Cryptographic keys meet a minimum strength | ~~VIOLATED~~ → **VERIFIED** | min 2048-bit + exponent validation shipped #19 (F-10); **default-on** |
| INV-14 | Security-relevant actions are durably, tamper-evidently recorded | **DELEGATED** | only reads Socrate logs `client.go:835`; no writer |

**Score (v1.9.0): 8 VERIFIED, 3 VERIFIED✱ (opt-in), 2 PARTIAL, 0 VIOLATED,
1 DELEGATED** — was *4 VERIFIED, 4 PARTIAL, 4 VIOLATED, 2 DELEGATED* at first
review; *5/3/4/1/1* after v1.8.0. **No invariant is VIOLATED.** v1.9.0 moved
INV-9 (5xx error redaction, #29), INV-11 (socrate path-escaping, #23), and INV-12
(bounded reads, #25) to VERIFIED, and confirmed INV-10 (opt-in SQL redaction,
#27). Only **INV-7** (mandatory authz) and **INV-8** (distributed rate-limit
store) remain PARTIAL, and the three ✱ auth/tenant controls (INV-2/3/6) are
verified **when enabled**. The remaining v2.0 step is flipping the ✱ controls to
default-on so the guarantees hold without per-app configuration.

---

## 7. Attack Trees — Every High/Critical Finding

### F-1 / INV-2 — Cross-app token reuse (HIGH)
```
GOAL: Act as a user inside App-B using a token minted for App-A
└─ AND
   ├─ Obtain a valid Socrate JWT for App-A
   │   ├─ be a legitimate App-A user (T1)              [trivial]
   │   └─ OR phish/replay any App-A token
   └─ Present it to App-B
       └─ App-B validates: sig ✔ (same JWKS), iss ✔ (same issuer),
          exp ✔, alg ✔ … aud ✗ NOT CHECKED  (middleware.go:191-207)
          └─ RESULT: token accepted; identity injected; App-B RBAC role
             comes from the *same* `role` claim → lateral access
MITIGATION (today): only if App-A and App-B happen to use different issuers
                    (config-dependent, not guaranteed)
KILL: enforce WithAudience(appClientID)        ✅ shipped v1.8.0 (#7, opt-in)
```

### F-2 / INV-3 — Use of a logically-revoked token (HIGH)
```
GOAL: Keep access after logout / password change / admin revoke
└─ AND
   ├─ Capture a still-unexpired access token (XSS, log, proxy, device theft)
   └─ Backend never checks revocation
       ├─ token_version captured but never compared  (middleware.go:163-165)
       ├─ no introspection on hot path (IntrospectToken exists, unused, client.go:741)
       └─ no revocation list / no token binding
          └─ RESULT: token valid until exp regardless of server-side revoke
KILL: token_version callback OR introspect-on-sensitive-route  ✅ shipped v1.8.0 (#17, WithRevocationCheck)
```

### F-3 / INV-6 — Cross-tenant access via absent tenant (HIGH)
```
GOAL: Read/write across tenant boundaries
└─ OR
   ├─ Default-config path (no compensating control)
   │   ├─ Socrate default does NOT issue tenant_id (middleware.go:38-40)
   │   ├─ GetTenantID → uuid.Nil, no error (ctxutil.go:49-54)
   │   └─ downstream query scoped to Nil tenant → shared/global rows
   └─ Overwrite path
       └─ any in-binary code calls WithTenantID again (exported, ctxutil.go:44)
          → no write-once invariant
KILL: RequireTenant middleware (401 on uuid.Nil) + write-once tenant  ✅ RequireTenant shipped v1.8.0 (#15); write-once = v2.0
```

### F-4 / INV-8 — Rate-limit / abuse-control bypass (HIGH)
```
GOAL: Flood the service / brute force without throttling
└─ OR
   ├─ Default-config bypass
   │   └─ nil-tenant request passes through unlimited (ratelimit.go:108-112)
   │      (and default tokens carry no tenant → ALL requests bypass)
   ├─ Horizontal scale bypass
   │   └─ in-memory limiter per instance (ratelimit.go:43)
   │      → effective limit = N_instances × rps
   └─ Tenant-internal DoS
       └─ one user exhausts the shared per-tenant bucket (getLimiter keyed on tenant only)
KILL: fallback key (subject/IP) + distributed store (Redis) + per-subject buckets  ◑ partially mitigated by RequireTenant (#15); limiter changes still open
```

---

## 8. Compliance Mapping

| Framework | Control | backendkit posture | Evidence |
|-----------|---------|--------------------|----------|
| **OWASP ASVS 4.0** | V2.1 token verification | ◑ alg/sig ✔, aud ✗ | `middleware.go:193`/F-1 |
| | V3.3 session/token revocation | ✗ | F-2 |
| | V4.1 mandatory access control | ◑ opt-in | `rbac.go`/INV-7 |
| | V4.2 BOLA/object-level | ✗ (app) | Phase 4 |
| | V7.1 log no sensitive data | ◑ SQL values | `gormlogger:88-95`/F-9 |
| | V8.3 no secret in logs | ✔ | `aigateway:91-95` |
| | V14.4/14.5 security headers | ✔ | `security.go:17-29` |
| **OWASP API Top 10 (2023)** | API1 BOLA | ✗ (app-owned) | no object-level authz |
| | API2 Broken Auth | ◑ aud+revocation gaps | F-1, F-2 |
| | API3 BOPLA / mass-assignment | ✔ typed structs | `socrate client.go:309-401` |
| | API4 Unrestricted Resource Consumption | ◑ | F-4, F-8 |
| | API5 BFLA | ◑ opt-in RBAC | INV-7 |
| | API8 Misconfiguration | ◑ empty-issuer default | F-5 |
| **CWE** | CWE-287 improper auth | F-1 | INV-2 |
| | CWE-613 insufficient expiration/revocation | F-2 | INV-3 |
| | CWE-284/639 improper access / IDOR | F-3 | INV-6 |
| | CWE-770 alloc without limit | F-8 | INV-12 |
| | CWE-799 improper interaction frequency | F-4 | INV-8 |
| | CWE-532 info in log | F-9 | INV-10 |
| | CWE-209 error info exposure | F-17 | INV-9 |
| | CWE-88/74 argument/URL injection | F-7 | INV-11 |
| | CWE-326 inadequate key strength | F-10 | INV-13 |
| **NIST 800-53** | IA-2/IA-5 auth & credentials | ◑ | F-1/F-2 |
| | AC-3/AC-4 access & flow enforcement | ◑/✗ | INV-6/INV-7 |
| | AU-2/AU-9 audit & protection | ✗ native | INV-14 |
| | SC-5 DoS protection | ◑ | F-4/F-8 |
| | SC-12/13 crypto & key mgmt | ◑ | F-10 |
| | SI-10 input validation | ◑ | F-7 |
| **SOC 2 (TSC)** | CC6.1 logical access | ◑ | F-1/F-3 |
| | CC6.6 boundary protection | ◑ | INV-6 |
| | CC7.2 monitoring | ◑ correlation ✔, audit ✗ | INV-14 |
| | CC8.1 change mgmt | ✔ deprecation discipline | `ctxutil.go:235-247` |
| **ISO 27001:2022 Annex A** | A.5.15 access control | ◑ | INV-7 |
| | A.5.17 authentication info | ◑ | F-2 |
| | A.8.16 monitoring | ◑ | INV-14 |
| | A.8.24 use of cryptography | ◑ | F-10 |
| | A.8.28 secure coding | ✔ | lint/vet/race CI `ci.yml:34-37` |

**Net:** clean passes on headers, secret-hygiene, typed I/O, and secure-coding
process; **conditional/fail** on token audience, revocation, mandatory access
control, tenant isolation, native audit, and key-strength — the regulated-industry
blockers.

---

## 9. Security Regression Test Suite (to lock the invariants)

The current suite covers valid/missing/tampered tokens only
(`jwtauth/middleware_test.go:73-166`). To make the invariants *enforced and
non-regressing*, add:

```
jwtauth (INV-2,3,4):
  TestRejectsAlgNone                  // forge {"alg":"none"} → 401
  TestRejectsHS256WithPublicKey       // alg-confusion → 401
  TestRejectsWrongAudience            // aud=app-A token at app-B → 401   (RED until F-1 fixed)
  TestRejectsExpired                  // exp in past → 401
  TestEnforcesIssuerWhenConfigured    // bad iss → 401
  TestRejectsMissingKid               // no kid → 401
  TestRejectsStaleTokenVersion        // token_version < current → 401     (RED until F-2 fixed)
  TestRejectsUndersizedRSAKey         // 1024-bit JWKS key → reject         (RED until F-10 fixed)

httpware (INV-5,8,9):
  TestContextIdentityNotForgeableViaHeader  // X-User-Role header ignored
  TestRateLimitDeniesNilTenant              // no-tenant request throttled   (RED until F-4 fixed)
  TestRecoverHidesStackFromClient           // body has no stack/panic text

tenant (INV-6):
  TestRequireTenantRejectsNil               // uuid.Nil → 401               (RED until F-3 fixed)

socrate (INV-11):
  TestPathParamsAreEscaped                  // userID="../x" cannot escape path (RED until F-7 fixed)

apierror (INV-9):
  TestInternalMessageNotLeaked              // 5xx body omits raw Message    (RED until F-17 fixed)
```

The "RED until fixed" cases are the **executable specification of the missing
invariants** — they should be committed now as failing/skipped tests so the gaps
cannot silently persist.

---

## 10. Supply-Chain Review

**Direct dependencies (`go.mod`):** 5 — `golang-jwt/jwt/v5 v5.2.1`,
`google/uuid v1.6.0`, `sirupsen/logrus v1.9.3`, `golang.org/x/time v0.15.0`,
`gorm.io/gorm v1.25.11`. Indirect: `jinzhu/inflection`, `jinzhu/now`,
`golang.org/x/sys v0.28.0`, `golang.org/x/text v0.14.0`. Test-only:
`stretchr/testify`, `objx`, `go-spew`, `go-difflib`, `yaml.v3`.

**Assessment:** small, reputable, well-maintained surface — architecturally a
strong position (minimal attack surface, no obscure transitive auth/crypto libs).

**Integrity controls present:** `go.sum` is pinned and **CI verifies it is tidy**
(`ci.yml:25-28`), build/test run with `-race` (`ci.yml:34`), `go vet` and
`golangci-lint v2.5.0` gate PRs (`ci.yml:36-51`).

**Architectural gap (violates the spirit of INV-12/process):**
- **No Software-Composition-Analysis in CI** — `ci.yml` has **no `govulncheck`,
  no `gosec`, no Dependabot/Renovate, no `mcp__github__run_secret_scanning`
  wiring**. There is no continuous mechanism to learn that a pinned dependency
  became vulnerable.
- **`golang-jwt/jwt/v5 v5.2.1` is a stale auth-critical pin.** This line is the
  cryptographic trust root of the whole framework; the v5.2.x line received a
  security fix for excessive memory allocation while parsing attacker-controlled
  tokens (DoS) in **v5.2.2**. Pinning the verifier one patch below the latest
  security release, with no SCA to flag it, is the supply-chain finding that most
  directly intersects the auth boundary and INV-12. *Action: bump to the latest
  v5.2.x and add `govulncheck` to CI; treat any advisory on the JWT/crypto deps as
  release-blocking.*

(Per rules of engagement, this is raised because it bears on INV-12 / the auth
trust root, not as a generic version-bump nit.)

---

## 11. Cryptographic Architecture Review

- **Primitive surface is deliberately tiny:** the only cryptography backendkit
  *performs* is **RS256 signature verification**, fully delegated to
  `golang-jwt/v5` with the algorithm pinned (`middleware.go:193, 199-201`). No
  bespoke crypto, no symmetric ciphers, no MAC, no nonce/IV management — the safest
  possible posture. ✔
- **Randomness:** identifiers come from `google/uuid` v4 (`requestid.go:22`,
  `middleware.go:138`), `crypto/rand`-backed. The only `math/rand`/`crypto/rand`
  import is in a test (`middleware_test.go:4`). ✔
- **Hashing:** `uuid.NewSHA1` (`middleware.go:138`) is an *identifier-derivation*
  use (namespaced sub→UUID), not a security MAC — benign. ✔
- **Trust anchor & key lifecycle:** verification keys are pulled from the JWKS URL
  over HTTPS, cached 1h with stale-fallback (`middleware.go:215-283`). **Weaknesses
  that violate INV-13:** (a) no minimum modulus check and exponent truncated via
  `Int64()` (`middleware.go:285-298`) → a downgraded/mis-served small key is
  trusted; (b) no key-set pinning beyond TLS; (c) no `singleflight` on refresh.
- **What is correctly *out of scope* (delegated):** password hashing (Socrate
  server bcrypt, `socrate/admin.go:51`), encryption at rest, secret storage, TLS
  termination. The architecture cleanly pushes these to the IdP / platform.

**Crypto verdict:** *correct by minimalism and delegation*; the single defect is
trust-anchor strength validation (INV-13).

---

## 12. Framework Evolution Plan

Sequenced to convert VIOLATED/PARTIAL invariants to VERIFIED with least churn:

**Phase A — additive, non-breaking (next minor, v1.x):**
- INV-6: ship `httpware.RequireTenant` (401 on `uuid.Nil`).
- INV-3: `jwtauth.WithRevocationCheck(fn)` option (token_version / introspection).
- INV-11: `url.PathEscape` all `socrate` path segments.
- INV-12/13: `io.LimitReader` on upstream reads; reject `N.BitLen() < 2048`.
- INV-10: `gormlogger` redaction/disable hook (default: no bound values in prod).
- Process: add `govulncheck` + Dependabot to `ci.yml`; bump `golang-jwt` to latest.
- Add the §9 regression suite (failing cases skipped behind a build tag).

**Phase B — opt-in security, default-off (v1.x+1):**
- INV-2: `jwtauth.WithAudience(...)` available but not yet default.
- INV-7: `Config.Validate()` that warns when no authz middleware is mounted on a
  protected group; `jwtauth.New` warns on empty issuer.

**Phase C — flip defaults, breaking (v2.0.0):**
- INV-2: audience **required** by default.
- INV-5/INV-6: tenant becomes **write-once** in context.
- INV-9: `apierror` stops serializing `Message` for 5xx; introduces `PublicMessage`.
- INV-14: ship an append-only `AuditSink` interface (durable/tamper-evident writer).

---

## 13. Backward-Compatibility Strategy

- **Compatibility contract:** follow SemVer strictly. All Phase A/B items are
  additive (new functions/options) → **no import breakage**; existing callers
  compile and behave unchanged.
- **Breaking changes are quarantined to v2.0.0** and pre-announced one minor in
  advance via `// Deprecated:` doc markers, mirroring the existing discipline
  already visible in the codebase (`ctxutil.go:235-247` keeps `GetTenantTier`/
  `WithTenantTier` aliases). Reuse that exact pattern.
- **Migration aids:** provide `v1`→`v2` shims (e.g. `jwtauth.NewLegacy` that keeps
  audience optional) and a `CHANGELOG`/`MIGRATION.md` enumerating each flipped
  default and the one-line fix.
- **Feature flags over forks:** every default-flip in Phase C must be reachable as
  an explicit opt-out in v2 (e.g. `WithoutAudience()`) so a large consumer can
  upgrade the dependency and adopt the stricter defaults incrementally.
- **CI gate:** `go test ./...` of a pinned downstream consumer (Kerplan) in the
  release workflow to catch accidental breakage before tagging.

---

## 14. Security Maturity Score

Scale 0–5 (0 ad-hoc · 3 defined/repeatable · 5 optimised). Levels below are
**post v1.8.0**; the pre-remediation level is shown in parentheses.

| Dimension | Level (v1.8.0) | Basis |
|-----------|:-----:|-------|
| Secure design | **4** (was 3) | Controls provided for every Critical; fail-closed gates; minimal crypto |
| AuthN/AuthZ completeness | **3** (was 2) | aud + revocation + issuer-warning shipped; object-level & mandatory-authz still gaps |
| Invariant enforcement | **4** (was 2) | **0 violated**, 2 partial, 3 verified✱(opt-in), 8 verified (§6) |
| Crypto architecture | **4** (was 3) | Delegated + pinned; min key size enforced (#19) |
| Supply-chain assurance | **3** (was 2) | `govulncheck` clean on Go 1.26.4, deps current (#11/#13); still **no SCA job in CI** |
| Verification/testing | **3** (was 2) | Negative tests for aud/revocation/key-size/oversized-JWKS/path-escape/redaction; `alg=none` still missing |
| Observability/audit | **3** (was 2) | Good correlation; opt-in SQL redaction (#27) closes log leakage; no native audit writer |
| Process (CI/lint/deprecation) | **4** (—) | race+vet+lint, SemVer + changelog discipline, shipped v1.8.0 + v1.9.0 cleanly |
| **Overall maturity** | **≈3.6 / 5** (was 2.5) | "Hardened; zero violated invariants; default-on guarantees + native audit pending v2.0" |

## 15. Enterprise Readiness Score

Post v1.8.0 + v1.9.0 (pre-remediation score in parentheses):

| Use as… | Score /10 | Rationale |
|---------|:---------:|-----------|
| Trusted **dependency / component** (app supplies compensating controls) | **8** (was 7) | Controls present in-framework; remaining gaps documented |
| **Sole** security foundation, single-tenant SaaS | **8** (was 6) | All High + Medium closed; in-memory rate limit accepted single-instance |
| **Sole** security foundation, **multi-tenant enterprise** | **7** (was 4) | INV-2/3/6 controls present but opt-in (must be enabled); distributed rate-limit store still open |
| Regulated (HIPAA/PCI/Gov) | **5** (was 3) | Revocation, key-strength, log minimisation, error redaction addressed; native audit durability still unmet |

---

## 16. Final Recommendation

> **If this framework were open-sourced today, would I recommend it as the
> security foundation of multiple enterprise SaaS products?**

**As a published *component library*: yes, with a documented
shared-responsibility model. As the *sole security foundation* for multiple
enterprise multi-tenant SaaS products: not yet — not until the four violated
invariants are closed.**

The architecture is honest and well-shaped: a single, tiny, correctly-delegated
cryptographic core (RS256, alg-pinned at two layers, `middleware.go:193,199-201`),
fail-closed authentication (`middleware.go:106-118`), un-forgeable in-process
identity (`ctxutil.go:20-39`), crash containment without disclosure
(`recover.go:18-23`), strong response headers (`security.go:17-29`), and a mature
engineering process (race+vet+lint CI `ci.yml:34-51`, SemVer/deprecation
discipline `ctxutil.go:235-247`). Those are exactly the traits I want in a
dependency.

But a *security foundation* is judged on its invariants, and four are provably
violated in code: **no audience binding** (INV-2/F-1), **no revocation**
(INV-3/F-2), **fail-open tenant isolation** (INV-6/F-3), and **bypassable abuse
control** (INV-8/F-4) — each demonstrated by an attack tree in §7 that succeeds
against the *default* configuration. Defense-in-depth at the core is shallow
(§5): every one of these has exactly one barrier, and that barrier is optional,
absent, or bypassable. Compounding it, the auth trust root is pinned to a
JWT library one security-patch behind, with no SCA in CI to ever notice (§10).

The encouraging part is that **none of this is a redesign.** §12 converts every
violated invariant to VERIFIED through additive v1.x work plus one curated v2.0
default-flip, and §9 gives the executable regression suite that keeps them closed.
Ship those, add `govulncheck` and the audience/tenant/revocation defaults, and
this becomes a framework I *would* endorse as an enterprise security foundation.

**Recommendation: APPROVE AS A DEPENDENCY behind a shared-responsibility doc;
WITHHOLD as a sole multi-tenant enterprise security foundation until INV-2,
INV-3, INV-6, and INV-8 are enforced.**

### Revised standing — post v1.8.0 + v1.9.0 (2026-06-20)

The entire v1.x roadmap anticipated above **has shipped.** v1.8.0 provided every
previously-violated control — audience binding (`WithAudience`, #7), revocation
(`WithRevocationCheck`, #17), tenant enforcement (`RequireTenant`, #15) — plus
default-on weak-key rejection (#19). **v1.9.0 closed every Medium and the last
VIOLATED invariant:** socrate path-escaping (#23, INV-11 → VERIFIED), bounded
upstream reads (#25, INV-12 → VERIFIED), gormlogger SQL redaction (#27, INV-10),
5xx error redaction (#29, INV-9 → VERIFIED), and the empty-issuer warning (#31).
**No invariant is VIOLATED.** INV-8 is the lone abuse-control caveat (distributed
rate-limit store still pending). `govulncheck` passes on Go 1.26.4 with
`golang-jwt v5.2.2`. The §7 attack trees no longer succeed against a correctly
configured deployment — their "KILL" lines are shipped code.

The one structural caveat that remains: INV-2/INV-3/INV-6 are **opt-in** (the
`✱` in §6), so the guarantee holds only when each app enables them. The remaining
v2.0 work is the default-flip (audience required, tenant write-once), a distributed
rate-limit store (INV-8), a native audit writer (INV-14), and a `govulncheck` CI
job.

**Revised recommendation: APPROVE AS A DEPENDENCY, and APPROVE as a multi-tenant
enterprise security foundation *for any service that enables the shipped controls*
(`WithAudience` + `WithRevocationCheck` + `RequireTenant`). With all High and
Medium findings closed, full by-default endorsement awaits only the v2.0
default-flips.**

### Verification limits (no speculation)
The following are **delegated trust** and cannot be verified from this repo —
they must be confirmed in the Socrate server and deployment config before any
"yes" upgrades: that Socrate issues scoped `aud` and `tenant_id` and honours
`token_version`; that TLS terminates in front of the binary and the :8081 admin
port is network-isolated (`client.go:19-21`); and that each consuming app actually
mounts RBAC/Gate/RequireTenant on every protected route.
