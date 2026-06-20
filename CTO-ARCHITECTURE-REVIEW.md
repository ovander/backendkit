# Final Pass — CTO Architecture Review

**Subject:** `backendkit` as a platform dependency, projected to: 50 teams,
300 developers, hundreds of SaaS products, thousands of services.
**Lens:** CTO accountable for the next five years. **Not** security, **not**
bugs, **not** style. One question only:

> If we keep building on backendkit for five years, which architectural decisions
> made *today* become tomorrow's technical debt — and how do we maximise the
> framework's **architectural half-life**?

The governing law of this review is **Hyrum's Law**: at thousands of services,
every observable behaviour — every import path, every JSON field, every
zero-value fallback, every transitive dependency version — becomes a contract
someone depends on. The cost of changing a decision scales with the number of
consumers, not the size of the change. So the debt that matters is not "what is
wrong" but "what is **load-bearing and hard to reverse**."

---

## The Master Decision: bundling components of radically different half-life

Before the individual decisions, the strategic one that frames them all.

`backendkit` is a **single Go module** (`module github.com/ovander/backendkit`)
that bundles, under one version and one dependency closure, components whose
*natural half-lives differ by one to two orders of magnitude*:

| Component | What it tracks | Natural half-life |
|-----------|----------------|-------------------|
| `apierror`, `ctxutil`, `pagination` | language + HTTP semantics | **~decade** |
| `httpware` | `net/http` middleware shape | ~5–10 yr |
| `jwtauth` | JWT/JWKS standards | ~5 yr |
| `tiering` | *a* product's billing model | ~2–3 yr |
| `socrate` | one IdP's private API (dual-port :8080/:8081) | ~1–2 yr |
| `aigateway` | OpenAI/Anthropic wire formats | **~6–12 mo** |
| `ainarration` | a product feature | months |

**Putting a 6-month-half-life component (`aigateway`) in the same versioned,
co-released unit as a 10-year component (`apierror`) is the root architectural
debt.** It forces one of two failures: either the stable core is dragged into
churn every time OpenAI changes a field, or the fast-moving clients ossify to
avoid breaking the core's SemVer promise. Every decision below is a special case
of this: *the framework has not separated platform primitives (stable, universal)
from product services (volatile, opinionated).*

Everything that follows is ranked by **reversal cost at scale**.

---

## D1 — Single module / one version / one dependency closure

**Decision today.** One `go.mod`; `apierror` (zero real deps) and `socrate`/
`tiering` (gorm, jwt, logrus) ship as one importable unit with one version line.

**Why it becomes painful.** Three compounding failures at scale:
1. *Imposed dependency graph.* Every service that imports `apierror` inherits the
   framework's `gorm`/`jwt`/`logrus` versions in its build. A team that needs a
   newer gorm than the framework pins gets a diamond conflict — the framework
   dictates dependency versions for thousands of services (the Terraform-provider
   problem).
2. *Coupled release cadence.* A breaking change in `aigateway` forces a major-version
   bump of the whole module, which by SemVer changes the import path
   (`/v2`) for `apierror` too — a package that did not change.
3. *Blast radius.* One CVE or one API break anywhere is a fleet-wide event.

**When.** Begins hurting at ~dozens of services; acute once the fast-moving
clients (`aigateway`, `socrate`) iterate on their own schedule — **12–24 months**.

**Cost to change later.** **Very high and super-linear.** Splitting modules after
thousands of import sites means a coordinated import-path migration across every
service (see D2). Early: a week of repo plumbing. Late: a multi-quarter,
multi-team migration program.

**Change before v2.0?** **Yes — this is the one that must land in v2.0.** Module
boundaries are the single least-reversible decision in Go.

**Migration strategy.** Multi-module repo + `go.work`: `backendkit` (core,
std-lib + uuid), `backendkit/auth`, `backendkit/tiering`,
`backendkit/integrations/{socrate,ai,gorm}`, `backendkit/otel`. Synchronised
majors, independent minors.

**Compatibility strategy.** Keep v1 as a thin meta-module that re-exports the new
locations via type aliases for one major, so existing imports compile during the
window.

**Alternatives.** (a) Stay monolithic and accept imposed deps — viable only for an
internal library, fatal for a platform. (b) Two modules (core vs. everything-else)
— half the benefit, half the work; a reasonable compromise if full decomposition
is too costly.

**Trade-offs.** Multi-module versioning is operational overhead (release matrix,
`go.work`); the payoff is that `import apierror` becomes free and each layer
versions on its own clock.

---

## D2 — The import path is a personal namespace (`github.com/ovander/...`)

**Decision today.** The module identity is a single person's GitHub account.

**Why it becomes painful.** The import path *is* the public API in Go — it is
interned into every file of every consumer. A personal namespace signals
single-owner risk to 50 adopting teams, ties the framework's identity to an
individual account's lifecycle, and is the hardest thing to change later because
**every `.go` file in thousands of services names it**.

**When.** A governance/perception problem from day one of broad adoption; a
*mechanical* problem the moment you want to move it — and that only gets worse.

**Cost to change later.** **The single most expensive refactor in Go.** Changing
an import path touches every consumer simultaneously; there is no gradual path
without a compatibility shim module. Cost grows strictly with adoption.

**Change before v2.0?** **Yes — do it with the v2 module split (D1), once.** Never
pay an import-path migration twice.

**Migration strategy.** Adopt a vanity/org path (`go.<org>.dev/backendkit` or a
neutral foundation-style domain) using `go-import` meta tags so the canonical path
is decoupled from the hosting provider forever after. Bundle the rename into the
v2 cutover so teams absorb one migration, not two.

**Compatibility strategy.** Publish the old path as a deprecated alias module that
type-aliases to the new one for one major version.

**Alternatives.** Keep the personal path — only defensible if the framework will
never outlive or exceed its author, which contradicts the premise.

**Trade-offs.** A vanity domain needs a tiny redirect service/hosting; the cost is
trivial against the value of a stable, ownership-neutral identity.

---

## D3 — A specific logging library (logrus) in the public API

**Decision today.** logrus types appear in constructors across the framework and
`ctxutil` stores/returns logrus entries — the logger *is* part of the contract.

**Why it becomes painful.** It dictates the logging stack of 300 developers, and
it bet on a library now in maintenance mode while the standard library shipped
`log/slog`. A logging choice baked into a *public signature* has a short half-life
and a wide blast radius: every consumer writes against logrus types, so the
ecosystem's move to slog is blocked by the framework.

**When.** Already underway; acute within **12 months** as slog becomes the default
everywhere and new hires expect it.

**Cost to change later.** **Medium-high but unavoidable.** Every signature and
every call site changes. Cheaper than D1/D2 (it's leaf-level, mechanical) but
touches a lot of surface.

**Change before v2.0?** **Yes.** Logging is a contract; flip it at the major.

**Migration strategy.** Move all signatures to `*slog.Logger`; ship a logrus→slog
`slog.Handler` adapter so teams on logrus keep their pipelines unchanged.

**Compatibility strategy.** v1.x adds slog-accepting variants alongside logrus and
deprecates the latter; v2 removes logrus.

**Alternatives.** Define a minimal internal `Logger` interface instead of binding
to slog — maximal decoupling, but reinvents what slog standardised; only worth it
if you must support pre-1.21 toolchains (you don't, given Go 1.25).

**Trade-offs.** slog's attribute semantics differ slightly from `WithField`; the
adapter and a mapping doc absorb that.

---

## D4 — Transport coupling: `net/http` is the only first-class citizen

**Decision today.** The framework's spine is `func(http.Handler) http.Handler`;
auth, RBAC, tiering, rate limiting are all HTTP-middleware-shaped.

**Why it becomes painful.** Across thousands of services, a meaningful fraction
will be gRPC / ConnectRPC / event-driven / queue consumers. None of them can reuse
`jwtauth`, `RBAC`, or `tiering` because those are welded to `http.Handler`. Teams
will re-implement auth and authz per transport — exactly the duplication the
framework exists to prevent. **Kratos and go-kit abstract transport for precisely
this reason.**

**When.** The day the second transport matters — **2–3 years** as the service mesh
diversifies.

**Cost to change later.** **High.** The *logic* (verify token → principal →
authorize) is sound but entangled with `http.ResponseWriter`. Re-seating it onto a
transport-neutral core after thousands of HTTP call sites exist is a deep refactor.

**Change before v2.0?** **Partially.** Don't build gRPC now, but **extract the
transport-neutral core in v2** so HTTP becomes one adapter, not the substrate.

**Migration strategy.** Factor each control into a pure core (`Verify(ctx, raw)
→ Principal`, `Authorize(ctx, principal, request) → Decision`) with thin
`net/http` adapters. gRPC interceptors and queue middleware become additional
adapters over the same core, later.

**Compatibility strategy.** The existing HTTP middleware keeps its exact signatures
as the first adapter — no consumer change.

**Alternatives.** Stay HTTP-only — acceptable if the org is forever HTTP; a real
bet against five years of transport evolution.

**Trade-offs.** One layer of indirection between core and transport; the upside is
write-auth-once across every protocol.

---

## D5 — Identity modelled as flat, optional, zero-value context getters with IdP semantics in core

**Decision today.** Identity is a set of independent context values
(`GetUserID`, `GetTenantID`, `GetUserRole`, `GetUserPlan`, …) that **return
zero-values when absent** (`uuid.Nil`, `""`, `"freemium"`) with no error, and the
claim *names and semantics are Socrate's*, embedded in core `ctxutil` and `jwtauth`.

**Why it becomes painful.** Two distinct debts:
1. *No `Principal` concept.* Identity is a bag of scalars, so the model cannot grow
   to express **impersonation / on-behalf-of, service identity vs. user identity,
   delegated tenancy, or multiple simultaneous roles** — all of which large
   multi-tenant orgs eventually need. Adding them later means changing the meaning
   of getters that thousands of services already call.
2. *Zero-value fallbacks are Hyrum landmines.* `GetUserPlan → "freemium"` and
   `GetTenantID → uuid.Nil` make "absent" indistinguishable from "present and
   default." Thousands of services will encode "if plan == freemium" logic that
   silently fires on *missing* identity. You can never tighten this to return an
   error without breaking them.
3. *Socrate's identity model is the framework's identity model.* Some of 50 teams
   will not use Socrate (acquisitions, partner SSO, standard OIDC). The core
   shouldn't know what `app_roles` or `plan` mean.

**When.** The first impersonation/multi-identity requirement, or the first non-Socrate
IdP — **18 months to 3 years**.

**Cost to change later.** **High.** Identity is referenced everywhere; reshaping it
is a fleet-wide change. The zero-value contract in particular is effectively frozen
by Hyrum once products depend on it.

**Change before v2.0?** **Yes — introduce a `Principal` and move IdP semantics to an
adapter in v2.** This is core and rarely revisited.

**Migration strategy.** Define an opaque `Principal` carried as one context value;
the existing scalar getters become convenience accessors over it. Socrate claim
mapping moves to a `socrate` adapter. New, explicit "present?" APIs
(`Principal.Tenant() (uuid.UUID, bool)`) coexist with the old zero-value getters.

**Compatibility strategy.** Keep the flat getters (deprecated) reading from the
`Principal`; both work through the v2 window.

**Alternatives.** Keep scalars and add ad-hoc keys per new need — the status quo,
which accretes the debt rather than resolving it.

**Trade-offs.** A `Principal` is slightly more ceremony for the common case; it buys
an identity model that can evolve without rewriting consumers.

---

## D6 — The JSON error envelope is an unversioned cross-boundary wire contract

**Decision today.** `apierror` emits `{"error":{"code":"...","message":"...",
"key":"...","details":...}}` with a fixed set of `code` strings.

**Why it becomes painful.** This shape crosses the framework boundary into **every
frontend and every consuming service**. By Hyrum's Law it ossifies the instant the
first frontend switches on `error.code == "validation_error"`. Yet it has **no
schema, no version field, and no content negotiation**. It is simultaneously the
most depended-upon contract in the framework and the least formally governed. The
day you need to evolve it (RFC 9457 `application/problem+json`, nested errors,
multi-error responses, machine-readable field paths) you cannot, because thousands
of clients parse the current shape exactly.

**When.** It is *already* frozen the moment of broad adoption; the pain arrives when
you first need to change it — **any time**, and you'll find you can't.

**Cost to change later.** **High and externalised** — the breakage lands on
frontend teams and API consumers you may not even control (partners, public APIs).

**Change before v2.0?** **Yes — stabilise it deliberately now**, while you still
can choose the shape, rather than discovering the accidental one is permanent.

**Migration strategy.** Adopt a versioned, standards-aligned envelope
(RFC 9457 problem+json) behind content negotiation, register the `code` vocabulary
as an explicit, documented enum, and treat it as a published API with its own
compatibility policy.

**Compatibility strategy.** Emit the legacy shape by default; opt into the new
shape via `Accept`/media-type so old and new clients coexist indefinitely.

**Alternatives.** Freeze the current shape forever and only ever *add* optional
fields (never remove/rename) — a legitimate, low-effort strategy *if you commit to
it explicitly today*. The danger is doing this by accident instead of by decision.

**Trade-offs.** Content negotiation adds a little complexity; it is the only way to
evolve a contract with uncontrolled consumers.

---

## D7 — Business semantics embedded in shared infrastructure (the tier model)

**Decision today.** A commercial three-tier model (`freemium`/`pro`/`enterprise`)
and a `"freemium"` default live inside shared libraries (`tiering`, and a default
baked into `ctxutil`).

**Why it becomes painful.** Hundreds of *different* SaaS products will not share one
billing model — seats, usage-based, per-feature entitlements, free-trial states,
non-commercial internal tools. A generic platform that assumes a specific monetisation
shape fights every product that monetises differently, and the `"freemium"` default
silently misclassifies any product that doesn't use that word.

**When.** The second distinct billing model in the portfolio — **12–24 months**.

**Cost to change later.** **Medium.** `tiering` is already partly abstracted
(`PlanRegistry`, `PolicyRepository`), so the debt is the *defaults and placement*,
not the whole design.

**Change before v2.0?** **Yes, cheaply** — relocate business defaults out of core.

**Migration strategy.** Move the tier vocabulary and the `"freemium"` fallback into
a product-supplied policy/adapter; core ships only the *mechanism* (ordered
registry, entitlement check), never a *policy*. Reframe `tiering` as a generic
"entitlements" engine, with tiers as one configuration of it.

**Compatibility strategy.** Ship the current three-tier registry as a provided
default config, not a core constant.

**Alternatives.** Leave it — fine for a single-product company, wrong for a
multi-product platform.

**Trade-offs.** Slightly more setup per product; the platform stops encoding one
team's pricing.

---

## D8 — In-process, in-memory state with no distributed-state seam

**Decision today.** Rate-limit buckets, JWKS cache, and policy cache are
process-local maps. The architectural assumption is "one process, local state."

**Why it becomes painful.** At thousands of autoscaled, multi-region services,
process-local state means rate limits multiply by replica count, caches can't be
invalidated fleet-wide, and there is no seam for a coordinated control plane. The
debt is not the in-memory *implementation* — that's a fine default — it's the
**absence of a store interface**, which forces 50 teams to each fork or work around
the stateful components.

**When.** First multi-region or aggressive-autoscaling workload — **18 months–3 yr**.

**Cost to change later.** **Medium.** Retrofitting an interface under a concrete
impl is mechanical; the cost is the call sites that assumed local semantics.

**Change before v2.0?** **Yes — introduce the interfaces** (keep in-memory as the
default adapter). Interfaces are cheap now, expensive to insert after forks
proliferate.

**Migration strategy.** Define `RateStore` / `KeySetCache` (and a `KeyFunc` for the
limiter key) with `memory.*` defaults and `redis.*` adapters in a separate module.

**Compatibility strategy.** Default to the in-memory adapter so current behaviour is
byte-for-byte unchanged unless a store is supplied.

**Alternatives.** Stay in-memory — guarantees every team builds their own
distributed limiter, defeating the framework's purpose.

**Trade-offs.** An interface boundary on a hot path (must support atomic
check-and-decrement); negligible cost for correctness at scale.

---

## D9 — Fleet governance by convention, not by a control-plane seam

**Decision today.** The "correct" middleware stack and its order are documented in
prose and assembled by each service's own `r.Use(...)` calls.

**Why it becomes painful.** With 300 developers, convention drifts: every service
wires its own stack. When the org must push a *mandatory* change across the fleet —
a new compliance header, a new tracing requirement, a kill-switch — **there is no
seam to do it.** You file 2,000 PRs. A platform at this scale needs a single,
versioned "standard stack" object that services adopt by reference, so the platform
team can evolve the fleet centrally.

**When.** The first org-wide mandate — **12–18 months**.

**Cost to change later.** **Medium**, but recurring: every un-seamed mandate is a
fleet-wide manual campaign.

**Change before v2.0?** **Yes, additively** — ship a composed, versioned
`RecommendedStack` that teams adopt as one line.

**Migration strategy.** Provide a `Stack`/`Chain` value encoding the standard order;
services call `stack.Then(handler)`. Platform updates flow by bumping the stack.

**Compatibility strategy.** Purely additive; raw `r.Use` keeps working.

**Alternatives.** Linting/policy-as-code to enforce ordering — complementary, but no
substitute for a single point of evolution.

**Trade-offs.** Centralising the stack trades per-team flexibility for fleet
governability — exactly the trade a platform should make.

---

## Consolidated Debt Ledger

| # | Decision | Pain onset | Reversal cost @ scale | Land in v2.0? |
|---|----------|-----------|------------------------|---------------|
| D1 | Single module / one dep closure | 12–24 mo | **Very high** | **Must** |
| D2 | Personal import path | day one / on move | **Highest (mechanical)** | **Must** |
| D5 | Flat identity + IdP-in-core | 18–36 mo | High | **Should** |
| D4 | HTTP-only transport | 24–36 mo | High | Extract core; full later |
| D6 | Unversioned error wire contract | already frozen | High (externalised) | **Should (stabilise)** |
| D3 | logrus in public API | <12 mo | Medium-high | **Should** |
| D8 | In-memory state, no store seam | 18–36 mo | Medium | Seam now |
| D7 | Business model in core | 12–24 mo | Medium | Cheap now |
| D9 | Governance by convention | 12–18 mo | Medium (recurring) | Additive now |

**Rule of thumb for sequencing:** the **irreversible packaging decisions (D1, D2)
must be made before v2.0**, because their cost is the only one that grows without
bound. The **seams (D4, D5, D8, D9)** should be *opened* in v2.0 even if the second
implementation comes later — inserting an interface is cheap before forks exist and
expensive after. The **contracts (D3, D6, D7)** should be *deliberately chosen* now
rather than allowed to ossify by accident.

---

## What decisions made today will still look correct in 2035?

Not everything here is debt. Several decisions have a long half-life *because they
bound the framework to durable, external standards rather than to fashions* — and
they should be **protected** through every migration above:

1. **The standard middleware signature `func(http.Handler) http.Handler`.** It is
   the `net/http` lingua franca; aligning to the platform interface (rather than a
   bespoke one) means the HTTP layer composes with the entire Go ecosystem. Even
   when transport is abstracted (D4), keeping this as *the HTTP adapter's* shape is
   correct for a decade.
2. **Unexported, typed context keys accessed only through helpers.** The decision to
   make context keys collision-proof and private is correct forever; the only change
   is *what* they carry (a `Principal`), not *how* they're keyed.
3. **Structured, typed errors that separate machine `code` from human `message`
   from i18n `key`.** The separation is exactly right and ages well; only the
   *envelope versioning* (D6) needs governance.
4. **Configuration injected as values; no environment reads inside packages.** This
   12-factor discipline is timeless and is what makes the whole framework testable
   and embeddable.
5. **Interfaces at the data boundary (the `PolicyRepository` pattern).** The one
   place the framework already inverted a dependency is the template for everything
   else; that instinct was correct and should be generalised, not undone.
6. **A small, reputable, std-lib-leaning dependency set, and pure middleware with no
   shared mutable request state.** Minimalism is the single best predictor of long
   half-life; resist every temptation to grow the core's dependency surface.
7. **Deprecation discipline via documented aliases.** The process already practised
   in the codebase is precisely how you keep faith with thousands of consumers
   across majors; institutionalise it (D-governance) rather than leaving it ad hoc.

**The through-line:** the decisions that will still look correct in 2035 are the ones
that **coupled backendkit to enduring standards — `net/http`, `context`, `log/slog`,
HTTP status semantics, dependency injection — and the ones that kept the core small.**
The decisions that will become debt are the ones that **coupled it to a moment —
a personal namespace, one logging library, one IdP, one billing model, one
transport, and one big module that fuses all of them.** Maximising the framework's
architectural half-life is, in the end, a single move repeated everywhere: **push
every "moment" out to an adapter, keep only the "standards" in the core, and version
them on separate clocks.**
