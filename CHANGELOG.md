# Changelog

All notable changes to backendkit are documented here. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.25.0] - 2026-10-08

Minor release on the **v1** line: additive API only. `bff.PendingLoginStore` keeps pending logins
(PKCE verifier, `LoginBinding` nonce, return path) between `/login` and the callback, in a bounded
memory store or in PostgreSQL shared by several instances (encrypted, single-use). No changed
signature and no changed default.

### Added
- **`bff.WithPostgresAutoSchema()` and `bff.WithPendingLoginAutoSchema()`: name the schema choice**
  (#100). The Postgres stores create their table at start-up unless told the migrations own it
  (`WithPostgresManagedSchema()` / `WithPendingLoginManagedSchema()`), which needs DDL rights the
  BFF's role should not hold in production. Making managed the default would break every caller
  relying on the table being created, so v1 keeps the behaviour and makes the choice explicit:
  - the new `…AutoSchema()` options name today's behaviour;
  - with neither option a store still creates its table and logs a start-up warning naming both;
  - both together are refused.

  The README, integration guide and migration guide now lead with managed schema. The default may
  flip in a future major version only.

### Added
- **`bff.PendingLoginStore`: pending logins that survive across instances** (#98). Between `/login`
  and the callback a BFF keeps the PKCE verifier, the `LoginBinding` nonce and the return path,
  keyed by the OAuth state. Each application kept them in its own in-memory map (oauth2-admin), or
  its own table (oauth2-monitoring, where the nonce was not stored and every sign-in failed), so
  behind several instances a login started on one could not finish on another.
  - The interface is `Put` / `Take` / `Sweep` with a context. `Take` returns and removes the
    entry in one step, and refuses an unknown, expired or unreadable state.
  - `NewMemoryPendingLoginStore(ttl, max)` is bounded (`ErrPendingLoginsFull`), because `/login`
    needs no session.
  - `NewPostgresPendingLoginStore(ctx, db, key, ttl, …)` encrypts each row with AES-256-GCM bound
    to its state, takes with one `DELETE … RETURNING`, and supports
    `WithPendingLoginManagedSchema()`, `WithPendingLoginTable()` and
    `WithPendingLoginErrorHandler()`.

  The session stores are unchanged.

## [1.24.0] - 2026-10-08

Minor release on the **v1** line: additive API only, from the Lakebridge review. `pep.Config.MinimumMode`
enforces a floor under Socrate's server-wide mode and, with Socrate v1.13.0+, reports it to the
decision log. `httpware.NewKeyedRateLimiter` leaves no request unlimited (tenant, else subject,
else client address in a smaller anonymous bucket). `apierror.WriteProblem` adds RFC 9457 problem
details, used by `jwtauth.WithErrorWriter` and `httpware.RequireTenantWith`. No changed signature
and no changed default; a 400 from `socrate.Client.Decide` now also matches
`socrate.ErrPolicyRequestRejected`.

### Added
- **`pep.Config.MinimumMode`, a floor under the mode Socrate reports** (#97). Socrate's
  `POLICY_MODE` is server-wide, so an application that must enforce its rules while the server is
  still `off` or `shadow` for others had to reimplement the mode logic (Lakebridge's
  `internal/guard`). The effective mode is now the stricter of the server's and `MinimumMode`
  (`off` < `shadow` < `enforce`). With `"enforce"`, in every server mode, a deny is
  `policy_denied`, an unmet obligation is `elevation_required` / `mfa_required`, and an
  unreachable decision point is `policy_unavailable` (503), even before any decision has reported a
  mode. With `"shadow"`, `off` is treated as `shadow`. `New` refuses an unknown value and
  `"enforce"` combined with `FailOpenWhenModeUnknown`. Empty or `"off"`, the default, follows
  Socrate exactly as before. The shadow would-deny log line gains `server_mode`.

- **`httpware.NewKeyedRateLimiter`: rate limiting with no unlimited request** (#94). `RateLimiter`
  keys on the tenant only and lets a request without one through, so service accounts without a
  tenant were unlimited (Lakebridge wrote its own bucket). The new limiter counts each request
  against its tenant (`t:`), else its subject (`s:`, e.g. a service account `app:7`), else its
  client address (`a:`) in a separate, smaller anonymous bucket (a tenth of the authenticated one
  by default), so an unauthenticated flood never shares a bucket with real traffic. The prefixes
  keep the tiers apart.
  - IPv6 addresses are grouped by /64.
  - The client address comes from a `ClientIP` function (pass a trusted-proxy-aware one behind a
    proxy), else the peer address.
  - Address buckets are bounded by `MaxAnonymousKeys` (default 10,000): a new address beyond it is
    refused until idle buckets expire; tenant and subject buckets never are.
  - `Retry-After` is computed from the bucket instead of a fixed `1`.

  `RateLimiter` is unchanged.

- **RFC 9457 problem details, and a hook to use them in the rejecting middleware** (#99).
  `(*apierror.AppError).WriteProblem` writes `application/problem+json`: `type: "about:blank"`,
  `title` the status text, `status`, `detail` the message, and `code`, `key` and `details` as
  extension members. 5xx is redacted as with `WriteJSON`. `apierror.ErrorWriter` is the shape of a
  writer, with `JSONWriter` (the default envelope) and `ProblemWriter`.
  `jwtauth.WithErrorWriter(w)` writes its four 401s through it, and `httpware.RequireTenantWith(w)`
  is `RequireTenant` with it, so an API answering in problem+json (Lakebridge) no longer wraps
  either to rewrite their bodies. Without these options the bodies are byte-for-byte unchanged.
- **`pep` reports `MinimumMode` to Socrate's decision log.** Once Socrate advertises
  `pep_mode_accepted` (go-oauth2 v1.13.0+), an enforcer with `MinimumMode` above `off` sends it as
  `pep_mode`, so decisions it enforces while `POLICY_MODE=off` appear on the monitoring console's
  Policy Decisions page. An older Socrate is never sent the field. If a Socrate that advertised it
  rejects it (a downgrade), the request is asked again without it and the flag is dropped, so
  reporting can never cost a decision. New: `socrate.DecideRequest.PEPMode`,
  `socrate.Decision.PEPModeAccepted`, and `socrate.ErrPolicyRequestRejected`, which `Decide` now
  wraps for a 400.

## [1.23.0] - 2026-10-08

Minor release on the **v1** line. The minimum Go is back to **1.26.0**, so importers that cannot
move to Go 1.27.1 yet can upgrade again. `httpware.RequestID` keeps only well-formed incoming ids
(new helpers `ValidRequestID`, `MaxRequestIDLength`). `socrate.Client` forwards the request id as
`X-Correlation-ID` on every call, not only `Decide`. No changed signature and no changed default;
with Socrate v1.12.2+, Socrate applies the same id rule on its side.

### Changed
- **The minimum Go is back to 1.26.0** (`go 1.26.0`, with `toolchain go1.27.1`). v1.20.0 had raised
  the `go` line to 1.27.1, which forced every importer onto Go 1.27.1. A consumer that could not
  move yet was stuck on v1.19.0 (Lakebridge's `client/`). The floor is now the oldest supported Go
  release, and CI builds and tests on it (`Build & Test (1.26.0)`, `GOTOOLCHAIN=local`). It checks
  that the job runs exactly go.mod's `go` line, as the main job already checks the `toolchain` line.
  backendkit is still developed and tested with Go 1.27.1. No code or API change; lowering the
  minimum breaks no caller (#93).
- **`socrate.Client` forwards the request id on every call**, not only `Decide`. The id comes from
  `ctxutil.GetRequestID` and is sent as `X-Correlation-ID`, the header Socrate reads. It covers
  user-JWT and service-account calls, the `client_credentials` exchange (with the id of the
  request that triggered it), code exchange and refresh, magic-link and admin login, signup,
  logout, revocation and introspection. An id that is not a short run of printable ASCII is not
  sent, so it can never make the call fail. No exported identifier changes (#96).

### Security
- **`httpware.RequestID` validates the incoming `X-Request-ID`.** It keeps the id only if it is 1 to
  128 characters of `A-Za-z0-9._:-` (UUIDs, ULIDs and similar). Otherwise it generates a UUID, as
  when the header is absent. Until now any value was stored, logged, echoed back and forwarded:
  line breaks, control characters or kilobytes of text could reach logs and audit fields. The
  request is never rejected. `httpware.ValidRequestID` and `httpware.MaxRequestIDLength` expose the
  rule (#95; Socrate's counterpart is ovander/go-oauth2#321).

## [1.22.0] - 2026-10-07

Minor release on the **v1** line: additive API only, the three options Lakebridge asked for (#88).
A `RevocationChecker` can read the raw token (to introspect it at Socrate), `ctxutil.GetAudiences`
tells a handler which audience a token was accepted for, and `(*socrate.Client).InvalidateServiceToken`
forces a new service-token exchange. No changed signature and no changed default.

### Added
- `ctxutil.WithAudiences` / `ctxutil.GetAudiences`: the audiences a token was accepted for, set
  by `jwtauth.Middleware`. With `WithAudience` / `WithAudiences` they are the token's `aud` values
  that are in the configured set (token order, no duplicates); without an audience check, every
  `aud` value. A route group serving several applications can tell which one a token is for, and
  require exactly one, without decoding the payload again. `GetAudiences` returns a copy, or nil
  when absent. Requested by Lakebridge (#88, item 2).
- `(*socrate.Client).InvalidateServiceToken()`: drops the cached service-account token, so the next
  `ServiceToken` (or service-account) call exchanges a new one. For a peer that refuses the token
  with 401 before its `exp`, e.g. after it was revoked at Socrate; until now nothing could force a
  new exchange before the cache's 30 s renewal window. Thread-safe, under the existing token lock;
  no existing call changes. Requested by Lakebridge (#88, item 3).

### Changed
- **A `jwtauth.RevocationChecker` can read the raw bearer token.** The middleware now stores it
  with `ctxutil.WithRawJWT` before the revocation check instead of after, so a checker that
  introspects the token at Socrate (`/oauth/introspect`) gets it from `ctxutil.GetRawJWT(ctx)`
  instead of copying the `Authorization` header in a middleware of its own. Ordering only: the
  identity values are still set only after the check passes, a refused token still gets a 401
  before the handler, and handlers see the same context as before. No exported identifier
  changes. Requested by Lakebridge (#88, item 1).

## [1.21.0] - 2026-10-05

Minor release on the **v1** line: additive API only. `jwtauth.WithTenantClaim` reads the tenant from
a namespaced claim, which is how a stock Socrate issues it (`https://socrate/tenant_id`); without it
`httpware.RequireTenant` refused every Socrate token. No exported identifier changes; the default
is unchanged.

### Added
- `jwtauth.WithTenantClaim(name)`: read the tenant from the named claim instead of `tenant_id`.
  A stock Socrate has no tenant model and issues claim mappings under its claims namespace, so a
  tenant reaches tokens as `https://socrate/tenant_id`, which the middleware ignored:
  `httpware.RequireTenant` then refused every token. With the option, the named claim replaces
  `SocrateClaims.TenantID` (the revocation check sees it too) and a plain `tenant_id` is ignored;
  a value that is not a UUID string, `null` included, is a 401; an empty name rejects every token.
  The default is unchanged. Reported by Lakebridge (go-oauth2 #308).

## [1.20.0] - 2026-10-04

Minor release on the **v1** line: additive API, and a new minimum Go. `bff.WithPostgresManagedSchema`
lets the session store run on a migration-owned table with a role holding only `SELECT`, `INSERT`,
`UPDATE` and `DELETE` (Lakebridge #82). **The module now requires Go 1.27.1**: importers on an
older Go need `GOTOOLCHAIN=auto` (the default) or an upgrade. No exported identifier changes.

### Added
- `bff.WithPostgresManagedSchema()`: `NewPostgresStore` runs no DDL, for a table created by the
  caller's migrations, so the BFF's database role needs only `SELECT`, `INSERT`, `UPDATE` and
  `DELETE` on it (PostgreSQL checks `CREATE` on the schema, and table ownership for the index,
  even when they already exist). At start-up the store checks the table's columns and each of
  those four privileges, and fails naming what is missing. The default is unchanged. Requested by
  Lakebridge (#82).

### Changed
- **The module now requires Go 1.27.1** (`go 1.27.1`; was `go 1.25.0` with `toolchain go1.27.1`).
  Importers need Go 1.27.1 or later; with `GOTOOLCHAIN=auto`, the default, an older `go` command
  downloads it. backendkit's language level and `GODEBUG` defaults now match the Go it is built
  and tested with. No exported identifier changes. `bff.NewSingleHostProxy` keeps its
  `httputil.ReverseProxy.Director` (deprecated since Go 1.26, still supported): callers wrap it,
  so moving to `Rewrite` needs a new, additive constructor. CI pins govulncheck to v1.8.0.

### Fixed
- The `WithPostgresManagedSchema` privilege test failed in CI: there the database role is a
  superuser, which holds every privilege whatever is revoked. The test now runs the store as a
  real limited role when the role is a superuser, and a new test runs the exact #82 layout (a
  CRUD-only role on a table it does not own) in CI. No library change.

## [1.19.0] - 2026-10-03

Minor release on the **v1** line: additive only. The service-side helpers Lakebridge asked for:
`ServiceToken` for calling another service with the app's identity, and `User.TokenVersion` for a
revocation check without introspection (needs Socrate v1.8.0; nil before).

### Added
- `(*socrate.Client).ServiceToken(ctx) (token string, expiresAt time.Time, err error)`: the
  application's `client_credentials` access token and its real expiry (the token's `exp` claim,
  else `expires_in` counted from when the request was sent; not the cache's early renewal time),
  for calling another service with
  the app's own identity. It is the cached token of the service-account calls (exchanged again
  within 30 s of expiry, one exchange for concurrent callers). Requested by Lakebridge (its consumer
  client takes Socrate service tokens without hand-rolling the OAuth exchange).
- `socrate.User.TokenVersion` and `socrate.User.Locked` (`*int`, `*bool`): set by `GetUser` and
  `GetUserAsService` from Socrate v1.8.0, nil from lists and older servers. A user token whose
  `token_version` claim is lower than `*TokenVersion` was revoked, so a resource server can check
  revocation with its cached service token instead of introspecting every user token
  (Lakebridge).

### Changed
- A `client_credentials` response without an `access_token` is now an error instead of an empty
  cached token (fail closed); a working caller never received one.
- The service-account token's expiry comes from its `exp` claim, else from `expires_in` counted
  from when the request was sent (it was counted from the response, a little late); a response
  with neither is trusted for one minute instead of a fixed 55 minutes.

### Documentation
- `jwtauth.WithAudiences` in the client integration guide (§5) and the migration guide (§3.1),
  including which application `role` belongs to when several audiences are accepted, and the
  README troubleshooting row for 401s.

## [1.18.0] - 2026-10-02

Minor release on the **v1** line: additive only.

### Added
- `jwtauth.WithAudiences(...string)`: audience validation against a set; a token is accepted when
  its `aud` contains at least one expected audience. Empty strings and duplicates are ignored, and
  a call with no non-empty audience rejects every token (fail closed, logged at `New`).
  `WithAudience(a)` is now the one-element case; `WithAudience("")` still disables the check.
  Requested by Lakebridge (one route group serving a portal and two service accounts).

## [1.17.1] - 2026-10-02

Documentation-only patch release: no code change from v1.17.0.

### Documentation
- The migration guide covers the v1.17.0 additions: a new §3.8 maps an application's own
  sign-up, profile edits, avatars and e-mail-verified flag to `Signup`, `UpdateProfile`,
  `UpdateUserAsService`, `AvatarURL` and `ProfileInfo`; §3.7 names `bff.NewPostgresStore`; the
  checklist and symptom index follow. The quick reference lists `Signup` and the profile calls.

## [1.17.0] - 2026-10-02

Minor release on the **v1** line, for GPWA: additive only. The user profile types carry
`EmailVerified` and the avatar; `socrate.Client.Signup` creates an account with the user's own
password; `UpdateUserAsService` updates a member's profile fields; `bff.PostgresStore` keeps BFF
sessions across restarts, encrypted at rest. The avatar fields and `UpdateUserAsService` need
Socrate v1.7.0. pgx is added to `go.mod` for the store's tests only.

### Added

- `bff.PostgresStore`, a durable `SessionStore`: sessions survive a restart and are shared by
  several BFF instances. It works through a `*sql.DB` the application opens with its own driver
  (backendkit imports none; pgx is used by the tests only) and creates its table. Session data,
  tokens included, is encrypted with AES-256-GCM under a required 32-byte key, bound to the session
  ID. A logout wipes the data and keeps a tombstone for an hour, so a request racing it cannot
  re-create the session. Same idle and absolute expiry as `MemoryStore`. CI now runs the tests
  against PostgreSQL 16. Requested by GPWA.
- `socrate.Client.UpdateUserAsService` updates profile fields of one of the application's
  members with the service-account token (`PATCH /api/apps/{id}/service/users/{user_id}`, Socrate
  v1.7.0): the `UpdateProfileRequest` fields, never the email, password or roles. It returns
  `ErrUserNotInApp` for a non-member and `ErrInvalidProfileUpdate` when Socrate refuses the values;
  against an older Socrate, an error naming the version. Requested by GPWA.
- `socrate.Client.Signup` creates a Socrate account with the password the user chose
  (`POST /api/auth/signup`), as a `user` member of the client's application; Socrate sends a
  verification e-mail. It returns `ErrUserAlreadyExists` for an email that already has a Socrate
  account and a `*SignupError`, whose message is safe to show, for a policy refusal. It carries the
  client attribution, since Socrate rate-limits sign-ups per address. Requested by GPWA.
- `socrate.ProfileInfo` gains `EmailVerified` (Socrate's userinfo already returns it; backendkit
  dropped it) and `Picture`, the user's avatar URL. `FullProfile`, `UpdateProfileRequest` and the
  app member type `User` gain `AvatarURL`. The avatar needs Socrate v1.7.0 (`avatar_url`, OIDC
  `picture`); against an older server the fields stay empty. Requested by GPWA.

## [1.16.0] - 2026-10-01

Minor release on the **v1** line: one new method, no breaking change. `socrate.LoginResult.TokenSet()`
turns a magic-link or admin login into the token set a BFF session is built from; `jwtauth.New`
warns at startup when the audience check is off; a new guide,
[`docs/MIGRATING-TO-SOCRATE.md`](docs/MIGRATING-TO-SOCRATE.md), condenses the Ascenda and Parashift
migrations into a checklist and a symptom index.

### Added

- Docs: [`docs/MIGRATING-TO-SOCRATE.md`](docs/MIGRATING-TO-SOCRATE.md), a field guide for moving an
  application onto Socrate, from the Ascenda and Parashift migrations: the identifiers to get from
  the operator (numeric app ID, admin address, whether user IDs are kept), the configuration names,
  the rule behind each failure seen (audience, app ID, service-account routes, loopback admin API,
  client attribution, magic-link page, BFF sessions), the cut-over order, a checklist and a symptom
  index. The integration guide now says that `role` belongs to the application the token was
  issued for (so `WithAudience` is required for `httpware.RBAC` to be safe), shows a BFF
  magic-link redemption handler, and lists the new symptoms in its FAQ. No code change.
- `socrate.LoginResult.TokenSet()` returns the tokens of a magic-link or admin login as the
  `*TokenSet` that `bff.NewSession` takes, so a BFF redeems a magic link the way it handles an
  Authorization Code login, without copying fields by hand. The roles are copied, not shared.
  The integration guide's magic-link handler (§7.5) uses it.

### Changed

- `jwtauth.New` logs a warning at startup when no `WithAudience` option is given, as it already
  does for an empty issuer. Without the audience check, a token issued to another application on
  the same Socrate validates, and its `role` claim (the user's role in that application) is
  trusted, including by `httpware.RBAC`: in the Ascenda migration, an administrator of another
  application was an administrator in Ascenda. Behaviour is unchanged; only the log line is new.

## [1.15.1] - 2026-09-30

Patch release on the **v1** line: no change to any exported identifier. `socrate.Client.RegisterUser`
and `GetUserAsService` call Socrate's service-account routes and work with a service-account token.
`GetUserAsService` needs Socrate v1.6.0 or later; against an older server it returns an error, never
a silent "not found".

### Fixed

- **`socrate.Client.RegisterUser` and `GetUserAsService` call the service-account routes.** They
  sent a service-account token to `/api/apps/{id}/users…`, routes that need an app admin's user
  token, so Socrate answered `401` and neither method worked. `RegisterUser` now posts to
  `/api/apps/{id}/service/users` (the route `InviteUserAsService` uses; `Name` is still sent).
  `GetUserAsService` now reads `GET /api/apps/{id}/service/users/{user_id}`, added in the
  Socrate release after v1.5.3. It returns nil, nil only for Socrate's own 404 (not a member, or no such user); a Socrate
  without the route answers with an error that names the version, never a silent "not found". No
  exported identifier changes.

### Changed

- Docs: `socrate.ClientConfig.AdminBaseURL` is documented as required in production. The value
  derived when it is empty (`BaseURL` with port 8081, same scheme and host) is wrong behind a
  TLS reverse proxy, where the admin API is plain HTTP on loopback; the integration guide, the
  README and the package doc now say to set it (e.g. `http://127.0.0.1:8081`), to read the port
  from the server's `ADMIN_PORT` (8082 in the layout that co-hosts a legacy server on 8081),
  and what a backend on another host can and cannot call. No code change.

## [1.15.0] - 2026-09-29

Minor release on the **v1** line: no breaking change to any exported identifier. It adds opt-in
client attribution, so a Backend-for-Frontend can tell Socrate which browser a token, refresh or
revoke call is made for (`socrate.WithClientAttribution`, `socrate.ApplyClientAttribution`,
`bff.WithClientAttribution`). Without it, requests are unchanged.

### Added

- **Client attribution for OAuth calls made on a user's behalf** (`socrate`, `bff`; opt-in,
  additive). `socrate.ClientAttribution`, `socrate.WithClientAttribution`,
  `socrate.ClientAttributionFrom` and `socrate.ApplyClientAttribution` carry the browser's
  address and User-Agent on the context; `ExchangeCode`, `RefreshToken`, `RevokeToken`,
  `VerifyMagicLink`, `AdminLogin` and `Logout` then send them as `X-Forwarded-For` and
  `User-Agent`, so Socrate (v1.5.0+) audits, rate-limits and blocks by the browser rather than
  the BFF's loopback address. `X-Forwarded-For` is replaced with the single address, never
  appended to (Socrate reads the leftmost entry), `X-Real-IP` is removed, an unparsable address
  sends nothing, and the User-Agent is stripped of control characters and capped at 512 bytes.
  The `client_credentials` grant, introspection and userinfo never carry it.
  `bff.WithClientAttribution(r, ip)` sets it from an incoming request; the gateway's refresh path
  already keeps the request context's values, so the refresh is attributed too. The caller
  resolves the IP; backendkit never reads it from headers. Without attribution on the context, requests are unchanged.

## [1.14.0] - 2026-09-29

Minor release on the **v1** line: no breaking change to any exported identifier. It adds the
`pep` package (enforcing Socrate's central policy decisions), `socrate.Client.Decide`, and the
`auth_time` / `amr` claims in `jwtauth`; moves the toolchain to Go 1.27.1; and brings the licence
(Apache-2.0), the contributor kit and the documentation to the suite's standard.

Policy enforcement for applications against Socrate's central policy decision
point, and a patched build toolchain. Both purely additive for consumers.

### Added

- **Apache-2.0 licence** (`LICENSE`) and the contributor kit: `CONTRIBUTING.md`, `SECURITY.md`
  (private vulnerability reporting, scope, supported versions), `CLAUDE.md`, `CODEOWNERS`, issue
  forms and a pull-request template.
- **README package reference for `bff` and `ailang`**, which had none, with examples that compile
  against the module.

- **`pep` package** — the policy enforcement point for Socrate's policy
  decision point. `Enforcer.Middleware` gates a route on an action,
  `Enforcer.Check` decides object-level inside a handler, `WriteDenial` writes
  the refusal. The user's own access token is sent as the decision's subject
  (so Socrate, not the application, resolves who the user is), and the mode
  Socrate reports with every answer decides what happens: `off` ignore,
  `shadow` log a would-deny and proceed, `enforce` refuse with `403
  policy_denied`. Obligations are honoured against the verified token
  (`require_fresh_auth` → `elevation_required`, `require_mfa` →
  `mfa_required`; unknown obligations count as unmet). When Socrate is
  unreachable the last mode seen applies — proceed in off/shadow, refuse `503
  policy_unavailable` in enforce, refuse before any decision unless
  `FailOpenWhenModeUnknown`. No subject token (pep mounted before jwtauth) is
  `401`, never a decision made as the application.
- **`socrate.Client.Decide`** — `POST /api/apps/{id}/service/policy/decide`
  with the cached service token, forwarding the request id as
  `X-Correlation-ID`; `ErrPolicyUnavailable` on 503 with the mode preserved.
- **`jwtauth` exposes `auth_time` and `amr`** (`SocrateClaims.AuthTime`,
  `SocrateClaims.Amr`), as `ctxutil.GetAuthTime` / `ctxutil.GetAMR`.

### Changed

- README: a row of self-updating badges (CI status, licence, Go version) under the title.
- **Documentation uplift:** the README, `docs/CLIENT-INTEGRATION.md` (new BFF and `pep`
  sections; a BFF is now the recommended path for browser apps), `SECURITY.md`, `CONTRIBUTING.md`
  and the GitHub templates follow the Socrate suite's documentation standard.
- **Build toolchain: Go 1.26.8 → Go 1.27.1** (`toolchain` directive and CI).
  The `go 1.25.0` minimum is unchanged: consumers are unaffected, and the
  GODEBUG defaults this module's own tests run with stay those of Go 1.25.
- **Build toolchain: Go 1.26.6 → Go 1.26.8** (`toolchain` directive and CI),
  picking up the 2026-08-28 security release. The `go 1.25.0` language minimum
  is unchanged, so consumers are unaffected. CI now fails if its Go and the
  `toolchain` line drift apart.
- **golangci-lint v2.5.0 → v2.14.0** in CI (still built with the job's
  toolchain). v2.5.0 cannot load Go 1.27's export data; v2.14.0 reports no
  issues on this module.

### Fixed

- README and `docs/CLIENT-INTEGRATION.md` linked Socrate to a repository that does not exist;
  they now name `ovander/go-oauth2` in plain text, as it is not public yet. The README's
  contributing rule on cross-package imports now matches the code (`bff`/`pep` → `socrate`,
  `aigateway` → `ailang`).

### Removed

- The internal review documents (the architecture review, the framework-evolution notes, the
  security architecture review and the security audit) left the public tree. The fixes they led
  to remain listed below with their finding IDs.

## [1.13.0] - 2026-09-04

Observability slice from the Socrate suite plan (B1): the same RED metric
names and label scheme that Socrate itself exposes, so every backendkit-based
service lands on one dashboard. Purely additive.

### Added

- **`httpware.Metrics(service)` / `httpware.MetricsHandler()`** — Prometheus
  RED instrumentation for backendkit-based services (Socrate suite plan B1):
  `backendkit_http_requests_total{service,route,method,status}` and
  `backendkit_http_request_duration_seconds{service,route,method}`, keyed by
  the Go 1.22 `ServeMux` route pattern (never the raw path); `Flush` is
  forwarded so SSE proxies keep streaming. New dependency:
  `github.com/prometheus/client_golang`. Mount `MetricsHandler` on a loopback
  or admin-only route only.

## [1.12.0] - 2026-09-03

Shared-gateway hardening from the third-pass security review of the Socrate
suite. Additive except for one behaviour change called out below.

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
  `false` when the stored value is empty. Addresses **P2-6** (second-pass
  security review of the Socrate suite).

- **bff: `Gateway`'s zero value is now fail-closed.** `Gateway.AuthEnabled`
  defaulted to `false`, so a bare `&Gateway{...}` struct literal — no field
  set — was a fully-open pass-through, contradicting this package's
  documented "fail-closed by default" behaviour. The field is renamed and
  inverted to **`DisableAuth`**, so the zero value now means "auth enforced."
  Addresses **P2-7** (second-pass security review).

- **bff: coalesce concurrent token refreshes per session.** Concurrent
  `EnsureFresh` calls near token expiry could each independently spend the
  same single-use rotating refresh token; only the first succeeded and the
  rest tore down the session. `EnsureFresh` now coalesces concurrent calls
  per session ID via `singleflight.Group` (mirroring the `jwtauth` H-1 JWKS
  fix), with every waiter re-checking token validity before spending a
  refresh. Addresses **P2-8** (second-pass security review).

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
  cooldown triggers exactly one refetch. Addresses **H-1** (internal security audit).

- **jwtauth: require `exp` and add clock-skew leeway.** The parser now sets
  `jwt.WithExpirationRequired()`, so a token minted without an `exp` claim (which
  would otherwise never expire) is rejected, plus `jwt.WithLeeway` (default 60s;
  `WithLeeway`) for time-based claim validation. Addresses **M-2**
  (internal security audit).

- **socrate: complete path-segment escaping (corrects the F-7 ledger).** v1.9.0
  escaped only `client.go`; the remaining admin/monitoring/alerts/reports methods
  still concatenated raw caller-supplied path segments. `url.PathEscape` is now
  applied to every caller-supplied segment across `admin.go`, `monitoring.go`,
  `alerts.go` and `reports.go` (user/app/superadmin/blocked-ip/ip-reputation/log/
  alert-rule/report IDs). Internal server-resolved values (e.g. the app ID) are
  intentionally left unescaped, as in `client.go`. Addresses **M-1** and corrects
  the previously overstated **F-7** "Fixed" claim (internal security audit).

## [1.9.0] - 2026-06-20

### Security

- **jwtauth: warn when issuer validation is disabled.** `jwtauth.New` now logs a
  warning at construction when the issuer is empty, so a service running without
  `iss` enforcement is visible at startup instead of silently fail-open. No change
  to token validation; making issuer mandatory remains a v2.0 default-flip.
  Addresses **F-5** (internal security audit).
  ([#30](https://github.com/ovander/backendkit/issues/30))

- **apierror: redact internal message/details on 5xx responses.** `WriteJSON` now
  replaces the dev-facing `Message` with a generic status text and drops `Details`
  for any 5xx response, so internal detail (e.g. `apierror.Internal(err.Error())`)
  can no longer leak to clients. **4xx responses are unchanged.** The full error
  is still available server-side via `Error()` for logging; the struct doc was
  corrected. Addresses **F-17 / INV-9** (internal security audit
  and architecture review).
  **Behaviour change:** 5xx response bodies no longer echo the supplied message.
  ([#28](https://github.com/ovander/backendkit/issues/28))

- **gormlogger: opt-in SQL redaction.** New `gormlogger.WithSQLRedaction()` option
  omits the SQL statement from log records (logs `sql: "[redacted]"`, keeping
  timing/row-count/caller). GORM hands the logger SQL with bound parameter values
  already interpolated — which can contain PII or secrets — so production loggers
  should enable it. Opt-in; default behaviour unchanged. Addresses **F-9 / INV-10**
  (internal security audit and architecture review).
  ([#26](https://github.com/ovander/backendkit/issues/26))

- **jwtauth / socrate / aigateway: bound upstream response reads.** All reads of
  upstream HTTP bodies are now capped with `io.LimitReader` — JWKS at 1 MiB,
  Socrate and AI-provider responses at 10 MiB — so a compromised/MITM or oversized
  upstream cannot exhaust memory. `socrate.readBody` returns an explicit error when
  the cap is exceeded. Normal-size responses are unaffected. Addresses
  **F-8 / INV-12** (internal security audit and architecture review).
  ([#24](https://github.com/ovander/backendkit/issues/24))

- **socrate: path-escape `userID` in request URLs.** `socrate.Client` now wraps the
  caller-supplied `userID` in `url.PathEscape` at every endpoint that interpolates
  it (`GetUser`, `UpdateUserRole`, `DeleteUser`, `ResendVerification`,
  `ForcePasswordReset`, `GetUserAsService`), so an ID containing `/`, `?`, `#`, or
  `..` can no longer rewrite the target route. Addresses **F-7 / INV-11**
  (internal security audit and architecture review).
  ([#22](https://github.com/ovander/backendkit/issues/22))

## [1.8.0] - 2026-06-20

### Security

- **jwtauth: enforce a minimum RSA key size (2048 bits) for JWKS keys.**
  `parseRSAPublicKey` now rejects moduli below 2048 bits and validates the public
  exponent (odd, > 1, within `int` range) instead of silently truncating it, so a
  JWKS serving an undersized or malformed key is no longer trusted. Backward
  compatible for real deployments (Socrate/RS256 use ≥2048-bit keys). Addresses
  **F-10 / INV-13** (internal security audit and architecture review).
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
  (internal security audit and architecture review).
  ([#16](https://github.com/ovander/backendkit/issues/16))

- **httpware: `RequireTenant` middleware.** A plain
  `func(http.Handler) http.Handler` that rejects requests with no tenant ID in
  context (`ctxutil.GetTenantID == uuid.Nil`) with 401 Unauthorized, so
  tenant-scoped handlers can never run against the nil tenant. Opt-in; mount it
  after the auth middleware on tenant-scoped route groups. Rejections are logged
  through the request-scoped logger. Addresses **F-3 / INV-6**
  (internal security audit and architecture review).
  ([#14](https://github.com/ovander/backendkit/issues/14))

- **jwtauth: opt-in JWT audience (`aud`) validation.** New `jwtauth.Option`
  functional-option type and `jwtauth.WithAudience(expectedAudience string)`.
  When supplied, a token is accepted only if its `aud` claim contains the
  expected audience (typically the service's OAuth `client_id`), closing the
  cross-app token-replay exposure where one Socrate-issued token was valid at
  every service sharing the same issuer and JWKS.
  Resolves **F-1 / INV-2** (internal security audit and architecture review).
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

[Unreleased]: https://github.com/ovander/backendkit/compare/v1.25.0...HEAD
[1.25.0]: https://github.com/ovander/backendkit/compare/v1.24.0...v1.25.0
[1.24.0]: https://github.com/ovander/backendkit/compare/v1.23.0...v1.24.0
[1.23.0]: https://github.com/ovander/backendkit/compare/v1.22.0...v1.23.0
[1.22.0]: https://github.com/ovander/backendkit/compare/v1.21.0...v1.22.0
[1.21.0]: https://github.com/ovander/backendkit/compare/v1.20.0...v1.21.0
[1.20.0]: https://github.com/ovander/backendkit/compare/v1.19.0...v1.20.0
[1.19.0]: https://github.com/ovander/backendkit/compare/v1.18.0...v1.19.0
[1.18.0]: https://github.com/ovander/backendkit/compare/v1.17.1...v1.18.0
[1.17.1]: https://github.com/ovander/backendkit/compare/v1.17.0...v1.17.1
[1.17.0]: https://github.com/ovander/backendkit/compare/v1.16.0...v1.17.0
[1.16.0]: https://github.com/ovander/backendkit/compare/v1.15.1...v1.16.0
[1.15.1]: https://github.com/ovander/backendkit/compare/v1.15.0...v1.15.1
[1.15.0]: https://github.com/ovander/backendkit/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/ovander/backendkit/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/ovander/backendkit/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/ovander/backendkit/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/ovander/backendkit/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/ovander/backendkit/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/ovander/backendkit/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/ovander/backendkit/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/ovander/backendkit/compare/v1.7.0...v1.8.0
