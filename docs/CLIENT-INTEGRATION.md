# Socrate + backendkit — Client Integration Guide

A practical, end-to-end guide for **application teams** integrating with Socrate, the suite's
OAuth 2.1 / OpenID Connect server (`ovander/go-oauth2`, not public yet), through the
`backendkit` library.

It is written for two audiences working on the same product:

- **Backend engineers** building a Go service that trusts Socrate-issued JWTs
  and needs to manage users, profiles and security data, or a
  Backend-for-Frontend (BFF) that signs browser users in.
- **Frontend engineers** driving the login flow and calling that backend:
  browser apps through a BFF, mobile, native and CLI clients with their own
  tokens.

> **Moving an existing application?** Read
> [Moving an application onto Socrate](MIGRATING-TO-SOCRATE.md) first: the order to do things in,
> the identifiers to ask for, and a symptom index from two real migrations.

> **Reference vs. guide.** This document is the *client-side* integration
> guide: it tells you how to wire things up. The raw HTTP endpoints are
> described in the Socrate server repository, which is not public yet; when
> this guide and the server disagree, the server wins.

---

## Table of contents

- [1. The mental model](#1-the-mental-model)
- [2. Who talks to what](#2-who-talks-to-what)
- [3. Install & configure](#3-install--configure)
- [4. Backend: the 5-minute setup](#4-backend-the-5-minute-setup)
- [5. Backend: reading the authenticated user](#5-backend-reading-the-authenticated-user)
- [6. Backend: the socrate.Client](#6-backend-the-socrateclient)
  - [6.1 Construction](#61-construction)
  - [6.2 The two auth modes](#62-the-two-auth-modes)
  - [6.3 Dual-port routing](#63-dual-port-routing)
  - [6.4 Method reference](#64-method-reference)
- [7. Frontend: driving the login flow](#7-frontend-driving-the-login-flow)
  - [7.1 Browser apps: use a Backend-for-Frontend (bff)](#71-browser-apps-use-a-backend-for-frontend-bff)
  - [7.2 Alternative: clients that hold their own tokens](#72-alternative-clients-that-hold-their-own-tokens)
  - [7.3 Authorization Code + PKCE in the client](#73-authorization-code--pkce-in-the-client)
  - [7.4 Direct JSON login (first-party only)](#74-direct-json-login-first-party-only)
  - [7.5 Magic link (passwordless)](#75-magic-link-passwordless)
  - [7.6 Calling your backend with a bearer token](#76-calling-your-backend-with-a-bearer-token)
- [8. Error handling](#8-error-handling)
- [9. Role & plan gating](#9-role--plan-gating)
- [10. Enforcing central policy decisions (pep)](#10-enforcing-central-policy-decisions-pep)
- [11. Recipes](#11-recipes)
- [12. Quick reference](#12-quick-reference)
- [13. Gotchas & FAQ](#13-gotchas--faq)

---

## 1. The mental model

Socrate is the **identity provider**. It owns users, passwords, apps
(`client_id` / `client_secret`), issues RS256-signed JWTs, and exposes an admin
surface for managing all of that.

Your application is split into a **frontend** and a **backend**:

- The **frontend** never validates tokens. A **browser app** should never hold
  them either: it signs in through a Backend-for-Frontend (BFF) and gets only an
  opaque session cookie (§7.1). A **mobile, native or CLI client** obtains tokens
  from Socrate (Authorization Code + PKCE, direct login, or magic link) and sends
  them as `Authorization: Bearer <token>` to your backend (§7.2).
- The **BFF** (`bff`) is a small server-side component, often part of your
  backend, that runs the login with Socrate, keeps the tokens in a server-side
  session, and forwards each browser request to your API with the bearer
  attached.
- The **backend** validates every incoming token against Socrate's public keys
  (JWKS), reads the user's identity and role from the verified claims, asks
  Socrate's policy decision point when an action needs a central decision
  (`pep`), and — when it needs to act on Socrate (list users, invite a teammate,
  look up a profile) — calls Socrate through the `socrate.Client`.

`backendkit` is the glue for the server side: JWT validation
(`jwtauth`), claim propagation (`ctxutil`), the typed Socrate API client
(`socrate`), the BFF runtime (`bff`), policy enforcement (`pep`), a middleware
stack (`httpware`), structured errors (`apierror`), and plan-based feature
gating (`tiering`).

```
                       ┌─────────────────────────────────────────────────────┐
                       │ Socrate                                             │
                       │ OAuth/OIDC (public)    /oauth/*  /.well-known/*     │
                       │ Admin API (internal)   /api/admin/*  /api/apps/*    │
                       └───────┬─────────────────────────┬──────────────┬────┘
                               │                         │              │
                 code exchange │                    JWKS │              │ socrate.Client:
                 and refresh   │                         │              │ JWT forward, M2M,
                               │                         │              │ policy decisions
┌──────────────┐  cookie  ┌────┴──────────┐  Bearer  ┌───┴──────────────┴───────────────┐
│ Browser SPA  │ ───────▶ │ BFF (bff)     │ ───────▶ │ Your backend (Go)                │
└──────────────┘          └───────────────┘          │ jwtauth → ctxutil → httpware →   │
                                                     │ handlers → pep, socrate.Client   │
┌──────────────┐              Bearer JWT             │                                  │
│ Mobile / CLI │ ──────────────────────────────────▶ │                                  │
└──────────────┘                                     └──────────────────────────────────┘
```

---

## 2. Who talks to what

| Actor | Talks to | How | Auth |
|-------|----------|-----|------|
| Browser app | **Your BFF** (same origin) | your REST API, proxied | opaque `__Host-` session cookie + `X-CSRF-Token` on unsafe methods |
| Your BFF | **Socrate OAuth port** | Authorization Code + PKCE, refresh (`socrate.Client`) | client ID + secret |
| Your BFF | **Your backend** | proxied request (`bff.Gateway`) | `Bearer <access_token>` from the session |
| Mobile / native / CLI client | **Socrate OAuth port** | Authorization Code + PKCE, or `POST /api/auth/login` | none → receives tokens |
| Mobile / native / CLI client | **Your backend** | your REST API | `Bearer <access_token>` |
| Your backend | **Socrate OAuth port** | `jwtauth` fetches JWKS; `socrate.Client` calls `/oauth/*` | JWKS is public; introspect/revoke use client creds |
| Your backend | **Socrate admin API port** | `socrate.Client` admin, app-user and policy calls | forwards the user JWT **or** a service-account token |

Socrate's **admin API port** (8081 in the default deployment) is internal.
Your frontend must never reach it directly — all admin, app-user and policy
operations go *through your backend* via the `socrate.Client`, which lets you
enforce your own authorization first.

---

## 3. Install & configure

```bash
go get github.com/ovander/backendkit@latest
```

Requires **Go 1.25+**.

`backendkit` reads **no environment variables itself** — you pass everything to
constructors explicitly. These are the conventional names used throughout this
guide:

| Variable | Consumed by | Purpose |
|----------|-------------|---------|
| `SOCRATE_JWKS_URL` | `jwtauth.New` | JWKS endpoint, e.g. `https://socrate.example.com/.well-known/jwks.json` |
| `SOCRATE_ISSUER` | `jwtauth.New` | Expected `iss` claim — optional but recommended in production |
| `SOCRATE_BASE_URL` | `socrate.NewClient` | OAuth (public) port base URL, e.g. `https://socrate.example.com` |
| `SOCRATE_ADMIN_BASE_URL` | `socrate.NewClient` | Admin API base URL, e.g. `http://127.0.0.1:8081`. Set it in production: when empty it is derived from `BaseURL` with port 8081, which is wrong behind a TLS proxy (§6.3) |
| `SOCRATE_CLIENT_ID` | `socrate.NewClient` | Your app's OAuth client ID |
| `SOCRATE_CLIENT_SECRET` | `socrate.NewClient` | Client secret — required for service-account calls, `Decide`, `RevokeToken`, `IntrospectToken` and a BFF's token exchange |
| `SOCRATE_APP_ID` | `socrate.NewClient` | Pre-resolved numeric app ID — **required** for every service-account method |

> **Get these values** by registering your app in Socrate (Admin API
> `POST /api/admin/apps`, or `socrate.Client.CreateApp`). The `client_secret`
> and the numeric app `id` are returned at creation — store both. The secret is
> shown **only once**.

---

## 4. Backend: the 5-minute setup

The minimum production-grade wiring: a middleware stack, JWT validation, and one
protected route.

```go
package main

import (
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/httpware"
	"github.com/ovander/backendkit/jwtauth"
)

func main() {
	log := logrus.WithField("service", "my-service")

	// Validates RS256 JWTs against Socrate's JWKS (keys cached 1h, stale-on-error).
	auth := jwtauth.New(
		os.Getenv("SOCRATE_JWKS_URL"),
		os.Getenv("SOCRATE_ISSUER"), // "" to skip issuer enforcement
		log,
	)

	r := chi.NewRouter()

	// Cross-cutting middleware — order matters.
	r.Use(httpware.RequestID)             // X-Request-ID in/out + ctxutil.GetRequestID
	r.Use(httpware.Recover(log))          // panic → 500 instead of a dropped conn
	r.Use(httpware.SecurityHeaders)       // HSTS, X-Content-Type-Options, etc.
	r.Use(httpware.Timeout(30 * time.Second))

	// Public routes (no token required).
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Protected routes — auth.Handler rejects missing/invalid tokens with a
	// structured 401 before your handler runs.
	r.Group(func(r chi.Router) {
		r.Use(auth.Handler)

		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			// Identity is already in the context — see §5.
			sub := ctxutil.GetUserSub(r.Context())
			_, _ = w.Write([]byte("hello user " + sub))
		})
	})

	_ = http.ListenAndServe(":8080", r)
}
```

What `auth.Handler` does on success: validates the signature and expiry, then
populates the request context with the user's identity, role, app-roles, plan,
and the **raw JWT** (so the `socrate.Client` can forward it). On failure it
writes an `apierror` JSON 401 and stops the chain.

### Recommended security hardening

The setup above is intentionally minimal. For production, layer on the opt-in
controls below — each is a one-liner, and each has a **precondition** worth
checking against your Socrate deployment first:

```go
auth := jwtauth.New(jwksURL, issuer, log,
	// Reject a token minted for another app that shares this Socrate issuer/JWKS.
	// Precondition: Socrate must populate the `aud` claim with this app's
	// client_id — confirm first, or tokens without `aud` are rejected with 401.
	jwtauth.WithAudience(os.Getenv("SOCRATE_CLIENT_ID")),

	// Make logout / password-change / admin-revoke take effect before token exp
	// instead of waiting it out. Compare the token_version claim against your
	// store; return an error to reject.
	jwtauth.WithRevocationCheck(func(ctx context.Context, c *jwtauth.SocrateClaims) error {
		if c.TokenVersion < store.CurrentTokenVersion(ctx, c.Subject) {
			return errors.New("token_version superseded")
		}
		return nil
	}),
)

// On tenant-scoped route groups, guarantee a tenant is present so no nil-tenant
// request reaches your handlers. Precondition: Socrate issues the `tenant_id`
// claim (the default server does not — see §5).
r.Group(func(r chi.Router) {
	r.Use(auth.Handler)
	r.Use(httpware.RequireTenant) // 401 when ctxutil.GetTenantID == uuid.Nil
	r.Mount("/orders", ordersRouter)
})
```

Also enable `gormlogger.WithSQLRedaction()` in production so interpolated SQL
parameter values (which may contain PII) stay out of logs. These controls landed
in v1.8.0 / v1.9.0; setting an empty `issuer` now also logs a startup warning.

---

## 5. Backend: reading the authenticated user

Never reach into the JWT yourself. After `auth.Handler` runs, read claims via
`ctxutil` typed getters. They are nil-safe and return sensible zero values, so
they're safe to call in tests that bypass the middleware.

```go
func handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	sub   := ctxutil.GetUserSub(ctx)   // "42"  — Socrate numeric user ID (string)
	role  := ctxutil.GetUserRole(ctx)  // "admin" | "manager" | "editor" | "viewer" | "user"
	plan  := ctxutil.GetUserPlan(ctx)  // "freemium" (default) | "pro" | "enterprise"
	jwt   := ctxutil.GetRawJWT(ctx)    // the raw bearer token, for forwarding

	// Per-app role (multi-app users): pass the app's client_id.
	appRole := ctxutil.GetAppRole(ctx, "my-app-client-id")
	_ = appRole
}
```

### What is and isn't in an access token

This trips people up, so it's worth stating plainly:

| Claim | In access token? | Notes |
|-------|------------------|-------|
| `sub`, `role`, `app_roles`, `token_version` | ✅ always | the dependable identity set |
| `email`, `name` | ❌ **not** in access tokens | present in ID tokens / `userinfo` only |
| `tenant_id` | ⚠️ only if the server is configured to issue it | else `ctxutil.GetTenantID` → `uuid.Nil` |
| `plan` | ⚠️ only if the server is configured to issue it | else `ctxutil.GetUserPlan` → `"freemium"` |

**`role` is the user's role in the application the token was issued for**, not in yours.
All applications on one Socrate share its signing keys, so without
`jwtauth.WithAudience(clientID)` a token issued to another application validates
here and carries *that* application's role, which `httpware.RBAC` then trusts.
Always set `WithAudience` (§4). `app_roles` maps each application's client ID to
the user's role in it; Socrate admins and superadmins are never listed there and
get `role: "admin"` on every application through their global role.

**To get the user's email/name**, call `socrate.Client.GetCurrentUserProfile`
(§6.4) — it hits `/oauth/userinfo` with the forwarded JWT. Don't expect them in
`ctxutil.GetUserEmail` unless the caller authenticated with an ID token.

---

## 6. Backend: the socrate.Client

When your backend needs to *act on* Socrate — list the app's users, invite a
teammate, fetch a profile, check security events — use the typed client.

### 6.1 Construction

```go
client, err := socrate.NewClient(socrate.ClientConfig{
	BaseURL:      os.Getenv("SOCRATE_BASE_URL"),       // required
	ClientID:     os.Getenv("SOCRATE_CLIENT_ID"),      // required
	ClientSecret: os.Getenv("SOCRATE_CLIENT_SECRET"),  // service-account / introspect / revoke
	AppID:        os.Getenv("SOCRATE_APP_ID"),          // required for service-account calls
	AdminBaseURL: os.Getenv("SOCRATE_ADMIN_BASE_URL"), // e.g. http://127.0.0.1:8081 — see §6.3
	// Timeout:      30 * time.Second,                   // optional; default 30s
})
if err != nil {
	log.Fatal(err)
}
```

Build it **once** at startup and share it — it's safe for concurrent use and
caches the service-account token internally.

### 6.2 The two auth modes

Every method uses exactly one of these. This is the single most important thing
to understand about the client.

**A. User-JWT forwarding** — the method forwards the caller's JWT. You must put
the JWT in the context first. Inside an HTTP handler protected by
`jwtauth.Middleware`, it's already there; just pass `r.Context()`. Outside one
(jobs, tests), attach it with `socrate.WithJWT`:

```go
// Inside a protected handler — JWT already in ctx:
users, err := client.ListUsers(r.Context(), "", 1, 20)

// Outside a handler — attach manually:
ctx := socrate.WithJWT(context.Background(), rawJWT)
user, err := client.GetUser(ctx, "42")
```

These calls inherit the **caller's permissions** — Socrate authorizes them as
that human user. `ListApps`, `AdminListUsers`, etc. require the caller to be an
admin/superadmin; a regular user's JWT gets a 403.

**B. Service-account (M2M)** — the method exchanges your
`ClientID` + `ClientSecret` for a `client_credentials` token (cached until
near-expiry) and calls Socrate as the *app itself*, no human involved. Used for
backend-initiated actions: onboarding, magic links, background sync.

```go
inv, err := client.InviteUserAsService(ctx, socrate.ServiceInviteRequest{
	Email: "teammate@example.com",
	Role:  "editor",
})
```

> **`AppID` is mandatory for service-account methods.** Service tokens carry
> `sub=app:{id}` and **cannot** resolve the numeric app ID at runtime (the
> lookup endpoint needs a human admin JWT). If `AppID` is unset, the first
> service-account call fails immediately with a clear error. Always set it.

### 6.3 Dual-port routing

The client routes each call to the correct port automatically — you never build
URLs yourself:

- **OAuth port** (`BaseURL`, the public port): `GetCurrentUserProfile`,
  `RevokeToken`, `IntrospectToken`, and the token endpoint calls
  (`ExchangeCode`, `RefreshToken`, the service-account token).
- **Admin API port** (`AdminBaseURL`; 8081 in the default deployment):
  everything else — app-user management, app management, superadmins,
  security, dashboard, audit logs, magic links, policy decisions.

`AdminBaseURL` defaults to `BaseURL` with the host port replaced by `8081`,
keeping its scheme and host. That default only fits a Socrate reached directly,
with both ports on one host. **Set `AdminBaseURL` explicitly in production:**

- Behind a TLS reverse proxy (the usual layout), `BaseURL` is the public issuer,
  e.g. `https://socrate.example.com`, and the derived
  `https://socrate.example.com:8081` is wrong: the admin API is plain HTTP bound
  to loopback (`ADMIN_BIND_HOST=127.0.0.1`), not published by the proxy. Use
  `http://127.0.0.1:<ADMIN_PORT>` from a service on the same host.
- The port is the server's `ADMIN_PORT`: 8081 by default, but a host that runs
  another service on 8081 moves it — the layout that co-hosts Socrate with a
  legacy server uses **8082**. Read it from the server's environment file rather
  than assuming 8081; a wrong port can reach a different service.
- A backend on another host cannot reach a loopback-bound admin API at all. It
  can still validate tokens (JWKS) and use the OAuth-port methods; admin, app-user
  and policy calls need the backend on the Socrate host, or an admin API bound
  to a private interface and firewalled to that backend.

### 6.4 Method reference

Legend — **Auth**: `JWT` = forwards caller JWT (mode A), `M2M` = service-account
(mode B), `creds` = client_id/secret form post. **Port**: which Socrate router.

#### Current user / OIDC — OAuth port

| Method | Auth | Returns | Notes |
|--------|------|---------|-------|
| `GetCurrentUserProfile(ctx)` | JWT | `*ProfileInfo` | `/oauth/userinfo`; **nil,nil** on 401/404. Limited OIDC claim set, including `EmailVerified` and `Picture` (the avatar URL; Socrate v1.7.0+). |
| `GetProfile(ctx)` | JWT | `*FullProfile` | full editable profile (`/api/profile`); **nil,nil** on 404. |
| `UpdateProfile(ctx, UpdateProfileRequest)` | JWT | `*FullProfile` | patches the caller's own profile (name, phone, company, …, and `AvatarURL`, an https URL, on Socrate v1.7.0+; `""` clears it). |
| `IntrospectToken(ctx, token)` | creds | `*IntrospectResponse` | RFC 7662; `.Active` tells you if the token is live. |
| `RevokeToken(ctx, token)` | creds | `error` | RFC 7009; revokes an access or refresh token. |
| `Logout(ctx)` | JWT | `error` | invalidates the caller's session (`/api/auth/logout`). |

#### Backend-for-frontend (BFF) token flows — OAuth/Admin port

For BFF architectures where the **backend** performs the OAuth exchange instead
of the browser. The configured `ClientSecret` is sent automatically for
confidential clients.

| Method | Auth | Returns | Notes |
|--------|------|---------|-------|
| `ExchangeCode(ctx, code, redirectURI, codeVerifier)` | creds | `*TokenSet` | Authorization Code + PKCE exchange. Pass `""` verifier if no PKCE. |
| `Signup(ctx, SignupRequest)` | client_id | `*SignupResult` | self-service account with the user's own password, member of this app as `user`; Socrate sends a verification e-mail and sign-in works once verified. `ErrUserAlreadyExists` when the email has a Socrate account (maybe from another app: ask the user to sign in, then add them with `RegisterUser`); `*SignupError` (message safe to show) for a policy refusal. Rate-limited per address: attribute the browser (§7.1). |
| `RefreshToken(ctx, refreshToken)` | creds | `*TokenSet` | refresh-token grant. |
| `VerifyMagicLink(ctx, token)` | client_id | `*LoginResult` | completes passwordless login; `ErrMagicLinkAlreadyUsed` (422), `ErrMagicLinkInvalid` (401). `LoginResult.TokenSet()` gives the `*TokenSet` a BFF session is built from. |
| `AdminLogin(ctx, email, password)` | creds | `*LoginResult` | superadmin portal login; `ErrInvalidCredentials` (401). |

These calls, with `RevokeToken` and `Logout`, send the browser's address and
User-Agent when the context carries a `socrate.ClientAttribution` — see
[client attribution](#client-attribution-telling-socrate-who-the-browser-is).

#### App-scoped user management — Admin port

Operates on **your app's** users (`/api/apps/{app_id}/users`). App ID resolved
automatically from `client_id` (cached).

| Method | Auth | Returns | Notes |
|--------|------|---------|-------|
| `ListUsers(ctx, search, page, pageSize)` | JWT | `*UserListResponse` | paginated + `search` filter (pass `""` for none). |
| `GetUser(ctx, userID)` | JWT | `*User` | **nil,nil** on 404. |
| `CreateUser(ctx, CreateUserRequest)` | JWT | `*CreateUserResult` | sends an invite email; `ErrUserAlreadyExists` on 409. |
| `UpdateUserRole(ctx, userID, role)` | JWT | `error` | role ∈ `admin, manager, editor, viewer, user`. |
| `DeleteUser(ctx, userID)` | JWT | `error` | removes the user's role in this app. |
| `ResendVerification(ctx, userID)` | JWT | `error` | re-sends the verification email. |
| `ForcePasswordReset(ctx, userID)` | JWT | `error` | triggers a password-reset email. |
| `GetUserAsService(ctx, userID)` | M2M | `*User` | one of the app's members by numeric id (a token's `sub`); **nil,nil** when not a member (Socrate's 404). Needs a Socrate later than v1.5.3; an older one answers with an error, not nil,nil. |
| `RegisterUser(ctx, CreateUserRequest)` | M2M | `*CreateUserResult` | M2M create+invite, with `Name`; `ErrUserAlreadyExists` on 409. |
| `InviteUserAsService(ctx, ServiceInviteRequest)` | M2M | `*CreateUserResult` | dedicated M2M invite route; no human JWT needed. |

#### Passwordless — Admin port

| Method | Auth | Returns | Notes |
|--------|------|---------|-------|
| `SendMagicLink(ctx, email)` | M2M | `*MagicLinkResponse` | opaque 202 (enumeration-safe); `ErrMagicLinkRateLimited` on 429 (5/hr per email+app). `MagicURL` is non-empty in dev mode only. |

#### Policy decisions — Admin port

| Method | Auth | Returns | Notes |
|--------|------|---------|-------|
| `Decide(ctx, DecideRequest)` | M2M | `*Decision` | asks Socrate's policy decision point; `ErrPolicyUnavailable` on 503, with the mode kept in the `Decision`. Usually called through `pep` (§10). |

#### App (client) management — Admin port · admin JWT

| Method | Auth | Returns |
|--------|------|---------|
| `ListApps(ctx)` | JWT | `*AppListResponse` |
| `GetApp(ctx, appID)` | JWT | `*App` (nil,nil on 404) |
| `CreateApp(ctx, CreateAppRequest)` | JWT | `*AppWithSecret` (secret shown once!) |
| `UpdateApp(ctx, appID, UpdateAppRequest)` | JWT | `*App` |
| `DeleteApp(ctx, appID)` | JWT | `error` |
| `RotateSecret(ctx, appID)` | JWT | `*AppWithSecret` (new secret shown once!) |

#### App activity logs — Admin port · app-admin JWT

| Method | Auth | Returns | Notes |
|--------|------|---------|-------|
| `GetAppLogs(ctx, page, pageSize)` | JWT | `*AppActivityLogListResponse` | your app's own activity feed (`/api/apps/{id}/logs`). |

#### Global user administration — Admin port · superadmin JWT

| Method | Auth | Returns |
|--------|------|---------|
| `AdminListUsers(ctx, page, pageSize)` | JWT | `*GlobalUserListResponse` |
| `AdminGetUser(ctx, userID)` | JWT | `*GlobalUser` (nil,nil on 404) |
| `AdminDeleteUser(ctx, userID)` | JWT | `error` |
| `GetUserApps(ctx, userID)` | JWT | `[]App` |
| `BlockUser(ctx, userID)` | JWT | `error` |
| `UnlockUser(ctx, userID)` | JWT | `error` |
| `RevokeUserTokens(ctx, userID)` | JWT | `error` (forces re-login) |
| `ListSessions(ctx, page, pageSize)` | JWT | `*SessionListResponse` |
| `GetUserSessions(ctx, userID)` | JWT | `*SessionListResponse` |

#### Superadmins — Admin port

`ListSuperadmins`, `GetSuperadmin`, `CreateSuperadmin`, `UpdateSuperadmin`,
`DeleteSuperadmin` — all JWT (superadmin).

#### Security & monitoring — Admin port · admin JWT

| Method | Returns |
|--------|---------|
| `GetActivityLogs(ctx, page, pageSize)` | `*ActivityLogResponse` (security audit events) |
| `GetThreatMetrics(ctx)` | `*ThreatMetrics` |
| `ListBlockedIPs(ctx)` | `[]BlockedIP` |
| `BlockIP(ctx, BlockIPRequest)` | `*BlockedIP` |
| `UnblockIP(ctx, id)` | `error` |
| `GetIPReputation(ctx, ip)` | `*IPReputation` (nil,nil on 404) |
| `GetGeoAnalytics(ctx, period)` | `*GeoAnalytics` |
| `GetTokenStats(ctx, period)` | `*TokenStats` |
| `StreamSecurityEvents(ctx, StreamEventOptions, handler)` | `error` (blocks; SSE) |

#### Alerts — Admin port · admin JWT

| Method | Returns |
|--------|---------|
| `ListAlertRules(ctx)` | `*AlertRulesListResponse` |
| `CreateAlertRule(ctx, AlertRuleRequest)` | `*AlertRule` |
| `UpdateAlertRule(ctx, id, AlertRuleRequest)` | `*AlertRule` |
| `DeleteAlertRule(ctx, id)` | `error` |
| `GetAlertHistory(ctx, page, pageSize)` | `*AlertsHistoryResponse` |
| `AcknowledgeAlert(ctx, id, note)` | `error` |

#### Reports — Admin port · admin JWT

| Method | Returns |
|--------|---------|
| `GenerateSecurityReport(ctx, ReportRequest)` | `*Report` |
| `GetReportStatus(ctx, reportID)` | `*Report` (nil,nil on 404) |
| `DownloadReport(ctx, reportID)` | `[]byte` (JSON or CSV) |

#### Dashboard, audit & settings — Admin port · admin JWT

| Method | Returns |
|--------|---------|
| `GetDashboardStats(ctx)` | `*DashboardStats` |
| `GetDashboardHealth(ctx)` | `map[string]interface{}` |
| `GetDashboardActivity(ctx, limit)` | `*DashboardActivityResponse` |
| `GetLoginTrends(ctx, days)` | `*LoginTrendsResponse` |
| `GetAppUsage(ctx)` | `*AppUsageResponse` |
| `ListAdminLogs(ctx, page, pageSize)` | `*AdminLogListResponse` |
| `GetAdminLog(ctx, id)` | `*AdminLog` (nil,nil on 404) |
| `GetAdminActivity(ctx, page, pageSize)` | `*AdminLogListResponse` |
| `ExportAdminLogs(ctx)` | `[]byte` (CSV) |
| `GetAdminProfile(ctx)` | `*FullProfile` |
| `GetAdminStats(ctx)` | `map[string]interface{}` |
| `GetServerConfig(ctx)` | `*ServerConfig` |
| `TestDB(ctx)` / `TestCache(ctx)` | `*ConnectionTest` |

---

## 7. Frontend: driving the login flow

For a **browser app**, use a Backend-for-Frontend (§7.1). The browser then
never sees an access or refresh token: an XSS bug cannot steal one, and there is
no token to keep in `localStorage` or `sessionStorage`. The Socrate admin and
monitoring consoles work this way.

The flows where the client obtains and holds its own tokens (§7.2–§7.6) remain
for **mobile, native and CLI clients**, and for a legacy SPA that has not moved
to a BFF yet.

### 7.1 Browser apps: use a Backend-for-Frontend (bff)

The BFF is the confidential OAuth client. It runs Authorization Code + PKCE
server-side, keeps the tokens in a server-side session, and gives the browser
only an opaque `HttpOnly`, `SameSite=Strict`, `__Host-` session cookie. The SPA
calls same-origin paths; the BFF looks up the session, refreshes the access
token when it is about to expire, and forwards the request to your API with
`Authorization: Bearer` attached. Your API validates that token with `jwtauth`
exactly as in §4.

A minimal BFF with the `bff` package and `socrate.Client`:

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/ovander/backendkit/bff"
	"github.com/ovander/backendkit/socrate"
)

// pendingLogin is what the BFF remembers between /bff/login and /bff/callback.
type pendingLogin struct {
	Verifier, Nonce, ReturnTo string
	Expires                   time.Time
}

func main() {
	const socrateURL = "https://socrate.example.com"
	const redirectURI = "https://app.example.com/bff/callback"
	apiURL, _ := url.Parse("http://127.0.0.1:9000") // your API, reachable only from the BFF

	client, err := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      socrateURL,
		ClientID:     os.Getenv("SOCRATE_CLIENT_ID"),
		ClientSecret: os.Getenv("SOCRATE_CLIENT_SECRET"), // the BFF is a confidential client
	})
	if err != nil {
		log.Fatal(err)
	}

	store := bff.NewMemoryStore(30*time.Minute, 8*time.Hour) // idle, absolute
	go func() {
		for range time.Tick(time.Minute) {
			store.Sweep()
		}
	}()

	gw := &bff.Gateway{ // use by pointer; never copy
		Store:     store,
		Cookie:    bff.CookieConfig{Name: "app_session", Secure: true}, // sent as __Host-app_session
		Refresher: client,                                             // *socrate.Client refreshes tokens
	}
	login := bff.LoginBinding{Cookie: bff.CookieConfig{Name: "app_login", Secure: true}}

	var mu sync.Mutex
	pending := map[string]pendingLogin{} // keyed by state; use a shared store with several instances

	mux := http.NewServeMux()

	mux.HandleFunc("GET /bff/login", func(w http.ResponseWriter, r *http.Request) {
		p, state := bff.NewPKCE(), bff.RandomToken(32)
		mu.Lock()
		pending[state] = pendingLogin{
			Verifier: p.Verifier,
			Nonce:    login.Begin(w), // ties the callback to this browser
			ReturnTo: bff.SanitizeReturnTo(r.URL.Query().Get("return_to")),
			Expires:  time.Now().Add(bff.DefaultLoginBindingTTL),
		}
		mu.Unlock()
		q := url.Values{
			"response_type": {"code"}, "client_id": {os.Getenv("SOCRATE_CLIENT_ID")},
			"redirect_uri": {redirectURI}, "scope": {"openid profile email"}, "state": {state},
			"code_challenge": {p.Challenge}, "code_challenge_method": {"S256"},
		}
		http.Redirect(w, r, socrateURL+"/oauth/authorize?"+q.Encode(), http.StatusFound)
	})

	mux.HandleFunc("GET /bff/callback", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		mu.Lock()
		st, ok := pending[state]
		delete(pending, state) // single use
		mu.Unlock()
		if !ok || time.Now().After(st.Expires) || !login.Verify(w, r, st.Nonce) {
			http.Error(w, "invalid login", http.StatusBadRequest)
			return
		}
		ts, err := client.ExchangeCode(r.Context(), r.URL.Query().Get("code"), redirectURI, st.Verifier)
		if err != nil {
			http.Error(w, "login failed", http.StatusBadGateway)
			return
		}
		user := bff.UserInfo{Roles: ts.Roles}
		if p, err := client.GetCurrentUserProfile(socrate.WithJWT(r.Context(), ts.AccessToken)); err == nil && p != nil {
			user.Sub, user.Email, user.Name = p.Sub, p.Email, p.Name
		}
		s := bff.NewSession(bff.RandomToken(32), bff.RandomToken(32), ts, user, time.Now())
		store.Put(s)
		gw.Cookie.SetSession(w, s.ID())
		http.Redirect(w, r, st.ReturnTo, http.StatusFound)
	})

	// The SPA learns who is signed in, and the CSRF token to echo, from here.
	mux.HandleFunc("GET /bff/session", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		s, ok := gw.SessionFromRequest(r)
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "user": s.User(), "csrf": s.CSRF()})
	})

	// Every API call: session cookie in, bearer out. No valid session ⇒ 401.
	// Unsafe methods must carry the session's CSRF token in X-CSRF-Token.
	mux.HandleFunc("/api/", gw.ProxyWithSession(bff.NewSingleHostProxy(apiURL)))

	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux)) // behind your TLS edge proxy
}
```

The SPA side is small: navigate to `/bff/login?return_to=/current/path` to sign
in, read `GET /bff/session` to learn who is signed in, and send the `csrf`
value from that response as `X-CSRF-Token` on every `POST`, `PUT`, `PATCH` or
`DELETE`. It never sends an `Authorization` header.

```js
const session = await (await fetch('/bff/session')).json();
if (!session.authenticated) location.assign('/bff/login?return_to=' + encodeURIComponent(location.pathname));

await fetch('/api/reports', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrf },
  body: JSON.stringify(report),
});
```

What the package guarantees (a request without a valid session gets 401 and is
never forwarded; CSRF is checked in constant time; only a refresh Socrate
rejects ends a session) is listed in the README's
[`bff` reference](../README.md#bff). For more than one BFF instance, replace
`MemoryStore` and the `pending` map with a shared store; `Session.Snapshot` and
`NewSessionFromSnapshot` serialise a session.
[`oauth2-admin/bff`](https://github.com/ovander/oauth2-admin/tree/main/bff)
is a complete BFF built this way, with logout and token revocation.

Magic links fit the same model: the page the emailed link opens posts the
token to your BFF, which calls `client.VerifyMagicLink` and creates the session.

#### Client attribution: telling Socrate who the browser is

The BFF calls `/oauth/token` (code exchange, refresh) and `/oauth/revoke`
server-to-server, usually over loopback. Socrate records the client IP and
User-Agent of every audited event, so without more it logs those as the BFF
(`127.0.0.1`, `Go-http-client/1.1`), and its per-IP rate limits and IP blocks
on the token endpoint apply to the BFF as a whole. Client attribution is
opt-in: put the browser's address and User-Agent on the request context, and
the `socrate.Client` calls made on the user's behalf (`ExchangeCode`,
`RefreshToken`, `RevokeToken`, `VerifyMagicLink`, `AdminLogin`, `Logout`,
`Signup`) send them as `X-Forwarded-For` and `User-Agent`. The `client_credentials` grant,
introspection and userinfo never do: no browser is involved.

```go
// clientIP is YOUR resolver: trust X-Forwarded-For only when the peer is your
// own edge proxy (e.g. loopback), else use RemoteAddr.
attribute := func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, bff.WithClientAttribution(r, clientIP(r)))
	})
}
log.Fatal(http.ListenAndServe("127.0.0.1:8080", attribute(mux)))
```

With that one wrapper, the callback's `client.ExchangeCode(r.Context(), …)`,
the gateway's refresh (it keeps the request context's values while detaching
its cancellation) and a logout's `client.RevokeToken(r.Context(), …)` are all
attributed. A BFF that builds its own token or revoke requests calls
`socrate.ApplyClientAttribution(req)` on each, with a context carrying the
attribution.

Two rules:

- **Pass an address you resolved, never a header.** Socrate trusts what the BFF
  sends from loopback. Passing the browser's own `X-Forwarded-For` or
  `X-Real-IP` would let it pick the address it is rate-limited, blocked and
  audited as. backendkit does not resolve client IPs; your BFF does.
- **Replace, never append.** `X-Forwarded-For` is set to exactly the one
  address, and `X-Real-IP` removed, because Socrate takes the **leftmost**
  entry from a trusted proxy: appending to a browser-supplied value would leave
  the browser's claim leftmost. An address that does not parse sends nothing;
  the User-Agent has control characters removed and is capped at 512 bytes.

Socrate honours the header only when the connection comes from one of its
`TRUSTED_PROXIES` (default `127.0.0.1/32,::1/128`), so a BFF on the same host
is covered; a BFF on another host needs its address added there, never a wide
range.

### 7.2 Alternative: clients that hold their own tokens

> ⚠️ **Use this only for mobile, native or CLI clients, or a legacy SPA not yet
> behind a BFF.** A client that holds tokens has to protect them itself. In a
> browser that is hard: any script running on the page — an XSS bug, a
> compromised dependency, a browser extension — can read tokens and PKCE state
> kept in memory, `sessionStorage` or `localStorage`, and a stolen refresh token
> keeps working until it is rotated or revoked. Keep access tokens short-lived,
> never put a client secret in the client, and plan the move to §7.1.

Native apps should run the authorization request in the system browser and
receive the redirect on a claimed HTTPS link, a private-use URI scheme or a
loopback address (RFC 8252). The steps below show the protocol with browser
APIs.

### 7.3 Authorization Code + PKCE in the client

For a public client (no client secret).

**Step 1 — generate a PKCE verifier/challenge and redirect to Socrate:**

```js
// Generate a high-entropy verifier and its S256 challenge.
function base64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
const digest   = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
const challenge = base64url(digest);

// Legacy SPA only: sessionStorage is readable by any script on the page.
sessionStorage.setItem('pkce_verifier', verifier);
const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
sessionStorage.setItem('oauth_state', state);

const url = new URL('https://socrate.example.com/oauth/authorize');
url.search = new URLSearchParams({
  response_type: 'code',
  client_id: 'YOUR_CLIENT_ID',
  redirect_uri: 'https://app.example.com/callback',
  scope: 'openid email profile',
  state,
  code_challenge: challenge,
  code_challenge_method: 'S256',
}).toString();

window.location.assign(url);
```

**Step 2 — at your `redirect_uri`, exchange the `code` for tokens:**

```js
const params = new URLSearchParams(window.location.search);
if (params.get('state') !== sessionStorage.getItem('oauth_state')) {
  throw new Error('state mismatch — possible CSRF');
}

const res = await fetch('https://socrate.example.com/oauth/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.get('code'),
    redirect_uri: 'https://app.example.com/callback',
    client_id: 'YOUR_CLIENT_ID',
    code_verifier: sessionStorage.getItem('pkce_verifier'),
  }),
});
const { access_token, refresh_token, id_token } = await res.json();
```

**Step 3 — refresh** when the access token expires:

```js
new URLSearchParams({
  grant_type: 'refresh_token',
  refresh_token,
  client_id: 'YOUR_CLIENT_ID',
});
```

### 7.4 Direct JSON login (first-party only)

For your *own* trusted frontends, Socrate exposes a JSON auth API on the public
port — no redirect dance. Only use this for apps you own end-to-end.

```
POST /api/auth/signup           {email, password, name}
GET  /api/auth/verify-email?token=...
POST /api/auth/login            {email, password}      → {access_token, refresh_token, id_token}
POST /api/auth/refresh          {refresh_token}
POST /api/auth/logout           (Bearer)
POST /api/auth/request-password-reset  {email}
POST /api/auth/reset-password   {token, new_password}
```

These endpoints are rate-limited per IP. Their request and response shapes are
documented in the Socrate server repository.

### 7.5 Magic link (passwordless)

Magic-link **send** is backend-only (M2M) — your frontend asks *your backend*,
which calls `client.SendMagicLink`. The user clicks the emailed link, and the
page it opens completes the login.

**Register that page first.** Since Socrate v1.6.0 each application has a
magic-link page (`magic_link_url`, the "Magic-link page" field on the
application in the admin console): an `https` URL on the same origin as one of
the app's redirect URIs. The e-mail opens it with `?token=…&client_id=…`. Without
it, `SendMagicLink` gets `409` and no e-mail is sent.

**The page must not redeem the token on load** (mail scanners open links), and
should remove the token from the address bar and send `Referrer-Policy:
no-referrer`. On a click, it posts the token to **your BFF**, which redeems it
and creates the session as the callback does (§7.1):

```go
// Pre-session POST: there is no session yet to carry a CSRF token, so require a
// same-origin JSON request (a cross-site form cannot send this Content-Type
// without a CORS preflight) and check Origin, against login CSRF.
mux.HandleFunc("POST /bff/magic-link/verify", func(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != appOrigin || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&in); err != nil || in.Token == "" {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	lr, err := client.VerifyMagicLink(r.Context(), in.Token)
	switch {
	case errors.Is(err, socrate.ErrMagicLinkAlreadyUsed):
		http.Error(w, "this link has already been used", http.StatusUnprocessableEntity)
		return
	case err != nil:
		http.Error(w, "invalid or expired link", http.StatusUnauthorized)
		return
	}
	ts := lr.TokenSet() // the same *TokenSet the callback's ExchangeCode returns
	user := bff.UserInfo{Roles: ts.Roles}
	if p, err := client.GetCurrentUserProfile(socrate.WithJWT(r.Context(), ts.AccessToken)); err == nil && p != nil {
		user.Sub, user.Email, user.Name = p.Sub, p.Email, p.Name
	}
	s := bff.NewSession(bff.RandomToken(32), bff.RandomToken(32), ts, user, time.Now())
	store.Put(s)
	gw.Cookie.SetSession(w, s.ID())
	w.WriteHeader(http.StatusNoContent)
})
```

The verify call uses this BFF's own client ID; ignore the `client_id` in the
link. A client that holds its own tokens (§7.2) posts the token to Socrate
instead:

```js
// User landed on your magic-link page with ?token=...&client_id=... in the URL.
// Verify is POST-only (a GET would let email scanners burn the single-use token).
const res = await fetch('https://socrate.example.com/api/auth/magic-link/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    token: new URLSearchParams(location.search).get('token'),
    client_id: new URLSearchParams(location.search).get('client_id'),
  }),
});
const { access_token, refresh_token, id_token } = await res.json();
```

### 7.6 Calling your backend with a bearer token

A client that holds an `access_token` sends it on every call to *your* backend:

```js
await fetch('https://api.example.com/me', {
  headers: { Authorization: `Bearer ${access_token}` },
});
```

Your backend's `jwtauth.Middleware` validates it and your handlers read identity
from `ctxutil`. **The frontend never talks to Socrate's admin API port** — route
admin/user-management actions through your backend.

---

## 8. Error handling

### Sentinel errors from the client

Use `errors.Is` — don't string-match:

```go
inv, err := client.RegisterUser(ctx, req)
switch {
case errors.Is(err, socrate.ErrUserAlreadyExists):   // 409
	// already a member — treat as success or surface a friendly message
case errors.Is(err, socrate.ErrMagicLinkRateLimited): // 429 (SendMagicLink)
	// back off; 5 per email+app per hour
case err != nil:
	return fmt.Errorf("register: %w", err)
}
```

### "Not found" is `(nil, nil)`, not an error

Getters return `nil, nil` on 404 so a missing resource isn't an exception:

```go
user, err := client.GetUser(ctx, id)
if err != nil {
	return err          // a real failure
}
if user == nil {
	return apierror.NotFound("user", id).WriteJSON(w) // 404, cleanly
}
```

Methods with this behavior: `GetUser`, `GetUserAsService`, `GetApp`,
`AdminGetUser`, `GetSuperadmin`, `GetIPReputation`, `GetAdminLog`, and
`GetCurrentUserProfile` (also nil on 401).

### Returning structured errors to your frontend

`apierror` produces a consistent JSON envelope your frontend can localize via
the `key` field:

```go
apierror.BadRequest("invalid role").
	WithKey("errors.invalidRole").
	WriteJSON(w)
```

```json
{ "error": { "code": "bad_request", "key": "errors.invalidRole", "message": "invalid role" } }
```

Constructors: `NotFound`, `ValidationError`, `BadRequest`, `Unauthorized`,
`Forbidden`, `Conflict`, `Internal`, `ServiceUnavailable`. `jwtauth.Middleware`
already emits `Unauthorized` for bad tokens in this exact shape.

> **Frontend note — 5xx responses (since v1.9.0).** For **server errors (≥ 500)**,
> `WriteJSON` replaces `message` with a generic status text and omits `details`,
> so internal detail can never leak to clients. **Key your UI on `error.code`, not
> `error.message`, for 5xx** — the message is intentionally non-specific there.
> 4xx responses are unchanged: their `code`, `key`, and `message` are all yours to
> display.

---

## 9. Role & plan gating

Two complementary layers, both reading from the validated JWT context.

### Role-based access control (`httpware.RBAC`)

Map your app's roles to permissions once, then guard routes:

```go
rbac := httpware.NewRBAC(httpware.RoleMap{
	"viewer": {"read:reports"},
	"editor": {"read:reports", "write:reports"},
	"admin":  {"read:reports", "write:reports", "delete:reports"},
}, log)

r.With(rbac.Require("write:reports")).Post("/reports", createReport)
```

`Require` reads `ctxutil.GetUserRole` and returns **403** when the role lacks the
permission. (Put it *after* `auth.Handler`.)

### Plan-based feature gating (`tiering.Gate`)

Gate premium features behind a minimum commercial plan:

```go
plans := tiering.DefaultRegistry() // freemium < pro < enterprise
gate  := tiering.NewGate(plans, log, "https://app.example.com/upgrade")

r.With(gate.Require(tiering.PlanPro)).Get("/analytics", analyticsHandler)
```

`Require` reads `ctxutil.GetUserPlan` (defaults to `"freemium"` when the server
doesn't issue a `plan` claim) and blocks lower tiers, pointing them at your
upgrade URL.

### Tenant isolation (`httpware.RequireTenant`)

For multi-tenant apps, mount `httpware.RequireTenant` after `auth.Handler` on
tenant-scoped route groups. It returns **401** when no tenant is in context
(`ctxutil.GetTenantID == uuid.Nil`), so a handler can never run against the nil
tenant. Requires Socrate to issue the `tenant_id` claim (see §5).

```go
r.Group(func(r chi.Router) {
	r.Use(auth.Handler)
	r.Use(httpware.RequireTenant)
	r.Mount("/orders", ordersRouter)
})
```

---

## 10. Enforcing central policy decisions (pep)

`httpware.RBAC` and `tiering.Gate` (§9) decide locally, from rules compiled into
your service. When the rule should live in Socrate instead — one declarative
policy over roles, user attributes, resource attributes and request context,
shared by every application — use `pep`, the enforcement point for Socrate's
policy decision point.

Prerequisites: the client needs `ClientSecret` and `AppID` (`Decide` uses the
service-account token), and `pep` runs after `jwtauth`, because the user's own
access token is sent as the decision's subject. Socrate resolves the user — role,
attributes, role in this application, how and when they authenticated — so
nothing about the user is taken on your application's word. Your application
supplies the action, the resource and the request context.

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"

	"github.com/ovander/backendkit/jwtauth"
	"github.com/ovander/backendkit/pep"
	"github.com/ovander/backendkit/socrate"
)

type invoice struct {
	ID      string
	Amount  int
	OwnerID string
}

func loadInvoice(r *http.Request) invoice { return invoice{ID: chi.URLParam(r, "id")} }

func main() {
	logger := logrus.WithField("service", "billing")

	client, err := socrate.NewClient(socrate.ClientConfig{
		BaseURL:      os.Getenv("SOCRATE_BASE_URL"),
		ClientID:     os.Getenv("SOCRATE_CLIENT_ID"),
		ClientSecret: os.Getenv("SOCRATE_CLIENT_SECRET"), // Decide uses the service-account token
		AppID:        os.Getenv("SOCRATE_APP_ID"),        // required by Decide
	})
	if err != nil {
		log.Fatal(err)
	}
	enf, err := pep.New(pep.Config{Decider: client, Logger: logger})
	if err != nil {
		log.Fatal(err)
	}

	auth := jwtauth.New(os.Getenv("SOCRATE_JWKS_URL"), os.Getenv("SOCRATE_ISSUER"), logger,
		jwtauth.WithAudience(os.Getenv("SOCRATE_CLIENT_ID")))

	r := chi.NewRouter()
	r.Use(auth.Handler) // first: the user's own token is the decision's subject

	// Route level: one decision before the handler runs.
	r.With(enf.Middleware(func(r *http.Request) (string, socrate.PolicyResource, bool) {
		return "invoice.read", socrate.PolicyResource{Type: "invoice"}, true
	})).Get("/invoices", func(w http.ResponseWriter, r *http.Request) { /* … */ })

	// Object level: once the resource is loaded, with its attributes.
	r.Post("/invoices/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		inv := loadInvoice(r)
		err := enf.Check(r.Context(), "invoice.approve", socrate.PolicyResource{
			Type: "invoice", ID: inv.ID,
			Attributes: map[string]any{"amount": inv.Amount, "owner_id": inv.OwnerID},
		}, pep.ContextFor(r))
		if pep.WriteDenial(w, err) { // 403 policy_denied, 403 mfa_required, 503 policy_unavailable…
			return
		}
		// … approve
	})

	log.Fatal(http.ListenAndServe(":8080", r))
}
```

What happens to a denial depends on the mode Socrate reports with each decision,
set centrally by its `POLICY_MODE`: `off` ignores it, `shadow` logs
`pep: policy would deny` and lets the request through, `enforce` refuses it. So
you can deploy the checks in `shadow`, read the would-deny lines, and switch to
`enforce` in Socrate without redeploying.

Your frontend sees these error codes, in the `{"error": "<code>"}` shape:

| Status | `error` | Meaning |
|--------|---------|---------|
| 401 | `unauthenticated` | no user token in context (`pep` mounted before `jwtauth`) |
| 403 | `policy_denied` | the policy refused the action (`enforce` mode) |
| 403 | `elevation_required` | the policy requires a recent sign-in; re-authenticate |
| 403 | `mfa_required` | the policy requires multi-factor authentication |
| 503 | `policy_unavailable` | Socrate could not be asked and the mode is `enforce`, or not yet known |

The README's [`pep` reference](../README.md#pep) details obligations, the
behaviour when Socrate is unreachable (`FailOpenWhenModeUnknown`), `CheckAsApp`
for background jobs and the `OnDecision` metrics hook.

---

## 11. Recipes

### Onboard a teammate from your backend (M2M)

```go
func InviteTeammate(ctx context.Context, c *socrate.Client, email, role string) error {
	_, err := c.InviteUserAsService(ctx, socrate.ServiceInviteRequest{
		Email: email, Role: role,
	})
	if errors.Is(err, socrate.ErrUserAlreadyExists) {
		return nil // idempotent: already a member
	}
	return err
}
```

### A user-management page in your dashboard (JWT-forwarding)

```go
// Caller's admin JWT is already in r.Context() via jwtauth.Middleware.
func ListTeam(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	list, err := client.ListUsers(r.Context(), r.URL.Query().Get("q"), page, 20)
	if err != nil {
		apierror.Internal("failed to list users").WriteJSON(w)
		return
	}
	_ = json.NewEncoder(w).Encode(list)
}
```

### Show the logged-in user's profile

```go
func Me(w http.ResponseWriter, r *http.Request) {
	p, err := client.GetCurrentUserProfile(r.Context())
	if err != nil {
		apierror.Internal("profile lookup failed").WriteJSON(w); return
	}
	if p == nil { // token rejected upstream
		apierror.Unauthorized("not authenticated").WriteJSON(w); return
	}
	_ = json.NewEncoder(w).Encode(p) // {sub, email, name, ...}
}
```

### Validate a token out-of-band (e.g. a webhook receiver)

```go
res, err := client.IntrospectToken(ctx, incomingToken)
if err != nil || !res.Active {
	http.Error(w, "invalid token", http.StatusUnauthorized)
	return
}
```

---

## 12. Quick reference

### Method → endpoint → auth → port

`OAuth` is Socrate's public OAuth/OIDC port; `Admin` is its internal admin API
port (8081 in the default deployment).

| Client method | HTTP | Auth | Port |
|---------------|------|------|------|
| `GetCurrentUserProfile` | `GET /oauth/userinfo` | JWT | OAuth |
| `IntrospectToken` | `POST /oauth/introspect` | creds | OAuth |
| `RevokeToken` | `POST /oauth/revoke` | creds | OAuth |
| `ListUsers` / `GetUser` / `CreateUser` | `…/api/apps/{id}/users` | JWT | Admin |
| `UpdateUserRole` / `DeleteUser` | `…/api/apps/{id}/users/{uid}` | JWT | Admin |
| `ResendVerification` / `ForcePasswordReset` | `…/users/{uid}/…` | JWT | Admin |
| `RegisterUser` / `InviteUserAsService` | `POST …/api/apps/{id}/service/users` | M2M | Admin |
| `GetUserAsService` | `GET …/api/apps/{id}/service/users/{uid}` | M2M | Admin |
| `SendMagicLink` | `POST …/api/apps/{id}/service/magic-link` | M2M | Admin |
| `ListApps` … `RotateSecret` | `…/api/admin/apps…` | JWT (admin) | Admin |
| `AdminListUsers` … `RevokeUserTokens` | `…/api/admin/users…` | JWT (superadmin) | Admin |
| `*Superadmin*` | `…/api/admin/superadmins…` | JWT (superadmin) | Admin |
| `GetThreatMetrics` … `GetIPReputation` | `…/api/admin/security…` | JWT (admin) | Admin |
| `GetDashboard*` / `*AdminLog*` | `…/api/admin/dashboard…`, `…/api/admin/logs…` | JWT (admin) | Admin |
| `Decide` | `POST …/api/apps/{id}/service/policy/decide` | M2M | Admin |

### Roles (highest → lowest privilege)

`admin` › `manager` › `editor` › `viewer` › `user`

### Plans (`tiering.DefaultRegistry`)

`freemium` ‹ `pro` ‹ `enterprise`

---

## 13. Gotchas & FAQ

**"no JWT in context" error from a client method.** A mode-A (JWT-forwarding)
method ran without a token in context. Inside a handler, ensure `auth.Handler`
runs first and you pass `r.Context()`. Outside one, wrap with
`socrate.WithJWT(ctx, rawJWT)`.

**"AppID must be set in ClientConfig" on a service-account call.** Set `AppID`
(the numeric app ID, not the `client_id`) in `ClientConfig`. Service tokens
can't resolve it at runtime.

**`GetUserEmail` returns "".** Access tokens don't carry email/name. Call
`GetCurrentUserProfile` instead, or have the frontend send the ID token only
where you specifically need OIDC claims.

**`GetUserPlan` always returns "freemium".** The default Socrate server doesn't
issue a `plan` claim. Either configure the server to emit it, or resolve the
plan from your own database after identifying the user by `sub`.

**Frontend gets 401 from my backend but the token "looks valid".** Common
causes: wrong `SOCRATE_ISSUER` (issuer mismatch), clock skew (expired), or the
JWKS URL pointing at the wrong environment. Check `jwtauth` logs — it logs the
validation failure reason.

**`SendMagicLink` answers 409.** The application has no magic-link page
registered (§7.5). The e-mail opening a `405` means a Socrate older than v1.6.0.

**An administrator of another application is an administrator here.** The
audience is not checked: add `jwtauth.WithAudience(clientID)` (§5).

**Invitations and magic-link e-mails fail, but sign-in works.** The admin API is
unreachable from your host: check `AdminBaseURL` and, on a separate host, the SSH
tunnel. The [migration guide](MIGRATING-TO-SOCRATE.md#6-symptom-index) has a
longer symptom index.

**Should the frontend ever call Socrate's admin API port?** No. It's internal
(8081 in the default deployment).
Proxy every admin/user-management action through your backend so you can apply
your own authorization first.

**The BFF answers 403 on a `POST`.** The request lacks the session's CSRF
token. Read `csrf` from your session endpoint and send it as `X-CSRF-Token` on
every unsafe method (§7.1).

**Every `pep` check answers 401.** `pep` runs before `jwtauth`, so there is no
user token in context. Mount `auth.Handler` first (§10).

**Is the client safe to share across goroutines?** Yes. Construct one at startup
and reuse it; the service-account token cache is mutex-guarded.

---

### See also

- [`README.md`](../README.md) — package-by-package reference for all of backendkit.
- The Socrate server repository (`ovander/go-oauth2`, not public yet) documents the raw HTTP API.
- Go API docs: <https://pkg.go.dev/github.com/ovander/backendkit/socrate>
