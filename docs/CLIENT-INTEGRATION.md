# Socrate + backendkit — Client Integration Guide

A practical, end-to-end guide for **application teams** integrating with the
[Socrate](https://github.com/ovander/socrate) OAuth 2.0 / OpenID Connect server
through the `backendkit` library.

It is written for two audiences working on the same product:

- **Backend engineers** building a Go service that trusts Socrate-issued JWTs
  and needs to manage users, profiles and security data.
- **Frontend engineers** (SPA / mobile / native) driving the login flow and
  calling that backend.

> **Reference vs. guide.** This document is the *client-side* integration
> guide. The authoritative description of every raw HTTP endpoint lives in the
> server repo at [`go-oauth2/docs/API.md`](https://github.com/ovander/go-oauth2/blob/main/docs/API.md).
> When the two disagree, the server doc wins. This guide tells you how to wire
> things up; that doc tells you exactly what each endpoint returns.

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
  - [7.1 Authorization Code + PKCE (recommended)](#71-authorization-code--pkce-recommended)
  - [7.2 Direct JSON login (first-party only)](#72-direct-json-login-first-party-only)
  - [7.3 Magic link (passwordless)](#73-magic-link-passwordless)
  - [7.4 Calling your backend](#74-calling-your-backend)
- [8. Error handling](#8-error-handling)
- [9. Role & plan gating](#9-role--plan-gating)
- [10. Recipes](#10-recipes)
- [11. Quick reference](#11-quick-reference)
- [12. Gotchas & FAQ](#12-gotchas--faq)

---

## 1. The mental model

Socrate is the **identity provider**. It owns users, passwords, apps
(`client_id` / `client_secret`), issues RS256-signed JWTs, and exposes an admin
surface for managing all of that.

Your application is split into a **frontend** and a **backend**:

- The **frontend** never validates tokens. It obtains them from Socrate (via the
  Authorization Code flow, direct login, or magic link) and sends them as
  `Authorization: Bearer <token>` to your backend.
- The **backend** validates every incoming token against Socrate's public keys
  (JWKS), reads the user's identity and role from the verified claims, and —
  when it needs to act on Socrate (list users, invite a teammate, look up a
  profile) — calls Socrate through the `socrate.Client`.

`backendkit` is the glue for the backend half: JWT validation
(`jwtauth`), claim propagation (`ctxutil`), the typed Socrate API client
(`socrate`), a middleware stack (`httpware`), structured errors (`apierror`),
and plan-based feature gating (`tiering`).

```
                         ┌────────────────────────────────────┐
                         │              Socrate                │
   login / tokens        │  :8080  OAuth/OIDC (public)         │
  ┌────────────────────▶ │         /oauth/*  /.well-known/*    │
  │                      │  :8081  Admin API (internal)        │
  │                      │         /api/admin/*  /api/apps/*    │
  │                      └────────────────────────────────────┘
  │                            ▲                     ▲
  │                            │ JWKS (validate)     │ socrate.Client
  │                            │                     │ (JWT-forward + M2M)
  │  Bearer JWT          ┌─────┴─────────────────────┴──────┐
┌─┴────────────┐  API    │           Your backend (Go)       │
│   Frontend   │ ──────▶ │  jwtauth → ctxutil → httpware →    │
│ SPA / mobile │         │  your handlers → socrate.Client   │
└──────────────┘         └───────────────────────────────────┘
```

---

## 2. Who talks to what

| Actor | Talks to | How | Auth |
|-------|----------|-----|------|
| Frontend | **Socrate :8080** | Authorization Code + PKCE, or `POST /api/auth/login` | none → receives tokens |
| Frontend | **Your backend** | your REST API | `Bearer <access_token>` |
| Your backend | **Socrate :8080** | `jwtauth` fetches JWKS; `socrate.Client` calls `/oauth/*` | JWKS is public; introspect/revoke use client creds |
| Your backend | **Socrate :8081** | `socrate.Client` admin & app-user calls | forwards the user JWT **or** a service-account token |

The **:8081 admin port is internal**. Your frontend must never reach it
directly — all admin/app-user operations go *through your backend* via the
`socrate.Client`, which lets you enforce your own authorization first.

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
| `SOCRATE_JWKS_URL` | `jwtauth.New` | JWKS endpoint, e.g. `https://auth.example.com/.well-known/jwks.json` |
| `SOCRATE_ISSUER` | `jwtauth.New` | Expected `iss` claim — optional but recommended in production |
| `SOCRATE_BASE_URL` | `socrate.NewClient` | OAuth (public) port base URL, e.g. `https://auth.example.com` |
| `SOCRATE_ADMIN_BASE_URL` | `socrate.NewClient` | Admin port base URL — derived from `BaseURL` (`:8081`) if omitted |
| `SOCRATE_CLIENT_ID` | `socrate.NewClient` | Your app's OAuth client ID |
| `SOCRATE_CLIENT_SECRET` | `socrate.NewClient` | Client secret — required for service-account calls, `RevokeToken`, `IntrospectToken` |
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
	// AdminBaseURL: "https://auth.example.com:8081",   // optional; derived from BaseURL if empty
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

- **OAuth port** (`BaseURL`, `:8080`): `GetCurrentUserProfile`, `RevokeToken`,
  `IntrospectToken`, and the internal token exchange.
- **Admin port** (`AdminBaseURL`, `:8081`): everything else — app-user
  management, app management, superadmins, security, dashboard, audit logs,
  magic links.

`AdminBaseURL` defaults to `BaseURL` with the host port replaced by `8081`.
Override it explicitly if your admin port lives on a different host.

### 6.4 Method reference

Legend — **Auth**: `JWT` = forwards caller JWT (mode A), `M2M` = service-account
(mode B), `creds` = client_id/secret form post. **Port**: which Socrate router.

#### Current user / OIDC — OAuth port

| Method | Auth | Returns | Notes |
|--------|------|---------|-------|
| `GetCurrentUserProfile(ctx)` | JWT | `*ProfileInfo` | `/oauth/userinfo`; **nil,nil** on 401/404. Limited OIDC claim set. |
| `GetProfile(ctx)` | JWT | `*FullProfile` | full editable profile (`/api/profile`); **nil,nil** on 404. |
| `UpdateProfile(ctx, UpdateProfileRequest)` | JWT | `*FullProfile` | patches the caller's own profile (name, phone, company, …). |
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
| `RefreshToken(ctx, refreshToken)` | creds | `*TokenSet` | refresh-token grant. |
| `VerifyMagicLink(ctx, token)` | client_id | `*LoginResult` | completes passwordless login; `ErrMagicLinkAlreadyUsed` (422), `ErrMagicLinkInvalid` (401). |
| `AdminLogin(ctx, email, password)` | creds | `*LoginResult` | superadmin portal login; `ErrInvalidCredentials` (401). |

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
| `GetUserAsService(ctx, userID)` | M2M | `*User` | service-account variant; **nil,nil** on 404. |
| `RegisterUser(ctx, CreateUserRequest)` | M2M | `*CreateUserResult` | M2M create+invite; `ErrUserAlreadyExists` on 409. |
| `InviteUserAsService(ctx, ServiceInviteRequest)` | M2M | `*CreateUserResult` | dedicated M2M invite route; no human JWT needed. |

#### Passwordless — Admin port

| Method | Auth | Returns | Notes |
|--------|------|---------|-------|
| `SendMagicLink(ctx, email)` | M2M | `*MagicLinkResponse` | opaque 202 (enumeration-safe); `ErrMagicLinkRateLimited` on 429 (5/hr per email+app). `MagicURL` is non-empty in dev mode only. |

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

The frontend's job is to obtain tokens from Socrate and attach them to backend
requests. Pick **one** primary flow.

> **Prefer a BFF?** If you'd rather keep tokens server-side and out of the
> browser entirely, let the frontend send the `code` (and your own session
> cookie) to your backend, and do the exchange there with
> `client.ExchangeCode` / `client.RefreshToken` / `client.VerifyMagicLink`
> (§6.4, "BFF token flows"). The browser steps below collapse to "redirect,
> then hand the `code` to my backend".

### 7.1 Authorization Code + PKCE (recommended)

The standard, most secure browser flow. Works for public clients (SPA/mobile)
with **no client secret**.

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

sessionStorage.setItem('pkce_verifier', verifier);
const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
sessionStorage.setItem('oauth_state', state);

const url = new URL('https://auth.example.com/oauth/authorize');
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

const res = await fetch('https://auth.example.com/oauth/token', {
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

### 7.2 Direct JSON login (first-party only)

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

These endpoints are rate-limited per IP. See `go-oauth2/docs/API.md` §5 for full
shapes.

### 7.3 Magic link (passwordless)

Magic-link **send** is backend-only (M2M) — your frontend asks *your backend*,
which calls `client.SendMagicLink`. The user clicks the emailed link, and your
frontend completes it:

```js
// User landed on your magic-link page with ?token=...&client_id=... in the URL.
// Verify is POST-only (a GET would let email scanners burn the single-use token).
const res = await fetch('https://auth.example.com/api/auth/magic-link/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    token: new URLSearchParams(location.search).get('token'),
    client_id: new URLSearchParams(location.search).get('client_id'),
  }),
});
const { access_token, refresh_token, id_token } = await res.json();
```

### 7.4 Calling your backend

Once you hold an `access_token`, every call to *your* backend carries it:

```js
await fetch('https://api.example.com/me', {
  headers: { Authorization: `Bearer ${access_token}` },
});
```

Your backend's `jwtauth.Middleware` validates it and your handlers read identity
from `ctxutil`. **The frontend never talks to the :8081 admin port** — route
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

## 10. Recipes

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

## 11. Quick reference

### Method → endpoint → auth → port

| Client method | HTTP | Auth | Port |
|---------------|------|------|------|
| `GetCurrentUserProfile` | `GET /oauth/userinfo` | JWT | 8080 |
| `IntrospectToken` | `POST /oauth/introspect` | creds | 8080 |
| `RevokeToken` | `POST /oauth/revoke` | creds | 8080 |
| `ListUsers` / `GetUser` / `CreateUser` | `…/api/apps/{id}/users` | JWT | 8081 |
| `UpdateUserRole` / `DeleteUser` | `…/api/apps/{id}/users/{uid}` | JWT | 8081 |
| `ResendVerification` / `ForcePasswordReset` | `…/users/{uid}/…` | JWT | 8081 |
| `RegisterUser` / `GetUserAsService` | `…/api/apps/{id}/users…` | M2M | 8081 |
| `InviteUserAsService` | `POST …/api/apps/{id}/service/users` | M2M | 8081 |
| `SendMagicLink` | `POST …/api/apps/{id}/service/magic-link` | M2M | 8081 |
| `ListApps` … `RotateSecret` | `…/api/admin/apps…` | JWT (admin) | 8081 |
| `AdminListUsers` … `RevokeUserTokens` | `…/api/admin/users…` | JWT (superadmin) | 8081 |
| `*Superadmin*` | `…/api/admin/superadmins…` | JWT (superadmin) | 8081 |
| `GetThreatMetrics` … `GetIPReputation` | `…/api/admin/security…` | JWT (admin) | 8081 |
| `GetDashboard*` / `*AdminLog*` | `…/api/admin/dashboard|logs…` | JWT (admin) | 8081 |

### Roles (highest → lowest privilege)

`admin` › `manager` › `editor` › `viewer` › `user`

### Plans (`tiering.DefaultRegistry`)

`freemium` ‹ `pro` ‹ `enterprise`

---

## 12. Gotchas & FAQ

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

**Should the frontend ever call the :8081 admin port?** No. It's internal.
Proxy every admin/user-management action through your backend so you can apply
your own authorization first.

**Is the client safe to share across goroutines?** Yes. Construct one at startup
and reuse it; the service-account token cache is mutex-guarded.

---

### See also

- [`README.md`](../README.md) — package-by-package reference for all of backendkit.
- [`go-oauth2/docs/API.md`](https://github.com/ovander/go-oauth2/blob/main/docs/API.md) — the canonical server-side HTTP API reference.
- Go API docs: <https://pkg.go.dev/github.com/ovander/backendkit/socrate>
