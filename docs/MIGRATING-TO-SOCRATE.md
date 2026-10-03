# Moving an application onto Socrate

A field guide for the team that moves an existing application onto a Socrate instance with
backendkit. It condenses what went wrong, and what worked, when Ascenda (2026-09-29 to 10-01)
and then Parashift (2026-10-01) moved onto the suite's Socrate. The
[client integration guide](CLIENT-INTEGRATION.md) explains how each piece works; this page is
the order to do things in and the traps on the way.

Versions this page assumes: **Socrate v1.6.0** or later (per-app magic-link page, service-account
member look-up) and **backendkit v1.15.1** or later (`RegisterUser` and `GetUserAsService` on the
service-account routes). Profile edits by the application, avatars and the durable BFF session
store (§3.7, §3.8) need **Socrate v1.7.0** and **backendkit v1.17.0**.

## 1. Before you write code

**Get these from the Socrate operator.** A new Socrate instance means new identifiers, even for
an application that already used an older one.

| Value | Where the operator finds it | Used for |
|---|---|---|
| Issuer (public URL) | the server's `OAUTH_ISSUER`; the admin console's Settings | `jwtauth.New`, `socrate.ClientConfig.BaseURL` |
| Client ID | the admin console, application page | `ClientConfig.ClientID`, `jwtauth.WithAudience` |
| Client secret | shown **once**, at creation or rotation | `ClientConfig.ClientSecret` |
| **Numeric app ID** | the admin console, application page ("ID 3") | `ClientConfig.AppID`: required for every service-account call |
| Admin API address, from your host | see §3.4 | `ClientConfig.AdminBaseURL` |
| Whether user IDs were carried over | the operator's migration notes | your users table |

Socrate's `sub` is its user row's numeric primary key. If your data is keyed by `sub` and the
users were **not** carried over with their IDs, every user arrives as a stranger: settle that
before the cut-over, not after.

**Write a dated, read-only compatibility report first.** Compare what your application does
today (the endpoints it calls, the claims it reads, the token it sends where) with what Socrate
does, and give each difference a row and a status. Every later fix should point at a row. When
your environment cannot reach the provider (a sandbox, an egress proxy), settle the unknowns
from the server's source with someone who has access, rather than guessing.

**Look at the server as it is**, not as the repository describes it: the reverse-proxy block,
the service unit (`systemctl show -p User -p WorkingDirectory <unit>`), the environment
variable *names* (cut values to four characters), and the release actually running. Both
migrations found a gap here: an API not on the host it was assumed to be on, a release months
older than the latest tag, a live secret in the repository.

## 2. Configuration

backendkit reads no environment variables; these are the names its documentation uses, and the
names the admin console's **Copy .env block** button produces (admin console v1.2.0 or later).
Name them as you like, but **compare names, never paste a generated block over an existing file**:
the block leaves `SOCRATE_CLIENT_SECRET` empty when the console no longer knows the secret, and
pasting it would erase the real one.

| Variable | Example | Notes |
|---|---|---|
| `SOCRATE_ISSUER` | `https://socrate.example.com` | No trailing slash. `jwtauth` checks `iss` against it. |
| `SOCRATE_BASE_URL` | `https://socrate.example.com` | The OAuth port, public. Usually equal to the issuer. |
| `SOCRATE_JWKS_URL` | `https://socrate.example.com/.well-known/jwks.json` | |
| `SOCRATE_ADMIN_BASE_URL` | `http://127.0.0.1:18082` | **Required, never derived** (§3.4). |
| `SOCRATE_CLIENT_ID` | | Also the expected audience. |
| `SOCRATE_CLIENT_SECRET` | | On the server only. A secret ever committed is presumed live: rotate it and replace it on the server in the same step. |
| `SOCRATE_APP_ID` | `3` | **Required** for service-account calls (§3.2). |

Make the application's own environment switch (`APP_ENV` or similar) **required, with no
default outside tests**. In one migration the code read `ENV` while the server set `APP_ENV`, and
every production-only check was silently off. Delete stale local env files from build
checkouts: Vite loads a git-ignored `.env.production.local` in production builds.

## 3. Rules

Each rule is a symptom we saw, its cause, and what to do.

### 3.1 Check the audience; read the role of *this* app

*Symptom:* an administrator of another application was an administrator in yours.
*Cause:* all applications on one Socrate share its signing keys, so a token issued to app X
validates in app Y unless the audience is checked. Its `role` claim is the user's role **in the
app the token was issued for**.

- Always pass `jwtauth.WithAudience(clientID)`. It is opt-in in backendkit v1 for compatibility;
  without it, `role` (and `httpware.RBAC`, which reads it) can belong to another application.
- One API serving several of your applications (a portal plus service accounts) passes
  `jwtauth.WithAudiences(id1, id2, …)` (backendkit v1.18.0): the token's `aud` must contain one of
  them, and `role` belongs to that one. Read `ctxutil.GetAppRole(ctx, clientID)` when the
  applications' roles differ; it is `""` for a Socrate admin and for a service account, so handle
  those two explicitly. Never fall back to no audience check to make a second client work.
- `app_roles` maps every app's client ID to the user's role in it; `ctxutil.GetAppRole(ctx,
  clientID)` reads yours. Socrate admins and superadmins never appear in `app_roles`: they get
  `role: "admin"` on every application through their global role.

### 3.2 Configure the app ID

*Symptom:* every call the application makes as itself (invitations, sign-up, magic-link
e-mails, policy decisions) fails with `401` or "AppID must be set in ClientConfig".
*Cause:* a service-account token cannot look its own app ID up: `GET /api/admin/apps` is for
human administrators. Set `ClientConfig.AppID` (the number, not the client ID).

### 3.3 Service tokens only work on `/api/apps/{id}/service/*`

*Symptom:* sign-up answers `500`; names silently missing from team lists.
*Cause:* the `/api/apps/{id}/users…` routes need an app administrator's **user** token and answer
a service token with `401`. backendkit v1.15.1 moved `RegisterUser` and `GetUserAsService` to
the service routes; `GetUserAsService` needs Socrate v1.6.0.

| As the application itself (service token) | As the signed-in user (their token) |
|---|---|
| `InviteUserAsService`, `RegisterUser`, `GetUserAsService`, `SendMagicLink`, `Decide` | `ListUsers`, `GetUser`, `CreateUser`, `UpdateUserRole`, `DeleteUser`, … (§6.4 of the guide) |

When an admin call fails with `401`, first check which token that route accepts. Fix the
library, not the application.

### 3.4 The admin API is loopback-only

*Symptom:* invitations, sign-up and magic-link e-mails fail; sign-in works.
*Cause:* the admin API listens on the Socrate host's loopback only. The value `socrate.Client`
derives when `AdminBaseURL` is empty (the public host on port 8081) is wrong behind a TLS proxy.

- Set `AdminBaseURL` explicitly. On the Socrate host itself: `http://127.0.0.1:8082`. On a
  separate applications host: the local end of the shared SSH tunnel, `http://127.0.0.1:18082`
  (`systemctl status socrate-admin-tunnel`).
- When the tunnel is down, everything the application does as itself fails; user sign-in, which
  uses the public OAuth port, keeps working.

### 3.5 Tell Socrate who the user is, from one trusted hop

Socrate rate-limits, blocks and audits by client address. Resolve the browser's address in your
API (trust `X-Forwarded-For` only from your own reverse proxy, e.g. a loopback peer, and take the
rightmost entry that is not that proxy), and hand it to backendkit with
`socrate.WithClientAttribution` / `bff.WithClientAttribution`. Never forward the browser's own
`X-Forwarded-For` or `X-Real-IP`: `bff.NewSingleHostProxy` strips them.

### 3.6 Magic links open your page, which posts to your BFF

*Symptom:* the magic-link e-mail opens a `405`, or `SendMagicLink` answers `409`.
*Cause:* before Socrate v1.6.0 the e-mail linked to a POST-only endpoint. Since v1.6.0 each
application registers its own landing page, `magic_link_url`, in the admin console (application
page, "Magic-link page"); without it Socrate refuses to send (`409`).

The landing page lives on your SPA, on the same origin as one of the app's redirect URIs. It
posts the token to **your BFF**, which redeems it with `client.VerifyMagicLink` and creates the
session: see §7.5 of the guide. Refuse any provider-hosted page that would redeem the link and
hand tokens to the browser.

### 3.7 Keep tokens on the server

Use the `bff` package (§7.1 of the guide): the browser holds an HttpOnly `__Host-` cookie and a
CSRF token in memory; the SPA has no Socrate setting and no token code. Keep a test that fails if
token code comes back (Ascenda's `noBrowserTokens.spec.ts`). `bff.MemoryStore` loses its
sessions on restart, which signs everyone out. To keep them across deploys, or to run several
instances, use `bff.NewPostgresStore` (backendkit v1.17.0): it stores the sessions encrypted in a
table of a database you already run, under a 32-byte key kept with the BFF's other secrets
(README, `bff` section).

### 3.8 Accounts live in Socrate: sign-up, profile edits, avatars

An application that managed its own users (its own password column, its own profile and avatar
fields) hands that to Socrate. The account, password included, is shared by every application on
the instance, so the application never sets a password or an e-mail address, and keeps in its own
tables only what is specific to it, keyed by `sub`.

| What the application used to do | With Socrate | Needs |
|---|---|---|
| Sign-up form with a password | `client.Signup`: the user's own password, member of this app as `user`; Socrate sends the verification e-mail. `ErrUserAlreadyExists` means the address already has a Socrate account (perhaps from another app): ask the user to sign in, then add them with `RegisterUser` | backendkit v1.17.0 |
| An administrator creates an account | `RegisterUser` or `InviteUserAsService`: Socrate e-mails the user an invitation | v1.15.1 |
| The user edits their profile | `UpdateProfile` with the user's token (name, phone, company, …, `AvatarURL`) | v1.17.0 / Socrate v1.7.0 for the avatar |
| The application edits a member's profile (an admin screen, an import) | `UpdateUserAsService` (profile fields only; e-mail, password and roles are refused). `ErrUserNotInApp` for a user outside this app, `ErrInvalidProfileUpdate` for a refused value | v1.17.0 / Socrate v1.7.0 |
| An avatar | Socrate stores a URL (`https`, no credentials, at most 2048 characters), not the image: host the file yourself and save its URL with `AvatarURL`; `""` clears it. It comes back as `FullProfile.AvatarURL`, `User.AvatarURL` and the OIDC `picture` claim (`ProfileInfo.Picture`) | v1.17.0 / Socrate v1.7.0 |
| "E-mail verified" | `ProfileInfo.EmailVerified` from the user's profile, never from the token | v1.17.0 |
| Password change or reset | Socrate's own pages (*Forgot password?*), or `ForcePasswordReset` for an administrator | |

Link a legacy account to a Socrate one by e-mail only when the profile says the e-mail is
verified. When the users were carried over with their IDs (§1), `sub` already equals the legacy
user ID and nothing needs linking.

## 4. The cut-over

The sequence that kept every pull request deployable on its own:

1. **Phase 1.** Every Socrate call goes through backendkit (`jwtauth`, `socrate.Client`, `bff`):
   no hand-written OAuth or admin requests. Audience check on, app ID and admin URL configured,
   client attribution.
2. **BFF, additive.** `/bff/*` routes next to the old ones; the old SPA still works.
3. **SPA switched to the BFF;** its token code deleted, with the no-token test.
4. **Old token routes removed** from the API.

Each step is its own release, **but the deploy of steps 3 and 4 is not independent**: deploy the
API, then the SPA, in one window. With the new API and the old SPA, sign-in fails with
*"Request failed with status code 404"*.

Before deploying the API that uses it, **register the BFF's redirect URI** on the application
(compared exactly: scheme, host, path, no trailing slash), and the magic-link page. After the
cut-over, sign in from a **fresh private window** (an old tab still runs the old flow), then
remove the old redirect URI so stale code fails with a clear error.

Back up first: the database, the env file, the reverse-proxy configuration and the old web app.
Keep the env file valid for the old release until the new one is confirmed. Route `/bff/*` and
`/api/*` to `127.0.0.1:<port>`, not `localhost` (which may resolve to `::1`).

## 5. Checklist

Before code:
- [ ] Issuer, client ID, numeric app ID, admin address and secret from the operator; user IDs
      carried over?
- [ ] Dated, read-only compatibility report.
- [ ] The server as it is: proxy block, service unit, env names, running release.
- [ ] Every provider URL in the env file compared with Socrate's discovery document.

Code (one pull request each):
- [ ] All Socrate calls through backendkit ≥ v1.15.1 (≥ v1.17.0 for §3.8 and `PostgresStore`).
- [ ] `jwtauth.WithAudience(clientID)`; roles from this app.
- [ ] `AppID` and `AdminBaseURL` required in production, never derived.
- [ ] Service-account calls only on `/service/*` routes.
- [ ] Client attribution from a trusted hop.
- [ ] BFF additive → SPA switch with a no-token test → old routes removed.
- [ ] Magic-link landing page on the SPA, redeemed through the BFF.
- [ ] No password or e-mail written by the application: sign-up, profile and avatar through
      Socrate (§3.8); the old password column dropped once the cut-over is confirmed.
- [ ] Sessions that must survive a deploy: `bff.NewPostgresStore`, its key in the server's env file.
- [ ] The environment switch required; accounts linked by e-mail only on a verified e-mail from
      the profile, never from the token.

Cut-over:
- [ ] Redirect URI and magic-link page registered on the application.
- [ ] Backups taken; env names compared, existing secret kept.
- [ ] API, then SPA; check both running versions.
- [ ] Fresh private window: sign-in, magic link, sign-up, invitation, team list.
- [ ] Old redirect URI removed; CORS origins trimmed.

## 6. Symptom index

| Symptom | Cause | See |
|---|---|---|
| Socrate: *redirect_uri is not registered for this client* | BFF callback not registered, or not an exact match | §4 |
| *Request failed with status code 404* after sign-in | new API with the old SPA | §4 |
| Lands on an old route (`/landing?code=…&state=…`) after Socrate | a tab opened before the deploy | §4 |
| Socrate: *Invalid email or password* | the account on **this** instance: exists, verified, unlocked, member of the app? Then *Forgot password?* | §1 |
| Sign-up answers `500`; names missing in team lists | service token on a user-token route | §3.3 |
| Every service-account call `401` | app ID not configured | §3.2 |
| Magic-link e-mail opens a `405` | Socrate before v1.6.0 | §3.6 |
| `SendMagicLink` answers `409` | no magic-link page registered | §3.6 |
| Invitations and magic-link e-mails fail, sign-in works | admin API unreachable (tunnel down) | §3.4 |
| An admin of another app is an admin here | no audience check | §3.1 |
| Everyone signed out after a deploy | in-memory BFF sessions; use `bff.NewPostgresStore` | §3.7 |
| `UpdateUserAsService`: *needs Socrate v1.7.0 or later* | Socrate older than v1.7.0 | §3.8 |
| `Signup` answers `ErrUserAlreadyExists` for a new user of this app | the address has a Socrate account from another app | §3.8 |
| Avatar refused (`ErrInvalidProfileUpdate`, *invalid avatar_url*) | not `https`, too long, or carries credentials | §3.8 |
| `curl -I /bff/login` shows no `Location` | `-I` sends `HEAD`; probe with `curl -s -o /dev/null -D - …` | |
