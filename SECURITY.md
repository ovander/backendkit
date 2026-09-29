# Security policy

backendkit sits on the authentication path of every service that uses it: JWT verification,
server-side sessions, CSRF protection and policy enforcement. Security reports are welcome and
handled first.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**: the repository's **Security** tab →
**Report a vulnerability**. Do not open a public issue or pull request for a vulnerability.

Include what you found, how to reproduce it, and the versions you tested
(`go list -m github.com/ovander/backendkit` and `go version`).

You will get an acknowledgement within a week. Fixes are released as a patch version as soon as
they are ready, and the report is credited in the release notes unless you prefer otherwise.

## Scope

- In scope: the packages in this repository, in particular `jwtauth` (token verification and
  JWKS handling), `bff` (sessions, cookies, CSRF, PKCE, the session→bearer proxy), `pep`,
  `socrate` and `httpware`.
- Out of scope: the Socrate identity provider itself (`ovander/go-oauth2`, not public yet), flaws
  in an application's own code or configuration, and denial-of-service by volume.

## Supported versions

Only the latest `v1` minor release receives security fixes. Upgrading within `v1` is
backward-compatible.

## Past reviews

The library has been through internal security and architecture reviews. The controls they led
to include:

- **Token verification (`jwtauth`):** optional audience and revocation checks, a required `exp`
  with bounded clock-skew leeway, a 2048-bit minimum for JWKS keys, and a JWKS refetch that is
  coalesced, rate-limited and negatively cached so unknown key IDs cannot force a fetch per
  request.
- **Sessions (`bff`):** a fail-closed zero value, CSRF that never matches an empty token, token
  refresh coalesced per session and detached from the triggering request, login binding against
  login CSRF, and stripping of client-supplied IP-attribution headers.
- **Upstream calls (`socrate`, `aigateway`):** capped response reads and escaped path and query
  values.
- **Error and log output (`apierror`, `gormlogger`):** 5xx responses redacted, and SQL values
  kept out of logs with `WithSQLRedaction`.

Each fix is listed in [CHANGELOG.md](CHANGELOG.md) with the version that shipped it.
