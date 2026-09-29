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
- Out of scope: the Socrate identity provider itself (report those in
  [`ovander/go-oauth2`](https://github.com/ovander/go-oauth2)), flaws in an application's own
  code or configuration, and denial-of-service by volume.

## Supported versions

Only the latest `v1` minor release receives security fixes. Upgrading within `v1` is
backward-compatible.

## Past reviews

The library has been through internal security and architecture reviews. The fixes they led to
are listed in [`CHANGELOG.md`](CHANGELOG.md), with the finding IDs they close (`F-n`, `INV-n`).
