// Package bff provides the shared runtime plumbing for a Socrate
// Backend-for-Frontend (BFF): server-side sessions, cookie and CSRF handling,
// PKCE generation, a safe return-to sanitiser, and a fail-closed
// session→bearer reverse proxy.
//
// In a BFF architecture the browser never holds OAuth tokens. The BFF is the
// confidential OAuth client: it runs the Authorization-Code + PKCE flow
// server-side, keeps the tokens in a server-side [Session], and hands the
// browser only an opaque, HttpOnly session cookie. Every authenticated request
// the browser makes is same-origin and is proxied upstream with the bearer
// injected by the BFF.
//
// This package is the consolidation of the previously-duplicated BFF cores in
// the oauth2-admin and oauth2-monitoring consoles. The OAuth token calls
// themselves (code exchange, refresh, revoke) live in the sibling socrate
// package; a [TokenRefresher] here is satisfied by *socrate.Client, so a BFF
// wires the two together rather than re-implementing either.
//
// The defaults are deliberately safe: [Gateway.ProxyWithSession] is
// fail-closed (no valid session ⇒ 401, never a pass-through), the session
// cookie uses the __Host- prefix when Secure, CSRF uses a constant-time
// compare, and [SanitizeReturnTo] rejects backslash and control-character
// open-redirect vectors.
package bff
