// Package conformance holds the shapes Socrate really produces — the claim sets
// of its tokens, its token, userinfo and introspection responses, and its
// discovery and JWKS documents — as fixtures a consumer's Socrate mock loads
// instead of hand-writing claims, plus the helpers to sign Socrate-shaped
// tokens with a test key and to check a document against a fixture.
//
// A mock written from memory drifts from the server: a claim spelt
// differently, aud as a string instead of an array, a custom claim without
// its namespace. Such differences surface in production. The fixtures here are
// checked nightly against a Socrate built from ovander/go-oauth2 main (the
// Conformance workflow, live tests behind the conformance build tag), so a
// mock built on them fails in CI when the server changes, not after a deploy.
//
// # Fixtures
//
// [Names] lists them. Each is a JSON document whose volatile or
// deployment-specific values are placeholders:
//
//	access/authorization_code                access token, authorization-code grant (password sign-in)
//	access/authorization_code_mfa            the same after a TOTP or recovery code: amr ["pwd","otp","mfa"], acr "mfa"
//	access/refresh                           access token from the refresh_token grant (auth_time, amr, acr kept)
//	access/audience_dual                     user token, AUDIENCE_MODE=dual, client with a registered audience
//	access/custom_claims                     user token of a client with claim mappings (namespaced custom claims)
//	access/client_credentials                service-account token: sub "app:<id>", scope "api" by default
//	access/client_credentials_audience_dual  the same, AUDIENCE_MODE=dual, client with a registered audience
//	access/client_credentials_custom_claims  the same, client with claim mappings (app and literal sources only)
//	access/client_credentials_dpop           the same, requested with a DPoP proof: cnf.jkt
//	id_token/authorization_code              ID token (nonce echoed), and …_mfa, refresh (no nonce), custom_claims
//	refresh_token/authorization_code         refresh token (Socrate's are JWTs; treat them as opaque)
//	token_response/authorization_code        /oauth/token response, and …/refresh, …/client_credentials
//	userinfo                                 /oauth/userinfo response
//	introspection/access                     /oauth/introspect, active user token, and …/client_credentials, …/inactive
//	discovery                                /.well-known/openid-configuration with DPOP_MODE=off (the default)
//	discovery_dpop                           the same with DPoP enabled (dpop_signing_alg_values_supported)
//	jwks                                     /.well-known/jwks.json (one entry per signing key)
//	jose_header                              the JOSE header of every Socrate token
//
// Without a registered audience, or with AUDIENCE_MODE=off (the server default),
// aud is ["<client_id>"]: the plain fixtures. Socrate's audience mode, claim
// namespace and DPoP mode are server-wide settings; the fixtures name the one
// they assume.
//
// # Placeholders
//
// A string value that is a whole placeholder stands for one value; [Load]
// fills it from [Params] (or a default), and [Match] checks it by rule:
//
//	<issuer>          Params.Issuer — also inside strings: "<issuer>/oauth/token"
//	<client_id>       Params.ClientID
//	<audience>        in an array only: Params.Audiences, appended after the client_id
//	<sub>             Params.Subject: the user's numeric id as a decimal string
//	<app_sub>         "app:" + Params.AppID
//	<role>            Params.Role, the user's role in the client
//	<app_roles>       {client_id: role} — the user's role in every client they belong to
//	<email>, <name>   Params.Email, Params.Name
//	<nonce>           Params.Nonce, echoed from the authorization request
//	<tenant_id>       Params.TenantID (a UUID) — the value of a literal claim mapping
//	<attribute:K>     Params.Attributes[K] — a user attribute projected by a claim mapping
//	<scope:D>         Params.Scope, or D, the scope Socrate grants when none is asked for
//	<iat>, <nbf>      Params.Now, as seconds since the epoch
//	<auth_time>       Params.AuthTime (default Params.Now)
//	<exp>             Params.Now + Params.TTL; <refresh_exp>: + Params.RefreshTTL
//	<expires_in>      Params.TTL in seconds
//	<jti>, <kid>      a UUID (kid: the signing key's ID)
//	<token_version>   Params.TokenVersion
//	<at_hash>         the OIDC at_hash of Params.AccessToken (random without it)
//	<jkt>             Params.JKT, a JWK SHA-256 thumbprint
//	<access_token>, <refresh_token>, <id_token>   Params.AccessToken, …
//	<n>               the RSA modulus of each key in Params.Keys
//
// A key may contain <ns>, the claim namespace (Params.ClaimsNamespace, default
// "https://socrate/", Socrate's CLAIMS_NAMESPACE default): "<ns>tenant_id" is
// the claim "https://socrate/tenant_id".
//
// # Using the fixtures in a mock
//
//	key, _ := conformance.NewKey()
//	jwks, _ := conformance.JWKS(key)                       // serve at /.well-known/jwks.json
//	disc, _ := conformance.Discovery(srv.URL)              // serve at /.well-known/openid-configuration
//	tok, _ := conformance.Sign("access/authorization_code", conformance.Params{
//		Issuer: srv.URL, ClientID: "my-app", Subject: "42",
//	}, key)
//
// [Match] checks a document — a token's claims, a response body — against a
// fixture: same keys, nothing missing or extra, and every value equal to the
// fixture's or satisfying its placeholder's rule. A placeholder whose Params
// field is set must equal it exactly.
//
// # Live checks
//
// Behind the conformance build tag, this package's tests obtain the real
// documents from a running Socrate over raw HTTP (hosted sign-in and consent,
// TOTP enrolment, a DPoP proof) and Match every fixture against them; the jwtauth, socrate, bff
// and pep packages each test themselves against the same server. They read
// SOCRATE_ISSUER, SOCRATE_ADMIN_URL, SOCRATE_REDIRECT_URI, SOCRATE_AUDIENCE,
// SOCRATE_TENANT_ID, SOCRATE_USER_PASSWORD, SOCRATE_POLICY_MODE and, for each
// of the plain, dual and claims clients, SOCRATE_<PLAIN|DUAL|CLAIMS>_CLIENT_ID
// and _SECRET, and expect a server with AUDIENCE_MODE=dual and DPOP_MODE=observe.
// Every fixture is matched against the live server except discovery, which a
// unit test ties to the live-checked discovery_dpop.
// scripts/conformance-local.sh builds, starts and seeds a Socrate and runs
// them; the Conformance workflow does the same nightly.
package conformance
