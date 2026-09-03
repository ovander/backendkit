package bff

import (
	"net/http"
	"time"
)

// DefaultLoginBindingTTL bounds how long a pending login (the window between
// the /login redirect and the /callback) stays valid in the browser.
const DefaultLoginBindingTTL = 10 * time.Minute

// LoginBinding ties a pending OAuth login to the browser that started it.
//
// Without it, a BFF callback only checks that the state parameter exists
// server-side, so whichever browser presents "?code=…&state=…" first gets
// the session: an attacker can complete their own login, capture the
// callback URL instead of following it, and get a victim to open it — the
// victim's cookie is silently swapped for the attacker's session (login
// CSRF / account swap). The binding issues a random nonce in a short-lived
// cookie when the login starts and requires the same nonce back at the
// callback, so only the browser that began the flow can finish it.
//
// Usage:
//
//	// in /login, alongside creating the pending state:
//	nonce := lb.Begin(w)
//	pending.Nonce = nonce // store with the state, server-side
//
//	// in /callback, after resolving the pending state:
//	if !lb.Verify(w, r, pending.Nonce) { 400 }
//
// The cookie is HttpOnly, Secure (+ __Host- prefix) when Cookie.Secure is
// set, Path=/ and SameSite=Lax — Lax rather than Strict because the callback
// is a top-level navigation arriving from the authorization server, on which
// Strict cookies are not sent.
type LoginBinding struct {
	// Cookie names the binding cookie (e.g. Name: "admin_login"); MaxAge is
	// ignored in favour of TTL.
	Cookie CookieConfig
	// TTL overrides DefaultLoginBindingTTL; keep it aligned with the pending
	// state's own expiry.
	TTL time.Duration
}

func (b LoginBinding) ttl() time.Duration {
	if b.TTL > 0 {
		return b.TTL
	}
	return DefaultLoginBindingTTL
}

// Begin issues a fresh nonce to the browser and returns it for the caller to
// store alongside the pending login state.
func (b LoginBinding) Begin(w http.ResponseWriter) string {
	nonce := RandomToken(32)
	http.SetCookie(w, &http.Cookie{
		Name:     b.Cookie.CookieName(),
		Value:    nonce,
		Path:     "/",
		HttpOnly: true,
		Secure:   b.Cookie.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(b.ttl().Seconds()),
	})
	return nonce
}

// Verify reports whether the browser presents the nonce that Begin issued
// for this pending login (constant-time compare) and always clears the
// binding cookie, so it is single-use either way. An empty want never
// matches.
func (b LoginBinding) Verify(w http.ResponseWriter, r *http.Request, want string) bool {
	b.clear(w)
	ck, err := r.Cookie(b.Cookie.CookieName())
	if err != nil || ck.Value == "" || want == "" {
		return false
	}
	return ConstantTimeEqual(ck.Value, want)
}

func (b LoginBinding) clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     b.Cookie.CookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   b.Cookie.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
