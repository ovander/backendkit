package bff

import "net/http"

// CookieConfig describes how the session cookie is emitted.
type CookieConfig struct {
	// Name is the cookie name when Secure is false (dev). When Secure is true
	// the __Host- prefix is required and applied automatically, so the wire
	// name becomes "__Host-" + Name.
	Name string
	// Secure sets the Secure attribute and enables the __Host- prefix. It must
	// be true in production.
	Secure bool
	// MaxAge in seconds for the cookie. Server-side idle/absolute expiry is the
	// real bound; this is only the browser-side hint.
	MaxAge int
}

// CookieName returns the on-the-wire cookie name, applying the __Host- prefix
// when Secure. The __Host- prefix binds the cookie to the exact host, forbids
// Domain, and requires Secure + Path=/ — all of which we set.
func (c CookieConfig) CookieName() string {
	if c.Secure {
		return "__Host-" + c.Name
	}
	return c.Name
}

// SetSession writes the session cookie: HttpOnly, SameSite=Strict, Path=/, and
// Secure + __Host- in production.
func (c CookieConfig) SetSession(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   c.MaxAge,
	})
}

// ClearSession expires the session cookie.
func (c CookieConfig) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.CookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// SessionID reads the opaque session id from the request cookie.
func (c CookieConfig) SessionID(r *http.Request) (string, bool) {
	ck, err := r.Cookie(c.CookieName())
	if err != nil || ck.Value == "" {
		return "", false
	}
	return ck.Value, true
}
