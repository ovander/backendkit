package bff

import (
	"net/url"
	"strings"
)

// SanitizeReturnTo validates a post-login "return to" target and returns a safe
// same-origin path, falling back to "/" for anything suspicious.
//
// It defends against open redirects, including the backslash variant that a
// naive HasPrefix("//") check misses: browsers normalise "\" to "/", so
// "/\evil.com" (and "/\/evil.com") would otherwise become the
// protocol-relative "//evil.com". The rules: the value must be a non-empty,
// control-character-free, root-relative path ("/..."), must not begin the
// authority ("//" or "/\"), must contain no backslashes anywhere, and must
// parse to a URL with no scheme and no host.
func SanitizeReturnTo(p string) string {
	if p == "" || p[0] != '/' {
		return "/"
	}
	// Reject authority-introducing prefixes and any backslash (browsers fold
	// "\" into "/", turning "/\host" into protocol-relative "//host").
	if strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.ContainsRune(p, '\\') {
		return "/"
	}
	// Reject control characters (incl. NUL, CR, LF, TAB) that could be used for
	// header or normalisation tricks.
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	// Parse-and-validate: a legitimate same-origin target has no scheme/host.
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return p
}
