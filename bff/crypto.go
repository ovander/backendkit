package bff

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// RandomToken returns a cryptographically-random, URL-safe token carrying
// nBytes of entropy (before base64 expansion). It is the primitive behind
// session IDs, CSRF tokens, PKCE verifiers and OAuth state values, all of which
// want 32 bytes (256 bits). It panics only if the system CSPRNG fails, which is
// unrecoverable.
func RandomToken(nBytes int) string {
	if nBytes <= 0 {
		nBytes = 32
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("bff: crypto/rand failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// PKCE holds a PKCE code pair: the secret Verifier kept server-side for the
// token exchange and the Challenge sent on the /oauth/authorize redirect.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a fresh S256 PKCE pair. Socrate rejects the "plain" method,
// so only S256 is produced.
func NewPKCE() PKCE {
	v := RandomToken(32)
	return PKCE{Verifier: v, Challenge: S256Challenge(v)}
}

// S256Challenge computes the RFC 7636 S256 code challenge for a verifier:
// BASE64URL(SHA256(verifier)), no padding.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ConstantTimeEqual reports whether a and b are equal without leaking timing
// information about where they first differ. Use it for CSRF and other
// secret-token comparisons.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
