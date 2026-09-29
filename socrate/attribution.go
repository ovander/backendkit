package socrate

// attribution.go — opt-in client attribution for OAuth calls a server makes on
// a browser's behalf. A Backend-for-Frontend calls /oauth/token and
// /oauth/revoke server-to-server, usually over loopback, so without this
// Socrate audits those events as the BFF (127.0.0.1, Go-http-client/1.1)
// rather than as the browser that caused them.

import (
	"context"
	"net"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxAttributedUserAgentBytes caps the User-Agent sent by ApplyClientAttribution.
const maxAttributedUserAgentBytes = 512

// ClientAttribution identifies the end user's browser on whose behalf a server
// calls Socrate. IP is the browser's address as the caller resolved it with its
// own trusted-proxy rules; UserAgent is the browser's User-Agent. Either may be
// empty, in which case that part is not sent.
type ClientAttribution struct {
	IP        string
	UserAgent string
}

// clientAttributionKey is the unexported context key for a ClientAttribution.
type clientAttributionKey struct{}

// WithClientAttribution returns a copy of ctx carrying a. The Client methods
// that call Socrate on a user's behalf (ExchangeCode, RefreshToken,
// RevokeToken, VerifyMagicLink, AdminLogin, Logout) then tell Socrate who the
// browser is, through ApplyClientAttribution.
//
// The caller MUST pass the browser address it resolved itself, with its own
// trusted-proxy rules (for example: honour X-Forwarded-For only when the peer
// is the local edge proxy, else use RemoteAddr). Never pass a raw request
// header such as X-Forwarded-For or X-Real-IP: Socrate trusts what the BFF
// sends from loopback, so a browser-controlled value here would let the
// browser choose the address Socrate rate-limits, blocks and audits it as.
// backendkit deliberately does not resolve client IPs itself.
func WithClientAttribution(ctx context.Context, a ClientAttribution) context.Context {
	return context.WithValue(ctx, clientAttributionKey{}, a)
}

// ClientAttributionFrom returns the ClientAttribution carried by ctx, and
// whether there was one.
func ClientAttributionFrom(ctx context.Context) (ClientAttribution, bool) {
	a, ok := ctx.Value(clientAttributionKey{}).(ClientAttribution)
	return a, ok
}

// ApplyClientAttribution sets the attribution headers on req from the
// ClientAttribution in req's context. It is called by the Client methods that
// act on a user's behalf; a BFF that builds its own token or revoke requests
// can call it too, after setting the request's context.
//
// With a non-empty IP that parses as an IP address, X-Forwarded-For is SET to
// exactly that one address (canonical form), replacing any existing value, and
// X-Real-IP is removed. It is replaced and never appended because Socrate, for
// a connection from a trusted proxy, takes the LEFTMOST X-Forwarded-For entry
// as the client: appending to a browser-supplied value would leave the
// browser's own claim leftmost and let it choose its logged address. An IP that
// does not parse sets nothing.
//
// With a non-empty UserAgent, User-Agent is set to it with invalid UTF-8 and
// control characters removed, truncated on a character boundary to 512 bytes.
//
// Without attribution in the context the request is left untouched.
func ApplyClientAttribution(req *http.Request) {
	if req == nil {
		return
	}
	a, ok := ClientAttributionFrom(req.Context())
	if !ok {
		return
	}
	if ip := net.ParseIP(strings.TrimSpace(a.IP)); ip != nil {
		req.Header.Set("X-Forwarded-For", ip.String())
		req.Header.Del("X-Real-IP")
	}
	if ua := sanitizeUserAgent(a.UserAgent); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
}

// sanitizeUserAgent drops invalid UTF-8 and control characters (which would
// otherwise make the transport reject the header, or smuggle line breaks into
// Socrate's logs) and truncates to maxAttributedUserAgentBytes without
// splitting a multi-byte character.
func sanitizeUserAgent(ua string) string {
	ua = strings.ToValidUTF8(ua, "")
	var b strings.Builder
	for _, r := range ua {
		if unicode.IsControl(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxAttributedUserAgentBytes {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
