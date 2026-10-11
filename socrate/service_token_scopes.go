package socrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrScopeNotGranted is returned (wrapped) by ServiceTokenWithScopes when
// Socrate does not grant every requested scope: either it refuses the request
// with invalid_scope (the error then also wraps the *OAuthError), or the
// token response's scope field lacks one of them. Test it with errors.Is.
var ErrScopeNotGranted = errors.New("socrate: scope not granted")

// maxScopedServiceTokens bounds how many distinct scope sets
// ServiceTokenWithScopes caches; the least recently used set is evicted
// beyond it.
const maxScopedServiceTokens = 16

// scopedServiceToken is the cache entry of one scope set. mu is held during
// an exchange, so concurrent callers for the same set share it; lastUsed is
// guarded by Client.scopedMu.
type scopedServiceToken struct {
	mu       sync.Mutex
	token    string
	expiry   time.Time
	lastUsed uint64
}

// ServiceTokenWithScopes returns a service-account access token (the
// client_credentials grant, sub=app:{id}) requested with the given scopes, and
// the time it really expires, as ServiceToken does. Use it to call a service
// that requires a scope of its own, for example a worker API behind
// jwtauth.RequireScopes("swingdrift:worker"): register the scope in the
// client's allowed_scopes in Socrate (application-defined <namespace>:<name>
// scopes need Socrate v1.14.0 or later), then request it here. Socrate issues
// exactly the requested scopes, without its default api, so list api too when
// the token must also carry it.
//
// The token is cached per scope set (order and duplicates do not matter:
// ("a", "b") and ("b", "a", "a") share one token) and exchanged again only when
// it is missing or expires within 30 s; concurrent callers for the same set
// share one exchange. At most 16 sets are cached; beyond that the least
// recently used one is dropped (and exchanged again when next asked for).
// This cache is separate from ServiceToken's, which keeps the scope-less token
// of the client's own service-account calls; InvalidateServiceToken clears
// both.
//
// It fails closed, without a network call, when no scope is given (use
// ServiceToken for the default scope), when a scope is not an RFC 6749 §3.3
// scope-token (non-empty, printable ASCII without space, '"' or '\'), or when
// ClientSecret is not set. A refusal by Socrate is an *OAuthError (errors.As);
// invalid_scope (a scope the client does not register) also matches
// ErrScopeNotGranted, as does a response whose scope field lacks a requested
// scope (a response without a scope field means the requested scopes were
// granted, RFC 6749 §5.1). The token is never logged or put in an error.
func (c *Client) ServiceTokenWithScopes(ctx context.Context, scopes ...string) (token string, expiresAt time.Time, err error) {
	set, err := normaliseScopes(scopes)
	if err != nil {
		return "", time.Time{}, err
	}
	if c.clientSecret == "" {
		return "", time.Time{}, errors.New("socrate: client_secret required for service-account token exchange")
	}
	scope := strings.Join(set, " ")

	e := c.scopedEntry(scope)
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.token != "" && time.Now().Add(serviceTokenRenewBefore).Before(e.expiry) {
		return e.token, e.expiry, nil
	}

	tr, expiry, err := c.exchangeClientCredentials(ctx, scope, func(status int, body []byte) error {
		oe := newOAuthError(status, body)
		if oe.Code == "invalid_scope" {
			return fmt.Errorf("%w: %w", ErrScopeNotGranted, oe)
		}
		return oe
	})
	if err != nil {
		return "", time.Time{}, err
	}
	if len(tr.Scope) > 0 && string(tr.Scope) != "null" {
		var grantedScope string
		if err := json.Unmarshal(tr.Scope, &grantedScope); err != nil {
			return "", time.Time{}, fmt.Errorf("%w: the token response's scope is not a string", ErrScopeNotGranted)
		}
		granted := strings.Fields(grantedScope)
		var missing []string
		for _, s := range set {
			if !slices.Contains(granted, s) {
				missing = append(missing, s)
			}
		}
		if len(missing) > 0 {
			return "", time.Time{}, fmt.Errorf("%w: the token response lacks %q (granted %q)",
				ErrScopeNotGranted, strings.Join(missing, " "), grantedScope)
		}
	}
	e.token, e.expiry = tr.AccessToken, expiry
	return e.token, e.expiry, nil
}

// scopedEntry returns the cache entry for the normalised scope set key,
// creating it (and evicting the least recently used entry beyond
// maxScopedServiceTokens) when needed, and marks it as used.
func (c *Client) scopedEntry(key string) *scopedServiceToken {
	c.scopedMu.Lock()
	defer c.scopedMu.Unlock()

	c.scopedTick++
	if e, ok := c.scoped[key]; ok {
		e.lastUsed = c.scopedTick
		return e
	}
	if c.scoped == nil {
		c.scoped = make(map[string]*scopedServiceToken)
	}
	if len(c.scoped) >= maxScopedServiceTokens {
		var oldest string
		var oldestTick uint64
		for k, e := range c.scoped {
			if oldest == "" || e.lastUsed < oldestTick {
				oldest, oldestTick = k, e.lastUsed
			}
		}
		// A caller still holding the evicted entry finishes with it; its
		// token is simply no longer cached.
		delete(c.scoped, oldest)
	}
	e := &scopedServiceToken{lastUsed: c.scopedTick}
	c.scoped[key] = e
	return e
}

// normaliseScopes validates scopes as RFC 6749 §3.3 scope-tokens and returns
// them deduplicated and sorted. It refuses an empty list.
func normaliseScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, errors.New("socrate: ServiceTokenWithScopes needs at least one scope (use ServiceToken for the default scope)")
	}
	set := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if !isScopeToken(s) {
			return nil, fmt.Errorf("socrate: invalid scope %q: not an RFC 6749 scope-token", s)
		}
		set = append(set, s)
	}
	slices.Sort(set)
	return slices.Compact(set), nil
}

// isScopeToken reports whether s is a non-empty RFC 6749 §3.3 scope-token:
// 1*( %x21 / %x23-5B / %x5D-7E ).
func isScopeToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch < 0x21 || ch > 0x7e || ch == '"' || ch == '\\' {
			return false
		}
	}
	return true
}
