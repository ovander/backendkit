package conformance

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	reDecimal = regexp.MustCompile(`^[0-9]+$`)
	reAppSub  = regexp.MustCompile(`^app:[0-9]+$`)
	reUUID    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reB64URL  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	reJWS     = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	reEmail   = regexp.MustCompile(`^[^@\s]+@[^@\s]+$`)
)

// Match checks got — a token's claims, a response body, a document — against
// the fixture: the same keys, none missing and none extra, every literal value
// equal, and every placeholder satisfied by its rule (a UUID jti, a numeric
// sub, an integer exp after iat, …). A placeholder whose Params field is set
// must equal it exactly; <ns> keys use Params.ClaimsNamespace or the default.
// got may be any value that marshals to a JSON object (jwt.MapClaims, a
// struct, a map). The error lists every difference found.
func Match(name string, got any, p Params) error {
	want, err := parse(name)
	if err != nil {
		return err
	}
	b, err := json.Marshal(got)
	if err != nil {
		return fmt.Errorf("conformance: marshal the document: %w", err)
	}
	var doc any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("conformance: decode the document: %w", err)
	}
	m := &matcher{p: p}
	if name == "jwks" {
		m.jwks = true
	}
	m.match("", want, doc)
	if len(m.errs) > 0 {
		return fmt.Errorf("conformance: %s: %w", name, errors.Join(m.errs...))
	}
	return nil
}

type matcher struct {
	p    Params
	jwks bool
	errs []error
}

func (m *matcher) fail(path, format string, args ...any) {
	if path == "" {
		path = "(document)"
	}
	m.errs = append(m.errs, fmt.Errorf("%s: %s", path, fmt.Sprintf(format, args...)))
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func (m *matcher) ns() string { return or(m.p.ClaimsNamespace, DefaultClaimsNamespace) }

func (m *matcher) match(path string, want, got any) {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			m.fail(path, "want an object, got %s", describe(got))
			return
		}
		m.matchObject(path, w, g)
	case []any:
		g, ok := got.([]any)
		if !ok {
			m.fail(path, "want an array, got %s", describe(got))
			return
		}
		m.matchArray(path, w, g)
	case string:
		if kind, arg, ok := placeholder(w); ok {
			m.rule(path, kind, arg, got)
			return
		}
		g, ok := got.(string)
		if !ok {
			m.fail(path, "want the string %q, got %s", w, describe(got))
			return
		}
		if strings.Contains(w, issuerToken) {
			rest := strings.SplitN(w, issuerToken, 2)
			if m.p.Issuer != "" {
				w = strings.ReplaceAll(w, issuerToken, m.p.Issuer)
			} else if strings.HasPrefix(g, rest[0]) && strings.HasSuffix(g, rest[1]) && len(g) > len(rest[0])+len(rest[1]) {
				return
			}
		}
		if g != w {
			m.fail(path, "want %q, got %q", w, g)
		}
	case bool:
		if g, ok := got.(bool); !ok || g != w {
			m.fail(path, "want %v, got %s", w, describe(got))
		}
	case float64:
		g, ok := number(got)
		if !ok || g != w {
			m.fail(path, "want %v, got %s", w, describe(got))
		}
	case nil:
		if got != nil {
			m.fail(path, "want null, got %s", describe(got))
		}
	}
}

func (m *matcher) matchObject(path string, w, g map[string]any) {
	expected := make(map[string]any, len(w))
	for k, v := range w {
		expected[strings.ReplaceAll(k, nsToken, m.ns())] = v
	}
	for _, k := range sortedKeys(expected) {
		gv, ok := g[k]
		if !ok {
			m.fail(join(path, k), "missing")
			continue
		}
		m.match(join(path, k), expected[k], gv)
	}
	for _, k := range sortedKeys(g) {
		if _, ok := expected[k]; !ok {
			m.fail(join(path, k), "not in the fixture (value %s)", describe(g[k]))
		}
	}
	// Time ordering: a token expires after it is issued.
	if iat, ok := number(g["iat"]); ok {
		if exp, ok := number(g["exp"]); ok && exp <= iat {
			m.fail(join(path, "exp"), "exp %v is not after iat %v", exp, iat)
		}
	}
}

func (m *matcher) matchArray(path string, w, g []any) {
	// The jwks fixture holds one key template that every published key matches.
	if m.jwks && path == "keys" && len(w) == 1 {
		if len(g) == 0 {
			m.fail(path, "no key")
		}
		for i, el := range g {
			m.match(fmt.Sprintf("%s[%d]", path, i), w[0], el)
		}
		return
	}
	// <audience> stands for the registered audiences, after the fixed entries.
	for i, el := range w {
		if el != "<audience>" {
			continue
		}
		if i != len(w)-1 {
			m.fail(path, "fixture error: <audience> must be the last entry")
			return
		}
		if len(g) < i+1 {
			m.fail(path, "want %d fixed entries followed by the registered audiences, got %s", i, describe(g))
			return
		}
		for j := 0; j < i; j++ {
			m.match(fmt.Sprintf("%s[%d]", path, j), w[j], g[j])
		}
		rest := g[i:]
		if len(m.p.Audiences) > 0 {
			if len(rest) != len(m.p.Audiences) {
				m.fail(path, "want the audiences %q after the fixed entries, got %s", m.p.Audiences, describe(rest))
				return
			}
			for j, a := range m.p.Audiences {
				if s, _ := rest[j].(string); s != a {
					m.fail(fmt.Sprintf("%s[%d]", path, i+j), "want %q, got %s", a, describe(rest[j]))
				}
			}
			return
		}
		for j, el := range rest {
			if s, ok := el.(string); !ok || s == "" {
				m.fail(fmt.Sprintf("%s[%d]", path, i+j), "want an audience string, got %s", describe(el))
			}
		}
		return
	}
	if len(g) != len(w) {
		m.fail(path, "want %d entries, got %d: %s", len(w), len(g), describe(g))
		return
	}
	for i := range w {
		m.match(fmt.Sprintf("%s[%d]", path, i), w[i], g[i])
	}
}

// rule checks got against the placeholder <kind:arg>.
func (m *matcher) rule(path, kind, arg string, got any) {
	p := m.p
	str := func(re *regexp.Regexp, desc, exact string) {
		s, ok := got.(string)
		switch {
		case !ok:
			m.fail(path, "want %s, got %s", desc, describe(got))
		case exact != "" && s != exact:
			m.fail(path, "want %q, got %q", exact, s)
		case exact == "" && re != nil && !re.MatchString(s):
			m.fail(path, "want %s, got %q", desc, s)
		case exact == "" && re == nil && s == "":
			m.fail(path, "want %s, got an empty string", desc)
		}
	}
	integer := func(min float64) {
		n, ok := number(got)
		if !ok || n != math.Trunc(n) || n < min {
			m.fail(path, "want an integer of at least %v, got %s", min, describe(got))
		}
	}
	switch kind {
	case "issuer":
		str(nil, "the issuer", p.Issuer)
	case "client_id":
		str(nil, "a client_id", p.ClientID)
	case "sub":
		str(reDecimal, "a numeric user id as a decimal string", p.Subject)
	case "app_sub":
		exact := ""
		if p.AppID != 0 {
			exact = fmt.Sprintf("app:%d", p.AppID)
		}
		str(reAppSub, `"app:<numeric id>"`, exact)
	case "role":
		str(nil, "a role", p.Role)
	case "email":
		str(reEmail, "an email address", p.Email)
	case "name":
		str(nil, "a name", p.Name)
	case "nonce":
		str(nil, "the nonce", p.Nonce)
	case "tenant_id":
		str(reUUID, "a UUID", p.TenantID)
	case "jti", "kid":
		str(reUUID, "a UUID", "")
	case "at_hash", "n":
		str(reB64URL, "a base64url string", "")
	case "jkt":
		if p.JKT != "" {
			str(nil, "the JWK thumbprint", p.JKT)
		} else if s, ok := got.(string); !ok || len(s) != 43 || !reB64URL.MatchString(s) {
			m.fail(path, "want a base64url SHA-256 thumbprint (43 characters), got %s", describe(got))
		}
	case "access_token", "refresh_token", "id_token":
		exact := map[string]string{"access_token": p.AccessToken, "refresh_token": p.RefreshToken, "id_token": p.IDToken}[kind]
		// Never echo a token into an error message.
		if s, ok := got.(string); !ok || !reJWS.MatchString(s) {
			m.fail(path, "want a compact JWS (header.payload.signature)")
		} else if exact != "" && s != exact {
			m.fail(path, "not the token given in Params")
		}
	case "scope":
		str(nil, "a scope", or(p.Scope, arg))
	case "attribute":
		if got == nil {
			m.fail(path, "want the attribute %q, got null", arg)
		} else if v, ok := p.Attributes[arg]; ok && !sameJSON(v, got) {
			m.fail(path, "want %s, got %s", describe(v), describe(got))
		}
	case "iat", "nbf", "auth_time", "exp", "refresh_exp":
		integer(1)
	case "expires_in":
		integer(1)
	case "token_version":
		if p.TokenVersion > 0 {
			if n, ok := number(got); !ok || n != float64(p.TokenVersion) {
				m.fail(path, "want %d, got %s", p.TokenVersion, describe(got))
			}
			return
		}
		integer(1)
	case "app_roles":
		obj, ok := got.(map[string]any)
		if !ok || len(obj) == 0 {
			m.fail(path, "want an object of client_id → role, got %s", describe(got))
			return
		}
		for _, k := range sortedKeys(obj) {
			if s, ok := obj[k].(string); !ok || s == "" {
				m.fail(join(path, k), "want a role, got %s", describe(obj[k]))
			}
		}
		if p.ClientID != "" {
			role, ok := obj[p.ClientID]
			switch {
			case !ok:
				m.fail(path, "no entry for the client %q", p.ClientID)
			case p.Role != "" && role != p.Role:
				m.fail(join(path, p.ClientID), "want %q, got %s", p.Role, describe(role))
			}
		}
	default:
		m.fail(path, "fixture error: unknown placeholder <%s>", kind)
	}
}

// number reads a JSON number (json.Number or float64) as a float64.
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(string(n), 64)
		return f, err == nil
	case float64:
		return n, true
	}
	return 0, false
}

func sameJSON(a, b any) bool {
	norm := func(v any) any {
		raw, err := json.Marshal(v)
		if err != nil {
			return v
		}
		var out any
		_ = json.Unmarshal(raw, &out)
		return out
	}
	return reflect.DeepEqual(norm(a), norm(b))
}

func describe(v any) string {
	if v == nil {
		return "null"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	s := string(raw)
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
