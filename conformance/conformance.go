package conformance

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

//go:embed fixtures
var fixtureFS embed.FS

// Defaults Load uses for an unset Params field.
const (
	DefaultIssuer          = "https://socrate.example.com"
	DefaultClientID        = "my-app"
	DefaultAudience        = "https://api.example.com"
	DefaultSubject         = "42"
	DefaultAppID           = 7
	DefaultRole            = "user"
	DefaultEmail           = "user@example.com"
	DefaultName            = "Example User"
	DefaultTenantID        = "00000000-0000-4000-8000-000000000001"
	DefaultClaimsNamespace = "https://socrate/"
	DefaultTTL             = 15 * time.Minute
	DefaultRefreshTTL      = 7 * 24 * time.Hour
)

// Params fills a fixture's placeholders (Load, Sign) and, when set, pins them
// to exact values (Match). Every field is optional: Load falls back to the
// Default… constants (a random nonce, jti and jkt; time.Now), and Match checks
// an unset field by its placeholder's rule only.
type Params struct {
	Issuer    string   // <issuer>, without a trailing slash
	ClientID  string   // <client_id>
	Audiences []string // <audience>: the client's registered audiences (AUDIENCE_MODE=dual)
	Subject   string   // <sub>: the user's numeric id
	AppID     uint     // <app_sub> is "app:<AppID>"
	Role      string   // <role> and the client's entry in <app_roles>
	Email     string   // <email>
	Name      string   // <name>
	Scope     string   // <scope:…>; empty uses the fixture's default
	Nonce     string   // <nonce>
	TenantID  string   // <tenant_id>
	// Attributes holds the user attributes <attribute:K> projects; Load's
	// default is {"department": "engineering"}.
	Attributes      map[string]any
	ClaimsNamespace string // <ns>; default DefaultClaimsNamespace
	TokenVersion    int    // <token_version>; default 1
	JKT             string // <jkt>

	Now        time.Time     // <iat>, <nbf>; default time.Now()
	AuthTime   time.Time     // <auth_time>; default Now
	TTL        time.Duration // <exp> = Now+TTL, <expires_in>; default DefaultTTL
	RefreshTTL time.Duration // <refresh_exp> = Now+RefreshTTL; default DefaultRefreshTTL

	// AccessToken, RefreshToken and IDToken fill the token_response fixtures;
	// AccessToken also gives an ID token its real at_hash.
	AccessToken  string
	RefreshToken string
	IDToken      string

	// Keys fill the jwks fixture (one entry each) and <kid>.
	Keys []Key
}

// Key is an RSA signing key and the kid Socrate would publish it under.
type Key struct {
	ID      string
	Private *rsa.PrivateKey
}

// NewKey returns a fresh 2048-bit RSA key with a UUID kid, as Socrate's key
// ring generates them.
func NewKey() (Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Key{}, fmt.Errorf("conformance: generate key: %w", err)
	}
	return Key{ID: uuid.NewString(), Private: priv}, nil
}

// Names returns the name of every fixture, sorted, for example
// "access/authorization_code" or "discovery".
func Names() []string {
	var names []string
	_ = fs.WalkDir(fixtureFS, "fixtures", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(path, "fixtures/"), ".json"))
		}
		return nil
	})
	sort.Strings(names)
	return names
}

// Raw returns the fixture's JSON with its placeholders unresolved.
func Raw(name string) ([]byte, error) {
	if name == "" || strings.Contains(name, "..") {
		return nil, fmt.Errorf("conformance: unknown fixture %q", name)
	}
	b, err := fixtureFS.ReadFile("fixtures/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("conformance: unknown fixture %q", name)
	}
	return b, nil
}

func parse(name string) (map[string]any, error) {
	b, err := Raw(name)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("conformance: fixture %s: %w", name, err)
	}
	return doc, nil
}

// Load returns the fixture with every placeholder resolved from p. The result
// is a fresh map the caller may change, e.g. to add a claim of its own.
func Load(name string, p Params) (map[string]any, error) {
	doc, err := parse(name)
	if err != nil {
		return nil, err
	}
	r := newResolver(p)
	var out any
	if name == "jwks" {
		out, err = r.resolveJWKS(doc)
	} else {
		out, err = r.resolve(doc)
	}
	if err != nil {
		return nil, fmt.Errorf("conformance: fixture %s: %w", name, err)
	}
	return out.(map[string]any), nil
}

// Discovery returns the discovery document of a Socrate whose issuer is
// issuer (DPoP off, the server default; load "discovery_dpop" for the other).
func Discovery(issuer string) (map[string]any, error) {
	return Load("discovery", Params{Issuer: issuer})
}

// JWKS returns the JWKS document Socrate serves for keys.
func JWKS(keys ...Key) (map[string]any, error) {
	if len(keys) == 0 {
		return nil, errors.New("conformance: JWKS needs at least one key")
	}
	return Load("jwks", Params{Keys: keys})
}

// Sign returns the fixture — an access/, id_token/ or refresh_token/ claim set,
// resolved from p — as a compact JWS signed RS256 with key, under Socrate's
// JOSE header (alg, kid, typ). A resource server validating it against
// JWKS(key) sees exactly what it would see from Socrate.
func Sign(name string, p Params, key Key) (string, error) {
	if !strings.HasPrefix(name, "access/") && !strings.HasPrefix(name, "id_token/") &&
		!strings.HasPrefix(name, "refresh_token/") {
		return "", fmt.Errorf("conformance: %s is not a token fixture", name)
	}
	if key.Private == nil || key.ID == "" {
		return "", errors.New("conformance: Sign needs a key with an ID and a private key")
	}
	claims, err := Load(name, p)
	if err != nil {
		return "", err
	}
	header, err := Load("jose_header", Params{Keys: []Key{key}})
	if err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	tok.Header = header
	s, err := tok.SignedString(key.Private)
	if err != nil {
		return "", fmt.Errorf("conformance: sign %s: %w", name, err)
	}
	return s, nil
}

// placeholder reports whether s is a whole placeholder and returns its kind
// and argument ("scope", "api" for "<scope:api>").
func placeholder(s string) (kind, arg string, ok bool) {
	if len(s) < 3 || s[0] != '<' || s[len(s)-1] != '>' || strings.ContainsAny(s[1:len(s)-1], "<>") {
		return "", "", false
	}
	inner := s[1 : len(s)-1]
	kind, arg, _ = strings.Cut(inner, ":")
	return kind, arg, true
}

const (
	issuerToken = "<issuer>"
	nsToken     = "<ns>"
)

type resolver struct {
	p   Params
	now time.Time
}

func newResolver(p Params) *resolver {
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	return &resolver{p: p, now: now}
}

func or(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func (r *resolver) clientID() string { return or(r.p.ClientID, DefaultClientID) }
func (r *resolver) role() string     { return or(r.p.Role, DefaultRole) }
func (r *resolver) ns() string       { return or(r.p.ClaimsNamespace, DefaultClaimsNamespace) }
func (r *resolver) issuer() string   { return or(r.p.Issuer, DefaultIssuer) }

func (r *resolver) ttl() time.Duration {
	if r.p.TTL > 0 {
		return r.p.TTL
	}
	return DefaultTTL
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// atHash is the OIDC Core §3.1.3.6 at_hash of an RS256-signed token: the
// left half of its SHA-256, base64url-encoded.
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

func (r *resolver) resolve(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			rv, err := r.resolve(val)
			if err != nil {
				return nil, err
			}
			out[strings.ReplaceAll(k, nsToken, r.ns())] = rv
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(t))
		for _, el := range t {
			if s, ok := el.(string); ok && s == "<audience>" {
				auds := r.p.Audiences
				if len(auds) == 0 {
					auds = []string{DefaultAudience}
				}
				for _, a := range auds {
					out = append(out, a)
				}
				continue
			}
			rv, err := r.resolve(el)
			if err != nil {
				return nil, err
			}
			out = append(out, rv)
		}
		return out, nil
	case string:
		kind, arg, ok := placeholder(t)
		if !ok {
			return strings.ReplaceAll(t, issuerToken, r.issuer()), nil
		}
		return r.value(kind, arg)
	default:
		return v, nil
	}
}

// resolveJWKS expands the jwks fixture's single key template once per key.
func (r *resolver) resolveJWKS(doc map[string]any) (any, error) {
	tmpls, _ := doc["keys"].([]any)
	if len(tmpls) != 1 {
		return nil, errors.New("the jwks fixture must hold one key template")
	}
	tmpl, _ := tmpls[0].(map[string]any)
	if len(r.p.Keys) == 0 {
		return nil, errors.New("the jwks fixture needs Params.Keys (or use JWKS)")
	}
	keys := make([]any, 0, len(r.p.Keys))
	for _, k := range r.p.Keys {
		if k.Private == nil || k.ID == "" {
			return nil, errors.New("every key needs an ID and a private key")
		}
		entry := make(map[string]any, len(tmpl))
		for name, val := range tmpl {
			switch val {
			case "<kid>":
				entry[name] = k.ID
			case "<n>":
				entry[name] = base64.RawURLEncoding.EncodeToString(k.Private.N.Bytes())
			default:
				entry[name] = val
			}
		}
		if e := big.NewInt(int64(k.Private.E)).Bytes(); base64.RawURLEncoding.EncodeToString(e) != entry["e"] {
			return nil, fmt.Errorf("key %s: exponent %d is not Socrate's (65537)", k.ID, k.Private.E)
		}
		keys = append(keys, entry)
	}
	return map[string]any{"keys": keys}, nil
}

func (r *resolver) value(kind, arg string) (any, error) {
	p := r.p
	switch kind {
	case "issuer":
		return r.issuer(), nil
	case "client_id":
		return r.clientID(), nil
	case "sub":
		return or(p.Subject, DefaultSubject), nil
	case "app_sub":
		id := p.AppID
		if id == 0 {
			id = DefaultAppID
		}
		return fmt.Sprintf("app:%d", id), nil
	case "role":
		return r.role(), nil
	case "app_roles":
		return map[string]any{r.clientID(): r.role()}, nil
	case "email":
		return or(p.Email, DefaultEmail), nil
	case "name":
		return or(p.Name, DefaultName), nil
	case "nonce":
		return or(p.Nonce, randomB64(12)), nil
	case "tenant_id":
		return or(p.TenantID, DefaultTenantID), nil
	case "attribute":
		attrs := p.Attributes
		if attrs == nil {
			attrs = map[string]any{"department": "engineering"}
		}
		v, ok := attrs[arg]
		if !ok {
			return nil, fmt.Errorf("no attribute %q in Params.Attributes", arg)
		}
		return v, nil
	case "scope":
		return or(p.Scope, arg), nil
	case "iat", "nbf":
		return r.now.Unix(), nil
	case "auth_time":
		if !p.AuthTime.IsZero() {
			return p.AuthTime.Unix(), nil
		}
		return r.now.Unix(), nil
	case "exp":
		return r.now.Add(r.ttl()).Unix(), nil
	case "refresh_exp":
		ttl := p.RefreshTTL
		if ttl <= 0 {
			ttl = DefaultRefreshTTL
		}
		return r.now.Add(ttl).Unix(), nil
	case "expires_in":
		return int64(r.ttl().Seconds()), nil
	case "jti":
		return uuid.NewString(), nil
	case "kid":
		if len(p.Keys) > 0 && p.Keys[0].ID != "" {
			return p.Keys[0].ID, nil
		}
		return uuid.NewString(), nil
	case "token_version":
		if p.TokenVersion > 0 {
			return int64(p.TokenVersion), nil
		}
		return int64(1), nil
	case "at_hash":
		if p.AccessToken != "" {
			return atHash(p.AccessToken), nil
		}
		return randomB64(16), nil
	case "jkt":
		return or(p.JKT, randomB64(32)), nil
	case "access_token", "refresh_token", "id_token":
		v := map[string]string{"access_token": p.AccessToken, "refresh_token": p.RefreshToken, "id_token": p.IDToken}[kind]
		if v == "" {
			return nil, fmt.Errorf("<%s> needs the token in Params", kind)
		}
		return v, nil
	}
	return nil, fmt.Errorf("unknown placeholder <%s>", kind)
}
