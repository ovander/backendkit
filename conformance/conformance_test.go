package conformance

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testKey is generated once: RSA generation dominates the test time otherwise.
var testKey = func() Key {
	k, err := NewKey()
	if err != nil {
		panic(err)
	}
	return k
}()

func fullParams() Params {
	return Params{
		Issuer: "https://socrate.test", ClientID: "app-1", Audiences: []string{"https://api.test", "urn:svc"},
		Subject: "1234", AppID: 99, Role: "admin", Email: "ada@example.test", Name: "Ada",
		Nonce: "nonce-1", TenantID: "11111111-2222-4333-8444-555555555555",
		Attributes:   map[string]any{"department": "research"},
		TokenVersion: 3, JKT: strings.Repeat("A", 43),
		Now: time.Unix(1_800_000_000, 0), AuthTime: time.Unix(1_799_999_000, 0),
		TTL: 10 * time.Minute, RefreshTTL: 24 * time.Hour,
		AccessToken: "aaa.bbb.ccc", RefreshToken: "ddd.eee.fff", IDToken: "ggg.hhh.iii",
		Keys: []Key{testKey},
	}
}

func TestNames(t *testing.T) {
	names := Names()
	want := []string{
		"access/authorization_code", "access/authorization_code_mfa", "access/refresh",
		"access/audience_dual", "access/custom_claims", "access/client_credentials",
		"access/client_credentials_audience_dual", "access/client_credentials_custom_claims",
		"access/client_credentials_dpop", "id_token/authorization_code", "id_token/authorization_code_mfa",
		"id_token/refresh", "id_token/custom_claims", "refresh_token/authorization_code",
		"token_response/authorization_code", "token_response/refresh", "token_response/client_credentials",
		"userinfo", "introspection/access", "introspection/client_credentials", "introspection/inactive",
		"discovery", "discovery_dpop", "jwks", "jose_header",
	}
	for _, n := range want {
		if !slices.Contains(names, n) {
			t.Errorf("Names() lacks %q", n)
		}
	}
	if len(names) != len(want) {
		t.Errorf("Names() = %d fixtures, want %d: %v", len(names), len(want), names)
	}
	if !slices.IsSorted(names) {
		t.Error("Names() is not sorted")
	}
}

func TestRawUnknown(t *testing.T) {
	for _, n := range []string{"", "nope", "../conformance", "access/../discovery", "fixtures/discovery"} {
		if _, err := Raw(n); err == nil {
			t.Errorf("Raw(%q): want an error", n)
		}
		if _, err := Load(n, Params{}); err == nil {
			t.Errorf("Load(%q): want an error", n)
		}
	}
}

func TestLoadResolvesEveryPlaceholder(t *testing.T) {
	for _, n := range Names() {
		doc, err := Load(n, fullParams())
		if err != nil {
			t.Errorf("Load(%s): %v", n, err)
			continue
		}
		raw, _ := json.Marshal(doc)
		if strings.Contains(string(raw), "<") || strings.Contains(string(raw), `<`) {
			t.Errorf("Load(%s) left a placeholder: %s", n, raw)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	claims, err := Load("access/authorization_code", Params{})
	if err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != DefaultIssuer || claims["sub"] != DefaultSubject || claims["role"] != DefaultRole {
		t.Errorf("defaults not applied: %v", claims)
	}
	if aud, _ := claims["aud"].([]any); len(aud) != 1 || aud[0] != DefaultClientID {
		t.Errorf("aud = %v, want [%s]", claims["aud"], DefaultClientID)
	}
	iat, exp := claims["iat"].(int64), claims["exp"].(int64)
	if exp-iat != int64(DefaultTTL.Seconds()) {
		t.Errorf("exp-iat = %d, want %v", exp-iat, DefaultTTL)
	}
	cc, err := Load("access/client_credentials", Params{})
	if err != nil {
		t.Fatal(err)
	}
	if cc["sub"] != "app:7" || cc["scope"] != "api" {
		t.Errorf("client_credentials defaults: sub=%v scope=%v", cc["sub"], cc["scope"])
	}
	dual, _ := Load("access/audience_dual", Params{ClientID: "c"})
	if aud, _ := dual["aud"].([]any); len(aud) != 2 || aud[0] != "c" || aud[1] != DefaultAudience {
		t.Errorf("dual aud = %v", dual["aud"])
	}
	custom, _ := Load("access/custom_claims", Params{ClaimsNamespace: "urn:x:"})
	if custom["urn:x:tenant_id"] != DefaultTenantID || custom["urn:x:department"] != "engineering" {
		t.Errorf("custom claims not namespaced: %v", custom)
	}
	if _, err := Load("access/custom_claims", Params{Attributes: map[string]any{"other": 1}}); err == nil {
		t.Error("want an error for a missing attribute")
	}
	if _, err := Load("token_response/authorization_code", Params{}); err == nil {
		t.Error("want an error when the tokens are not given")
	}
	if _, err := Load("jwks", Params{}); err == nil {
		t.Error("want an error for jwks without keys")
	}
}

func TestLoadReturnsFreshMaps(t *testing.T) {
	a, _ := Load("userinfo", Params{})
	a["sub"] = "changed"
	b, _ := Load("userinfo", Params{})
	if b["sub"] == "changed" {
		t.Error("Load shares state between calls")
	}
}

// Every fixture, filled by Load, matches itself — with the Params pinned and
// with no Params at all.
func TestMatchSelf(t *testing.T) {
	for _, n := range Names() {
		p := fullParams()
		doc, err := Load(n, p)
		if err != nil {
			t.Fatalf("Load(%s): %v", n, err)
		}
		if err := Match(n, doc, p); err != nil {
			t.Errorf("Match(%s) with pinned params: %v", n, err)
		}
		p.Issuer, p.ClientID, p.Audiences, p.Subject, p.AppID, p.Role, p.Email, p.Name = "", "", nil, "", 0, "", "", ""
		p.Nonce, p.TenantID, p.Attributes, p.TokenVersion, p.JKT = "", "", nil, 0, ""
		p.AccessToken, p.RefreshToken, p.IDToken = "", "", ""
		if n == "discovery" || n == "discovery_dpop" {
			p.Issuer = "https://socrate.test" // its URLs are built from the issuer
		}
		if err := Match(n, doc, p); err != nil {
			t.Errorf("Match(%s) with rules only: %v", n, err)
		}
	}
}

func TestMatchDetects(t *testing.T) {
	p := Params{Issuer: "https://socrate.test", ClientID: "app-1", Audiences: []string{"https://api.test"}}
	base := func(name string) map[string]any {
		doc, err := Load(name, p)
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	tests := []struct {
		name    string
		fixture string
		mutate  func(map[string]any)
		want    string
	}{
		{"missing claim", "access/authorization_code", func(c map[string]any) { delete(c, "token_version") }, "token_version: missing"},
		{"extra claim", "access/authorization_code", func(c map[string]any) { c["tenant_id"] = "x" }, "tenant_id: not in the fixture"},
		{"aud as a string", "access/authorization_code", func(c map[string]any) { c["aud"] = "app-1" }, "aud: want an array"},
		{"wrong client", "access/authorization_code", func(c map[string]any) { c["aud"] = []any{"other"} }, `want "app-1"`},
		{"non-numeric sub", "access/authorization_code", func(c map[string]any) { c["sub"] = "user-42" }, "numeric user id"},
		{"uuid sub", "access/authorization_code", func(c map[string]any) { c["sub"] = "6f1c0f3e-0000-4000-8000-000000000000" }, "numeric user id"},
		{"exp before iat", "access/authorization_code", func(c map[string]any) { c["exp"] = c["iat"].(int64) - 1 }, "is not after iat"},
		{"string exp", "access/authorization_code", func(c map[string]any) { c["exp"] = "soon" }, "exp: want an integer"},
		{"wrong acr", "access/authorization_code_mfa", func(c map[string]any) { c["acr"] = "pwd" }, `acr: want "mfa"`},
		{"missing audience", "access/audience_dual", func(c map[string]any) { c["aud"] = []any{"app-1"} }, "registered audiences"},
		{"bare custom claim", "access/custom_claims", func(c map[string]any) {
			c["tenant_id"] = c["https://socrate/tenant_id"]
			delete(c, "https://socrate/tenant_id")
		}, "https://socrate/tenant_id: missing"},
		{"service sub", "access/client_credentials", func(c map[string]any) { c["sub"] = "7" }, `"app:<numeric id>"`},
		{"user claims on a service token", "access/client_credentials", func(c map[string]any) { c["role"] = "user" }, "role: not in the fixture"},
		{"jkt shape", "access/client_credentials_dpop", func(c map[string]any) { c["cnf"] = map[string]any{"jkt": "short"} }, "thumbprint"},
		{"app_roles without the client", "userinfo", func(c map[string]any) { c["app_roles"] = map[string]any{"x": "user"} }, `no entry for the client "app-1"`},
		{"wrong endpoint", "discovery", func(c map[string]any) { c["token_endpoint"] = "https://socrate.test/token" }, "token_endpoint"},
		{"plain PKCE", "discovery", func(c map[string]any) { c["code_challenge_methods_supported"] = []any{"S256", "plain"} }, "want 1 entries"},
		{"jwks alg", "jwks", func(c map[string]any) { c["keys"].([]any)[0].(map[string]any)["alg"] = "RS512" }, "keys[0].alg"},
		{"token type", "token_response/client_credentials", func(c map[string]any) { c["token_type"] = "DPoP" }, `want "Bearer"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := p
			q.Keys = []Key{testKey}
			q.AccessToken = "a.b.c"
			var doc map[string]any
			if strings.HasPrefix(tt.fixture, "token_response/") || tt.fixture == "jwks" {
				d, err := Load(tt.fixture, q)
				if err != nil {
					t.Fatal(err)
				}
				doc = d
			} else {
				doc = base(tt.fixture)
			}
			tt.mutate(doc)
			err := Match(tt.fixture, doc, p)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Match = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

func TestMatchNeverEchoesTokens(t *testing.T) {
	doc, _ := Load("token_response/client_credentials", Params{AccessToken: "x.y.z"})
	doc["access_token"] = "secret-not-a-jws"
	err := Match("token_response/client_credentials", doc, Params{})
	if err == nil || strings.Contains(err.Error(), "secret-not-a-jws") {
		t.Errorf("Match = %v: want an error that does not echo the token", err)
	}
}

func TestMatchAcceptsStructsAndMapClaims(t *testing.T) {
	claims, _ := Load("access/client_credentials", Params{})
	if err := Match("access/client_credentials", jwt.MapClaims(claims), Params{}); err != nil {
		t.Errorf("jwt.MapClaims: %v", err)
	}
	type inactive struct {
		Active bool `json:"active"`
	}
	if err := Match("introspection/inactive", inactive{}, Params{}); err != nil {
		t.Errorf("struct: %v", err)
	}
	if err := Match("introspection/inactive", []int{1}, Params{}); err == nil {
		t.Error("an array is not an object")
	}
}

func publicKeyFromJWK(t *testing.T, jwk map[string]any) *rsa.PublicKey {
	t.Helper()
	n, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
	if err != nil {
		t.Fatal(err)
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk["e"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
}

func TestSignVerifiesAgainstJWKS(t *testing.T) {
	other, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	set, err := JWKS(testKey, other)
	if err != nil {
		t.Fatal(err)
	}
	if err := Match("jwks", set, Params{}); err != nil {
		t.Fatalf("JWKS does not match its fixture: %v", err)
	}
	byKid := map[string]*rsa.PublicKey{}
	for _, k := range set["keys"].([]any) {
		jwk := k.(map[string]any)
		byKid[jwk["kid"].(string)] = publicKeyFromJWK(t, jwk)
	}

	p := Params{Issuer: "https://socrate.test", ClientID: "app-1", Subject: "5"}
	for _, n := range Names() {
		if !strings.HasPrefix(n, "access/") && !strings.HasPrefix(n, "id_token/") && !strings.HasPrefix(n, "refresh_token/") {
			if _, err := Sign(n, p, testKey); err == nil {
				t.Errorf("Sign(%s): want an error for a non-token fixture", n)
			}
			continue
		}
		tok, err := Sign(n, p, testKey)
		if err != nil {
			t.Fatalf("Sign(%s): %v", n, err)
		}
		parsed, err := jwt.Parse(tok, func(tk *jwt.Token) (any, error) {
			return byKid[tk.Header["kid"].(string)], nil
		}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("https://socrate.test"), jwt.WithAudience("app-1"))
		if err != nil {
			t.Fatalf("Sign(%s): the token does not verify: %v", n, err)
		}
		if err := Match("jose_header", parsed.Header, Params{}); err != nil {
			t.Errorf("Sign(%s) header: %v", n, err)
		}
		if parsed.Header["kid"] != testKey.ID {
			t.Errorf("Sign(%s) kid = %v, want %s", n, parsed.Header["kid"], testKey.ID)
		}
		if err := Match(n, parsed.Claims, p); err != nil {
			t.Errorf("Sign(%s) claims: %v", n, err)
		}
	}
	if _, err := Sign("access/authorization_code", p, Key{}); err == nil {
		t.Error("Sign without a key: want an error")
	}
}

func TestIDTokenAtHash(t *testing.T) {
	at, err := Sign("access/authorization_code", Params{}, testKey)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := Load("id_token/authorization_code", Params{AccessToken: at})
	if claims["at_hash"] != atHash(at) || len(claims["at_hash"].(string)) != 22 {
		t.Errorf("at_hash = %v, want %s", claims["at_hash"], atHash(at))
	}
}

func TestDiscovery(t *testing.T) {
	d, err := Discovery("https://id.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if d["jwks_uri"] != "https://id.example.org/.well-known/jwks.json" {
		t.Errorf("jwks_uri = %v", d["jwks_uri"])
	}
	// discovery_dpop is discovery plus the DPoP algorithms, nothing else: the
	// live suite checks discovery_dpop, so this keeps discovery honest too.
	withDPoP, _ := Load("discovery_dpop", Params{Issuer: "https://id.example.org"})
	if got := withDPoP["dpop_signing_alg_values_supported"]; !slices.Equal(toStrings(got), []string{"ES256"}) {
		t.Errorf("dpop_signing_alg_values_supported = %v", got)
	}
	delete(withDPoP, "dpop_signing_alg_values_supported")
	a, _ := json.Marshal(d)
	b, _ := json.Marshal(withDPoP)
	if string(a) != string(b) {
		t.Errorf("discovery and discovery_dpop differ beyond the DPoP key:\n%s\n%s", a, b)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, el := range v.([]any) {
		out = append(out, el.(string))
	}
	return out
}

// The plain fixtures of a grant are the dual and custom-claims ones without
// what those add, so a change to one is made to all.
func TestFixtureFamiliesAgree(t *testing.T) {
	strip := func(name string, drop ...string) map[string]any {
		var doc map[string]any
		raw, err := Raw(name)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &doc)
		for _, k := range drop {
			delete(doc, k)
		}
		return doc
	}
	same := func(a, b map[string]any) bool {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return string(x) == string(y)
	}
	pairs := [][2]map[string]any{
		{strip("access/authorization_code"), strip("access/refresh")},
		{strip("access/authorization_code", "aud"), strip("access/audience_dual", "aud")},
		{strip("access/authorization_code"), strip("access/custom_claims", "<ns>client", "<ns>department", "<ns>tenant_id")},
		{strip("access/authorization_code", "amr", "acr"), strip("access/authorization_code_mfa", "amr", "acr")},
		{strip("access/client_credentials", "aud"), strip("access/client_credentials_audience_dual", "aud")},
		{strip("access/client_credentials"), strip("access/client_credentials_custom_claims", "<ns>client", "<ns>tenant_id")},
		{strip("access/client_credentials"), strip("access/client_credentials_dpop", "cnf")},
		{strip("id_token/authorization_code", "nonce"), strip("id_token/refresh")},
		{strip("id_token/authorization_code"), strip("id_token/custom_claims", "<ns>tenant_id")},
		{strip("id_token/authorization_code", "amr", "acr"), strip("id_token/authorization_code_mfa", "amr", "acr")},
		{strip("token_response/authorization_code"), strip("token_response/refresh")},
	}
	for i, pr := range pairs {
		if !same(pr[0], pr[1]) {
			t.Errorf("pair %d differs", i)
		}
	}
}
