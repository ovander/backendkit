//go:build conformance

// Live conformance: jwtauth validates real Socrate tokens against the real
// JWKS. Run with scripts/conformance-local.sh (see package conformance for the
// environment). Without that environment the tests fail: the build tag is the
// opt-in.

package jwtauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/ovander/backendkit/ctxutil"
	"github.com/ovander/backendkit/jwtauth"
)

const liveUser = "conf-jwtauth@example.test"

func liveEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: the conformance tests need a running Socrate (scripts/conformance-local.sh)", name)
	}
	return v
}

func livePostJSON(t *testing.T, req *http.Request) map[string]any {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %s: HTTP %d: %.200s", req.Method, req.URL.Path, resp.StatusCode, b)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s: %v", req.URL.Path, err)
	}
	return out
}

// liveUserToken signs the test user in to clientID through Socrate's direct
// login API and returns the access token.
func liveUserToken(t *testing.T, clientID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"email": liveUser, "password": liveEnv(t, "SOCRATE_USER_PASSWORD"), "app_client_id": clientID,
	})
	req, _ := http.NewRequest(http.MethodPost, liveEnv(t, "SOCRATE_ISSUER")+"/api/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	tok, _ := livePostJSON(t, req)["access_token"].(string)
	if tok == "" {
		t.Fatal("login returned no access token")
	}
	return tok
}

// liveServiceToken returns a client_credentials access token for the client
// named by the SOCRATE_<kind>_CLIENT_ID/_SECRET variables.
func liveServiceToken(t *testing.T, kind string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, liveEnv(t, "SOCRATE_ISSUER")+"/oauth/token",
		strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(liveEnv(t, "SOCRATE_"+kind+"_CLIENT_ID"), liveEnv(t, "SOCRATE_"+kind+"_CLIENT_SECRET"))
	tok, _ := livePostJSON(t, req)["access_token"].(string)
	if tok == "" {
		t.Fatal("client_credentials returned no access token")
	}
	return tok
}

type liveSeen struct {
	sub, role, tenant string
	authTime          int64
	amr, aud          []string
	appRoles          map[string]string
}

// liveServe runs token through a Middleware on the live JWKS and issuer.
func liveServe(t *testing.T, token string, opts ...jwtauth.Option) (int, liveSeen) {
	t.Helper()
	issuer := liveEnv(t, "SOCRATE_ISSUER")
	m := jwtauth.New(issuer+"/.well-known/jwks.json", issuer, testLogger(), opts...)
	var seen liveSeen
	h := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		seen = liveSeen{
			sub: ctxutil.GetUserSub(ctx), role: ctxutil.GetUserRole(ctx), tenant: ctxutil.GetTenantIDStr(ctx),
			authTime: ctxutil.GetAuthTime(ctx), amr: ctxutil.GetAMR(ctx), aud: ctxutil.GetAudiences(ctx),
			appRoles: ctxutil.GetAppRoles(ctx),
		}
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, seen
}

func TestConformanceUserToken(t *testing.T) {
	plain := liveEnv(t, "SOCRATE_PLAIN_CLIENT_ID")
	tok := liveUserToken(t, plain)

	code, seen := liveServe(t, tok, jwtauth.WithAudience(plain))
	if code != http.StatusOK {
		t.Fatalf("a real user token for %s: HTTP %d, want 200", plain, code)
	}
	if seen.sub == "" || strings.Trim(seen.sub, "0123456789") != "" {
		t.Errorf("sub = %q, want the numeric user id", seen.sub)
	}
	if seen.role != "user" || seen.appRoles[plain] != "user" {
		t.Errorf("role = %q, app_roles = %v, want user in %s", seen.role, seen.appRoles, plain)
	}
	if seen.authTime == 0 || !slices.Equal(seen.amr, []string{"pwd"}) {
		t.Errorf("auth_time = %d, amr = %v, want a sign-in time and [pwd]", seen.authTime, seen.amr)
	}
	if !slices.Contains(seen.aud, plain) {
		t.Errorf("audiences = %v, want %s", seen.aud, plain)
	}

	// Fail closed: another application's audience, the wrong issuer, a
	// tampered signature.
	if code, _ := liveServe(t, tok, jwtauth.WithAudience("some-other-app")); code != http.StatusUnauthorized {
		t.Errorf("wrong audience: HTTP %d, want 401", code)
	}
	issuer := liveEnv(t, "SOCRATE_ISSUER")
	wrongIss := jwtauth.New(issuer+"/.well-known/jwks.json", "https://not-socrate.example", testLogger(), jwtauth.WithAudience(plain))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	wrongIss.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong issuer: HTTP %d, want 401", w.Code)
	}
	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	sig[len(sig)/2] ^= 0x01
	if code, _ := liveServe(t, parts[0]+"."+parts[1]+"."+string(sig), jwtauth.WithAudience(plain)); code != http.StatusUnauthorized {
		t.Errorf("tampered signature: HTTP %d, want 401", code)
	}
}

// With AUDIENCE_MODE=dual a resource server checks only its own identifier,
// registered as an audience of the calling client, for user and service tokens.
func TestConformanceAudienceDual(t *testing.T) {
	dual := liveEnv(t, "SOCRATE_DUAL_CLIENT_ID")
	resource := liveEnv(t, "SOCRATE_AUDIENCE")
	for name, tok := range map[string]string{
		"user token":    liveUserToken(t, dual),
		"service token": liveServiceToken(t, "DUAL"),
	} {
		t.Run(name, func(t *testing.T) {
			code, seen := liveServe(t, tok, jwtauth.WithAudience(resource))
			if code != http.StatusOK {
				t.Fatalf("HTTP %d, want 200 for the registered audience %s", code, resource)
			}
			if !slices.Contains(seen.aud, resource) {
				t.Errorf("audiences = %v, want %s", seen.aud, resource)
			}
			if code, _ := liveServe(t, tok, jwtauth.WithAudiences("unrelated", dual)); code != http.StatusOK {
				t.Errorf("WithAudiences(…, client_id): HTTP %d, want 200 (aud[0] is the client_id)", code)
			}
			if code, _ := liveServe(t, tok, jwtauth.WithAudience("https://other.example")); code != http.StatusUnauthorized {
				t.Errorf("unregistered audience: HTTP %d, want 401", code)
			}
		})
	}
}

// A literal claim mapping issues the tenant under the claims namespace, in
// user and service tokens alike; WithTenantClaim reads it.
func TestConformanceTenantClaim(t *testing.T) {
	claimsClient := liveEnv(t, "SOCRATE_CLAIMS_CLIENT_ID")
	tenant := liveEnv(t, "SOCRATE_TENANT_ID")
	for name, tok := range map[string]string{
		"user token":    liveUserToken(t, claimsClient),
		"service token": liveServiceToken(t, "CLAIMS"),
	} {
		t.Run(name, func(t *testing.T) {
			code, seen := liveServe(t, tok, jwtauth.WithAudience(claimsClient), jwtauth.WithTenantClaim("https://socrate/tenant_id"))
			if code != http.StatusOK {
				t.Fatalf("HTTP %d, want 200", code)
			}
			if seen.tenant != tenant {
				t.Errorf("tenant = %q, want %q", seen.tenant, tenant)
			}
			// The bare name is not what Socrate issues.
			if _, seen := liveServe(t, tok, jwtauth.WithAudience(claimsClient)); seen.tenant != "" {
				t.Errorf("default tenant_id claim = %q: Socrate never issues a bare tenant_id", seen.tenant)
			}
		})
	}
}
