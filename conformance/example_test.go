package conformance_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/ovander/backendkit/conformance"
)

// A Socrate mock for a resource server's tests: its JWKS and discovery
// documents, and access tokens with the claims Socrate really issues.
func Example_mock() {
	key, err := conformance.NewKey()
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	serve := func(doc map[string]any) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
		}
	}
	jwks, _ := conformance.JWKS(key)
	disc, _ := conformance.Discovery(srv.URL)
	mux.Handle("/.well-known/jwks.json", serve(jwks))
	mux.Handle("/.well-known/openid-configuration", serve(disc))

	// A user's access token for the client "my-app"…
	userToken, _ := conformance.Sign("access/authorization_code", conformance.Params{
		Issuer: srv.URL, ClientID: "my-app", Subject: "42", Role: "editor",
	}, key)
	// …and a service account's, carrying a tenant through a literal claim mapping.
	serviceToken, _ := conformance.Sign("access/client_credentials_custom_claims", conformance.Params{
		Issuer: srv.URL, ClientID: "billing-worker", AppID: 12,
		TenantID: "5b0c7a52-3e0c-4d2a-9f8e-0d6f1a2b3c4d",
	}, key)

	fmt.Println(userToken != "" && serviceToken != "")
	// Output: true
}

func ExampleLoad() {
	claims, err := conformance.Load("access/client_credentials", conformance.Params{
		Issuer: "https://socrate.example.com", ClientID: "billing-worker", AppID: 12,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(claims["sub"], claims["aud"], claims["scope"], claims["type"])
	// Output: app:12 [billing-worker] api access
}

func ExampleMatch() {
	// A hand-written mock token: aud as a bare string, no type, no jti.
	handWritten := map[string]any{
		"iss": "https://socrate.example.com", "sub": "42", "aud": "my-app",
		"iat": 1700000000, "exp": 1700000900,
	}
	err := conformance.Match("access/client_credentials", handWritten, conformance.Params{})
	fmt.Println(err != nil)
	// Output: true
}
