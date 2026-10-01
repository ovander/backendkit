package socrate_test

import (
	"reflect"
	"testing"

	"github.com/ovander/backendkit/socrate"
)

func TestLoginResult_TokenSet(t *testing.T) {
	lr := &socrate.LoginResult{
		AccessToken: "at", RefreshToken: "rt", IDToken: "it", TokenType: "Bearer", ExpiresIn: 900,
		UserID: 7, Roles: []string{"user"}, AppRoles: map[string]string{"cid": "admin"},
		MustChangePassword: true,
	}
	got := lr.TokenSet()
	want := &socrate.TokenSet{
		AccessToken: "at", RefreshToken: "rt", IDToken: "it", TokenType: "Bearer", ExpiresIn: 900,
		Roles: []string{"user"}, AppRoles: map[string]string{"cid": "admin"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TokenSet() = %+v, want %+v", got, want)
	}

	// The result does not alias the LoginResult's slice and map.
	got.Roles[0] = "changed"
	got.AppRoles["cid"] = "changed"
	if lr.Roles[0] != "user" || lr.AppRoles["cid"] != "admin" {
		t.Errorf("TokenSet() aliases the LoginResult: %+v", lr)
	}

	var nilResult *socrate.LoginResult
	if nilResult.TokenSet() != nil {
		t.Error("nil LoginResult: want nil TokenSet")
	}
	if ts := (&socrate.LoginResult{AccessToken: "at"}).TokenSet(); ts.Roles != nil || ts.AppRoles != nil {
		t.Errorf("empty roles: want nil Roles and AppRoles, got %+v", ts)
	}
}
