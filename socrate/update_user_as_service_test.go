package socrate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ovander/backendkit/socrate"
)

func TestUpdateUserAsService_PatchesTheServiceRoute(t *testing.T) {
	var gotBody map[string]any
	c, calls := serviceRoutesServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/apps/3/service/users/7" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":7,"email":"m@example.test","name":"New Name","role":"user","avatar_url":"https://cdn.example.test/7.png"}`))
	})
	name, avatar := "New Name", "https://cdn.example.test/7.png"
	u, err := c.UpdateUserAsService(context.Background(), "7", socrate.UpdateProfileRequest{Name: &name, AvatarURL: &avatar})
	if err != nil || u.Name != "New Name" || u.AvatarURL == nil || *u.AvatarURL != avatar {
		t.Fatalf("UpdateUserAsService = %+v, %v", u, err)
	}
	if (*calls)[0] != "PATCH /api/apps/3/service/users/7 Bearer svc-tok" {
		t.Fatalf("calls = %v", *calls)
	}
	// Only the fields set are sent.
	if len(gotBody) != 2 || gotBody["name"] != name || gotBody["avatar_url"] != avatar {
		t.Fatalf("body = %v", gotBody)
	}
}

func TestUpdateUserAsService_Errors(t *testing.T) {
	name := "x"
	cases := map[string]struct {
		status int
		body   string
		check  func(error) bool
	}{
		"not a member": {404, `{"error":"user not in app"}`, func(e error) bool { return errors.Is(e, socrate.ErrUserNotInApp) }},
		"refused": {400, `{"error":"invalid avatar_url: must use https"}`, func(e error) bool {
			return errors.Is(e, socrate.ErrInvalidProfileUpdate) && strings.Contains(e.Error(), "must use https")
		}},
		"old socrate": {405, ``, func(e error) bool {
			return e != nil && !errors.Is(e, socrate.ErrUserNotInApp) && strings.Contains(e.Error(), "v1.7.0")
		}},
		"router 404": {404, "404 page not found", func(e error) bool {
			return e != nil && !errors.Is(e, socrate.ErrUserNotInApp) && strings.Contains(e.Error(), "v1.7.0")
		}},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			c, _ := serviceRoutesServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			u, err := c.UpdateUserAsService(context.Background(), "7", socrate.UpdateProfileRequest{Name: &name})
			if u != nil || !tc.check(err) {
				t.Fatalf("got %+v, %v", u, err)
			}
		})
	}
}
