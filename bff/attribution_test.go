package bff

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ovander/backendkit/socrate"
)

func TestWithClientAttributionSetsContext(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/bff/callback", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (Browser)")
	r.Header.Set("X-Forwarded-For", "6.6.6.6") // must be ignored: the caller resolves the IP

	got, ok := socrate.ClientAttributionFrom(WithClientAttribution(r, "203.0.113.7").Context())
	want := socrate.ClientAttribution{IP: "203.0.113.7", UserAgent: "Mozilla/5.0 (Browser)"}
	if !ok || got != want {
		t.Fatalf("got %+v, %v; want %+v, true", got, ok, want)
	}
	if _, ok := socrate.ClientAttributionFrom(r.Context()); ok {
		t.Fatal("the original request's context must not be modified")
	}
}

// fakeTokenEndpoint is a Socrate /oauth/token recording the attribution
// headers of each refresh.
type fakeTokenEndpoint struct {
	mu        sync.Mutex
	xff, ua   []string
	hasXFF    []bool
	refreshes int
}

func (f *fakeTokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.refreshes++
	_, has := r.Header["X-Forwarded-For"]
	f.hasXFF = append(f.hasXFF, has)
	f.xff = append(f.xff, r.Header.Get("X-Forwarded-For"))
	f.ua = append(f.ua, r.Header.Get("User-Agent"))
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-new", "refresh_token": "rt-new", "token_type": "Bearer", "expires_in": 3600})
}

// TestProxyRefreshCarriesClientAttribution: attribution set on the incoming
// request by the BFF's middleware reaches Socrate's /oauth/token on the
// gateway's refresh path, although that refresh runs under a context detached
// from the request's cancellation.
func TestProxyRefreshCarriesClientAttribution(t *testing.T) {
	tokenEP := &fakeTokenEndpoint{}
	socrateSrv := httptest.NewServer(tokenEP)
	defer socrateSrv.Close()
	client, err := socrate.NewClient(socrate.ClientConfig{BaseURL: socrateSrv.URL, ClientID: "bff", ClientSecret: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}

	var gotAuth string
	up := upstreamRecorder(&gotAuth)
	defer up.Close()
	uu, _ := url.Parse(up.URL)

	store := NewMemoryStore(time.Hour, time.Hour)
	g := newTestGateway(uu, store, client)
	h := g.ProxyWithSession(NewSingleHostProxy(uu))

	for i, attributed := range []bool{true, false} {
		// Expired access token → the proxy must refresh.
		store.Put(NewSession("sid", "csrf", tokenSet("old-at", "rt", 0), UserInfo{Sub: "u1"}, time.Now().Add(-time.Minute)))
		req := httptest.NewRequest(http.MethodGet, "/api/admin/x", nil)
		req.AddCookie(&http.Cookie{Name: "sess", Value: "sid"})
		req.Header.Set("User-Agent", "Mozilla/5.0 (Browser)")
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		if attributed {
			req = WithClientAttribution(req, "203.0.113.7")
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK || gotAuth != "Bearer at-new" {
			t.Fatalf("request %d: got %d, upstream Authorization %q", i, rec.Code, gotAuth)
		}
	}

	tokenEP.mu.Lock()
	defer tokenEP.mu.Unlock()
	if tokenEP.refreshes != 2 {
		t.Fatalf("want 2 refreshes, got %d", tokenEP.refreshes)
	}
	if tokenEP.xff[0] != "203.0.113.7" || tokenEP.ua[0] != "Mozilla/5.0 (Browser)" {
		t.Errorf("attributed refresh: Socrate saw XFF=%q UA=%q, want 203.0.113.7 / the browser UA", tokenEP.xff[0], tokenEP.ua[0])
	}
	if tokenEP.hasXFF[1] || tokenEP.ua[1] != "Go-http-client/1.1" {
		t.Errorf("unattributed refresh: Socrate saw XFF=%q UA=%q, want none / Go's default", tokenEP.xff[1], tokenEP.ua[1])
	}
}
