package lotorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPortalSessionPreservesUserAuthority(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/public/applications/app/billing/portal-sessions" || r.Header.Get("Authorization") != "Bearer alice" {
			t.Error("lost portal authority or route")
		}
		var input PortalSessionInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.OrganizationID != "org_acme" || input.ReturnURL != "http://localhost:3300/settings" {
			t.Errorf("invalid request: %+v %v", input, err)
		}
		if calls == 2 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if calls == 3 {
			_, _ = w.Write([]byte(`{"id":"portal","url":"javascript:alert(1)"}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"portal","url":"https://billing.stripe.com/session/test"}`))
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.ForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	input := PortalSessionInput{OrganizationID: "org_acme", ReturnURL: "http://localhost:3300/settings"}
	result, err := user.CreatePortalSession(t.Context(), input)
	if err != nil || result.ID != "portal" {
		t.Fatalf("portal=%+v err=%v", result, err)
	}
	if _, err = user.CreatePortalSession(t.Context(), input); err == nil {
		t.Fatal("denial ignored")
	}
	if _, err = user.CreatePortalSession(t.Context(), input); err == nil {
		t.Fatal("unsafe portal response accepted")
	}
	for _, returnURL := range []string{"http://avault.test/settings", "https://user:pass@avault.test/settings", "javascript:alert(1)", "https://avault.test/?token=secret"} {
		if _, err = user.CreatePortalSession(t.Context(), PortalSessionInput{OrganizationID: "org_acme", ReturnURL: returnURL}); err == nil {
			t.Fatal("unsafe return URL accepted")
		}
	}
	if calls != 3 {
		t.Fatalf("unexpected retry or invalid request: %d", calls)
	}
}
