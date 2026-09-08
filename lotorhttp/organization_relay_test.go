package lotorhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOrganizationRelayPreservesDelegatedAuthority(t *testing.T) {
	calls, denied := 0, false
	statusBody := `{"binding_id":"efb_acme","status":"pending","bootstrap_expires_at":123,"challenge":{"status":"not_started"}}`
	challengeBody := `{"status":"pending","expires_at":123}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer alice" || r.Header.Get("X-Lotor-Secret-Key") != "secret" || !strings.HasPrefix(r.URL.Path, "/v1/public/applications/app/resources/organization:acme/e2ee/function-bindings") {
			t.Error("lost delegated authority or route")
		}
		if denied {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodPost:
			if strings.HasSuffix(r.URL.Path, "/challenge") {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(challengeBody))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"binding_id":"efb_acme","status":"pending","bootstrap_token":"e2ee_bootstrap_once"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			if strings.HasSuffix(r.URL.Path, "/efb_acme") {
				_, _ = w.Write([]byte(statusBody))
			} else {
				_, _ = w.Write([]byte("[" + statusBody + "]"))
			}
		}
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = app.StartOrganizationFunctionBindingChallenge(ctx, "organization:acme", "efb_acme"); err == nil || calls != 0 {
		t.Fatal("challenge must require delegated authority")
	}
	if _, err = app.CreateOrganizationFunctionBinding(ctx, "organization:acme"); err == nil || calls != 0 {
		t.Fatal("application authority must not substitute for a user")
	}
	client, err := app.ForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateOrganizationFunctionBinding(ctx, "organization:acme")
	if err != nil || created.BindingID != "efb_acme" {
		t.Fatal("bootstrap failed", err)
	}
	challenge, err := client.StartOrganizationFunctionBindingChallenge(ctx, "organization:acme", created.BindingID)
	if err != nil || challenge.Status != "pending" || challenge.ExpiresAt != 123 {
		t.Fatal("challenge failed", err)
	}
	for _, invalid := range []string{`{"status":"ready"}`, `{"status":"pending"}`, `{"status":"unknown"}`, `{"status":"pending","expires_at":123,"connector_token":"secret"}`} {
		challengeBody = invalid
		if _, err = client.StartOrganizationFunctionBindingChallenge(ctx, "organization:acme", created.BindingID); err == nil {
			t.Fatal("accepted invalid challenge", invalid)
		}
	}
	bindings, err := client.ListOrganizationFunctionBindings(ctx, "organization:acme")
	if err != nil || len(bindings) != 1 || bindings[0].BindingID != created.BindingID {
		t.Fatal("discovery failed", err)
	}
	if _, err = client.GetOrganizationFunctionBinding(ctx, "organization:acme", created.BindingID); err != nil {
		t.Fatal(err)
	}
	if err = client.RevokeOrganizationFunctionBinding(ctx, "organization:acme", created.BindingID); err != nil {
		t.Fatal(err)
	}
	statusBody = `{"binding_id":"efb_other","status":"pending"}`
	if _, err = client.GetOrganizationFunctionBinding(ctx, "organization:acme", created.BindingID); err == nil {
		t.Fatal("accepted mismatched binding")
	}
	statusBody = `{"binding_id":"efb_acme","status":"pending","bootstrap_token":"secret"}`
	if _, err = client.ListOrganizationFunctionBindings(ctx, "organization:acme"); err == nil {
		t.Fatal("accepted secret-bearing discovery")
	}
	denied = true
	before := calls
	if _, err = client.CreateOrganizationFunctionBinding(ctx, "organization:acme"); err == nil {
		t.Fatal("accepted denied request")
	}
	if calls != before+1 {
		t.Fatal("retried denied request")
	}
	if _, err = client.StartOrganizationFunctionBindingChallenge(ctx, "organization:acme", created.BindingID); err == nil || calls != before+2 {
		t.Fatal("denied challenge accepted or retried")
	}
}
