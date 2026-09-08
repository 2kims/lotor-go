package lotorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlResourcePoliciesPreserveDelegatedCustodyAndGuestRestrictions(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer alice" {
			t.Error("lost delegated policy authority")
		}
		if r.URL.Path == "/v1/public/applications/app/resources/vault:one/collaboration-policy" {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			guests := body["guests"].(map[string]any)
			if guests["allowed"] != true || guests["allowed_domains"].([]any)[0] != "example.com" {
				t.Errorf("guest policy=%v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": "vault:one", "revision": 2})
			return
		}
		if r.Method == http.MethodPut {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["required_account_custody"] != "enterprise_box" || body["function_binding_id"] != "efb_acme" || body["resource_key_policy"] != "organization_default" {
				t.Errorf("E2EE policy=%v", body)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"organization": "organization:acme", "required_account_custody": "enterprise_box", "resource_key_executor": "customer_box", "automation_executor": "customer_box", "function_binding_id": "efb_acme", "resource_key_policy": "organization_default", "status": "ready", "revision": 3})
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.OrganizationE2EEPolicy(t.Context(), "organization:acme"); err == nil {
		t.Fatal("application authority was accepted as policy actor")
	}
	if _, err = app.SetResourceCollaborationPolicy(t.Context(), "vault:one", ResourceCollaborationPolicyOverride{Guests: ResourceGuestPolicyOverride{Allowed: boolPointer(true)}}); err == nil {
		t.Fatal("application authority was accepted as policy actor")
	}
	if calls != 0 {
		t.Fatalf("application-only policy request reached transport: %d", calls)
	}
	client, err := app.ForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := client.OrganizationE2EEPolicy(t.Context(), "organization:acme")
	if err != nil || policy.FunctionBindingID != "efb_acme" || policy.Revision != 3 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	input := OrganizationE2EEPolicyInput{RequiredAccountCustody: "enterprise_box", ResourceKeyExecutor: "customer_box", AutomationExecutor: "customer_box", FunctionBindingID: "efb_acme", ResourceKeyPolicy: "organization_default"}
	if policy, err = client.ConfigureOrganizationE2EE(t.Context(), "organization:acme", input); err != nil || policy.Status != "ready" {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	mutation, err := client.SetResourceCollaborationPolicy(t.Context(), "vault:one", ResourceCollaborationPolicyOverride{Guests: ResourceGuestPolicyOverride{Allowed: boolPointer(true), AllowedDomains: []string{"example.com"}}})
	if err != nil || mutation.Revision != 2 {
		t.Fatalf("mutation=%+v err=%v", mutation, err)
	}
	before := calls
	input.RequiredAccountCustody = "invalid"
	if _, err = client.ConfigureOrganizationE2EE(t.Context(), "organization:acme", input); err == nil {
		t.Fatal("accepted invalid E2EE policy")
	}
	if _, err = client.SetResourceCollaborationPolicy(t.Context(), "vault:one", ResourceCollaborationPolicyOverride{}); err == nil {
		t.Fatal("accepted empty guest policy")
	}
	if calls != before {
		t.Fatalf("invalid policy reached transport: %d", calls-before)
	}
}

func TestControlResourcePoliciesRejectMalformedResponsesAndDoNotRetryDenials(t *testing.T) {
	calls := 0
	denied := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if denied {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path == "/v1/public/applications/app/resources/vault:one/collaboration-policy" {
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": "vault:one", "revision": 0})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"organization": "organization:acme", "required_account_custody": "enterprise_box", "resource_key_executor": "customer_box", "automation_executor": "customer_box", "resource_key_policy": "organization_default", "status": "unknown", "revision": 1})
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := app.ForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.OrganizationE2EEPolicy(t.Context(), "organization:acme"); err == nil {
		t.Fatal("accepted malformed E2EE policy")
	}
	if _, err = client.SetResourceCollaborationPolicy(t.Context(), "vault:one", ResourceCollaborationPolicyOverride{Guests: ResourceGuestPolicyOverride{Allowed: boolPointer(false)}}); err == nil {
		t.Fatal("accepted malformed guest policy mutation")
	}
	denied = true
	before := calls
	if _, err = client.OrganizationE2EEPolicy(t.Context(), "organization:acme"); err == nil {
		t.Fatal("accepted denied E2EE policy")
	}
	if calls != before+1 {
		t.Fatalf("denied request retried: %d", calls-before)
	}
}

func boolPointer(value bool) *bool { return &value }
