package lotorhttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func graphLinkResult(status string, committable bool) map[string]any {
	return map[string]any{
		"resource": "vault:one", "status": status, "expires_at": 123, "idempotent": false, "committable": committable,
		"revisions":          map[string]any{"customer": "1", "graph": "2", "policy": "3", "identity": "4", "billing": "5", "seat": "6", "key": "7"},
		"outcomes":           []any{map[string]any{"resource": "vault:one", "subject": "user:bob", "relation": "member", "state": "active", "allowed": true}},
		"capacity":           map[string]any{"scope": "per_organization", "before": 1, "after": 2, "claim": 1, "release": 0},
		"billing":            map[string]any{"current_quantity": 1, "next_cycle_quantity": 2, "increase": 1, "next_cycle_reduction": 0},
		"invitation_actions": []any{},
		"key_requirements":   []any{map[string]any{"manifest_item_id": "item", "grant_id": "grant", "resource": "vault:one", "relation": "member", "key_resource": "vault:one", "key_version": "1", "recipient_subject": "user:bob", "recipient_key_id": "key", "encryption_algorithm": "X25519", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "activation": "active_access"}},
		"impact":             map[string]any{"impacted_resources": []any{"vault:one"}, "retained_resources": []any{}, "rekey_resources": []any{}},
	}
}

func TestControlResourceGraphWorkflow(t *testing.T) {
	calls := 0
	denied := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Lotor-Secret-Key") != "secret" || r.Header.Get("Authorization") != "Bearer alice" {
			t.Error("lost delegated application scope")
		}
		switch {
		case r.URL.Path == "/v1/public/applications/app/resources/vault:one/link-candidates/search":
			var body ResourceLinkCandidateSearchInput
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Query != "deploy" || body.Relation != "operator" || !reflect.DeepEqual(body.Kinds, []string{"service_account"}) {
				t.Errorf("candidate body=%+v", body)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"candidates": []any{map[string]any{"kind": "service_account", "resource": "service_account:deploy", "display_name": "Deploy", "link_state": "available", "selectable": true}}, "next_cursor": nil})
		case r.URL.Path == "/v1/public/applications/app/resources/vault:one/links/preflight":
			w.Header().Set("Lotor-Link-Token", "link-token")
			_ = json.NewEncoder(w).Encode(graphLinkResult("ready", !denied))
		case r.URL.Path == "/v1/public/applications/app/resources/vault:one/links/commit":
			if r.Header.Get("Lotor-Link-Token") != "link-token" {
				t.Error("missing link capability")
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if raw, present := body["envelopes"]; present && len(raw.([]any)) != 1 {
				t.Error("missing envelope")
			}
			_ = json.NewEncoder(w).Encode(graphLinkResult("active", true))
		case r.URL.EscapedPath() == "/v1/public/applications/app/resources/vault:one/links/link%2Fone":
			if r.Header.Get("Idempotency-Key") != "unlink-once" {
				t.Error("missing unlink idempotency")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "link/one", "resource": "vault:one", "status": "revoked", "rekey_required": true, "rekey_subjects": []string{"user:bob"}, "idempotent": false})
		case r.URL.Path == "/v1/public/applications/app/resources/vault:one/collaborators":
			if !reflect.DeepEqual(r.URL.Query()["kind"], []string{"service_account", "invitation"}) || r.URL.Query().Get("cursor") != "page+one" {
				t.Errorf("collaborator query=%v", r.URL.Query())
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": "vault:one", "collaborators": []any{map[string]any{"kind": "service_account", "id": "service_account:deploy", "resource": "service_account:deploy", "relations": []string{"operator"}, "status": "active"}}, "next_cursor": "next"})
		case r.URL.Path == "/v1/public/applications/app/resources/search":
			_ = json.NewEncoder(w).Encode(map[string]any{"resources": []any{map[string]any{"resource": "vault:one", "resource_type": "vault", "display_name": "Vault", "status": "active", "references": map[string]string{"environment": "environment:preview"}, "parent": map[string]any{"resource": "project:one", "resource_type": "project", "display_name": "Project"}}}, "next_cursor": nil})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
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
	if _, err = app.SearchResources(t.Context(), ResourceSearchInput{}); err == nil {
		t.Fatal("application authority was accepted as a graph actor")
	}

	candidates, err := client.SearchResourceLinkCandidates(t.Context(), "vault:one", ResourceLinkCandidateSearchInput{Query: "deploy", Relation: "operator", Kinds: []string{"service_account"}, Limit: 2})
	if err != nil || candidates.Candidates[0].Kind != "service_account" {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
	changes := []ResourceLinkChange{{Action: "grant", Relation: "member", Subject: "user:bob", Provisioning: "existing_only", Delivery: "none"}}
	preflight, err := client.PreflightResourceLinks(t.Context(), "vault:one", changes)
	if err != nil || preflight.Token != "link-token" || len(preflight.Result.KeyRequirements[0].PublicKey) != 32 {
		t.Fatalf("preflight=%+v err=%v", preflight, err)
	}
	envelopes := []ResourceLinkEnvelopeSubmission{{ManifestItemID: "item", EncryptionSuite: "X25519-HKDF-SHA256-AES-256-GCM", Ciphertext: "ciphertext", AADHash: "hash", Issuer: "user:owner", IssuerKeyID: "key", Signature: "signature"}}
	if result, callErr := client.CommitResourceLinks(t.Context(), "vault:one", preflight, envelopes); callErr != nil || result.Status != "active" {
		t.Fatalf("commit=%+v err=%v", result, callErr)
	}
	if result, callErr := client.SendResourceLinks(t.Context(), "vault:one", ResourceLinkSendInput{Changes: changes}); callErr != nil || result.Committed.Status != "active" {
		t.Fatalf("send=%+v err=%v", result, callErr)
	}
	if result, callErr := client.UnlinkResource(t.Context(), "vault:one", "link/one", "unlink-once"); callErr != nil || !result.RekeyRequired {
		t.Fatalf("unlink=%+v err=%v", result, callErr)
	}
	page, err := client.ResourceCollaborators(t.Context(), "vault:one", ResourceCollaboratorListOptions{Kind: "service_account", Kinds: []string{"invitation"}, Cursor: "page+one", Limit: 10})
	if err != nil || page.Collaborators[0].Kind != "service_account" {
		t.Fatalf("collaborators=%+v err=%v", page, err)
	}
	resources, err := client.SearchResources(t.Context(), ResourceSearchInput{Filters: &ResourceSearchFilters{Resource: &ResourceSearchResourceFilters{Types: []string{"vault"}, References: map[string]string{"environment": "environment:preview"}}}, Include: []string{"parent", "references"}, Page: &ResourceSearchPage{Limit: 10}})
	if err != nil || resources.Resources[0].Parent == nil || resources.Resources[0].Parent.Resource != "project:one" || resources.Resources[0].References["environment"] != "environment:preview" {
		t.Fatalf("resources=%+v err=%v", resources, err)
	}
	denied = true
	before := calls
	_, err = client.SendResourceLinks(t.Context(), "vault:one", ResourceLinkSendInput{Changes: changes})
	var controlErr *ControlError
	if !errors.As(err, &controlErr) || controlErr.Status != http.StatusConflict || calls != before+1 {
		t.Fatalf("denial err=%v calls=%d", err, calls-before)
	}
}

func TestControlResourceGraphRejectsInvalidInputBeforeTransport(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := app.ForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.SearchResourceLinkCandidates(t.Context(), "vault:one", ResourceLinkCandidateSearchInput{Query: "x", Relation: "member"}); err == nil {
		t.Fatal("accepted short query")
	}
	if _, err = client.PreflightResourceLinks(t.Context(), "vault:one", nil); err == nil {
		t.Fatal("accepted empty changes")
	}
	if _, err = client.CommitResourceLinks(t.Context(), "vault:one", ResourceLinkPreflight{}, nil); err == nil {
		t.Fatal("accepted missing capability")
	}
	if _, err = client.ResourceCollaborators(t.Context(), "vault:one", ResourceCollaboratorListOptions{Limit: 101}); err == nil {
		t.Fatal("accepted invalid page")
	}
	if _, err = client.SearchResources(t.Context(), ResourceSearchInput{Include: []string{"private_keys"}}); err == nil {
		t.Fatal("accepted invalid include")
	}
	if calls != 0 {
		t.Fatalf("invalid requests reached transport: %d", calls)
	}
}

func TestControlResourceSubjectAccessCheckUsesOnlyApplicationAuthority(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/public/applications/app/resources/vault:one/subject-access/check" {
			t.Errorf("request=%s %s", r.Method, r.URL.EscapedPath())
		}
		if r.Header.Get("X-Lotor-Secret-Key") != "secret" {
			t.Error("missing application secret")
		}
		if authorization := r.Header.Get("Authorization"); authorization != "" {
			t.Errorf("delegated authority leaked: %q", authorization)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !reflect.DeepEqual(body, map[string]any{"subject": "user:alice"}) {
			t.Errorf("body=%v err=%v", body, err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource": "vault:one", "subject": "user:alice", "allowed": true,
		})
	}))
	defer server.Close()

	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := app.CheckResourceSubjectAccess(t.Context(), "vault:one", "user:alice")
	if err != nil || !result.Allowed {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	delegated, err := app.ForUser("alice-session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = delegated.CheckResourceSubjectAccess(t.Context(), "vault:one", "user:alice"); err == nil {
		t.Fatal("delegated client reached application-only endpoint")
	}
	if _, err = app.CheckResourceSubjectAccess(t.Context(), "vault:one", "bad subject"); err == nil {
		t.Fatal("invalid subject reached transport")
	}
	if calls != 1 {
		t.Fatalf("requests=%d want 1", calls)
	}
}

func TestControlResourceSubjectAccessCheckRejectsMalformedResponse(t *testing.T) {
	response := map[string]any{"resource": "vault:other", "subject": "user:alice", "allowed": true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.CheckResourceSubjectAccess(t.Context(), "vault:one", "user:alice"); err == nil {
		t.Fatal("accepted mismatched resource")
	}
	response = map[string]any{"resource": "vault:one", "subject": "user:other", "allowed": true}
	if _, err = app.CheckResourceSubjectAccess(t.Context(), "vault:one", "user:alice"); err == nil {
		t.Fatal("accepted mismatched subject")
	}
	response = map[string]any{"resource": "vault:one", "subject": "user:alice", "allowed": true, "relations": []string{"owner"}}
	if _, err = app.CheckResourceSubjectAccess(t.Context(), "vault:one", "user:alice"); err == nil {
		t.Fatal("accepted undisclosed response field")
	}
}

func TestControlResourceGraphRejectsMalformedAuthorityResponses(t *testing.T) {
	response := graphLinkResult("ready", true)
	includeToken := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if includeToken {
			w.Header().Set("Lotor-Link-Token", "link-token")
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "link-candidates/search"):
			_ = json.NewEncoder(w).Encode(response)
		case strings.HasSuffix(r.URL.Path, "collaborators"):
			_ = json.NewEncoder(w).Encode(response)
		case strings.HasSuffix(r.URL.Path, "resources/search"):
			_ = json.NewEncoder(w).Encode(response)
		default:
			_ = json.NewEncoder(w).Encode(response)
		}
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
	changes := []ResourceLinkChange{{Action: "revoke", LinkID: "link"}}
	if _, err = client.PreflightResourceLinks(t.Context(), "vault:one", changes); err == nil {
		t.Fatal("accepted missing link token")
	}
	includeToken = true
	response["private_key"] = "secret"
	if _, err = client.PreflightResourceLinks(t.Context(), "vault:one", changes); err == nil {
		t.Fatal("accepted unknown response field")
	}
	delete(response, "private_key")
	response["key_requirements"].([]any)[0].(map[string]any)["public_key"] = "invalid"
	if _, err = client.PreflightResourceLinks(t.Context(), "vault:one", changes); err == nil {
		t.Fatal("accepted malformed public key")
	}
	response = map[string]any{"candidates": []any{map[string]any{"kind": "service_account", "display_name": "Deploy", "link_state": "available", "selectable": true}}, "next_cursor": nil}
	if _, err = client.SearchResourceLinkCandidates(t.Context(), "vault:one", ResourceLinkCandidateSearchInput{Query: "dep", Relation: "member"}); err == nil {
		t.Fatal("accepted malformed candidate")
	}
	response = map[string]any{"resource": "vault:one", "collaborators": []any{map[string]any{"kind": "robot", "id": "robot", "relations": []string{}, "status": "active"}}, "next_cursor": nil}
	if _, err = client.ResourceCollaborators(t.Context(), "vault:one", ResourceCollaboratorListOptions{}); err == nil {
		t.Fatal("accepted malformed collaborator")
	}
	response = map[string]any{"resources": []any{map[string]any{"resource": "vault:one", "resource_type": "vault", "display_name": "Vault"}}, "next_cursor": nil}
	if _, err = client.SearchResources(t.Context(), ResourceSearchInput{}); err == nil {
		t.Fatal("accepted malformed resource search")
	}
}
