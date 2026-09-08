package lotorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestTypedResourceTypePolicy(t *testing.T) {
	var bodies []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/public/applications/app/resource-types/vault" || r.Header.Get("X-Lotor-Secret-Key") != "secret" {
			t.Error("incorrect resource type request")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		bodies = append(bodies, body)
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	input := ResourceTypeDefinition{
		ResourceType: "vault", Kind: "container", Lifecycle: "application", KeyBehavior: "configurable", AllowedParentTypes: []string{"project"}, Relations: []string{"owner", "member"}, InheritedRelations: []string{"member"}, CatalogEntryKinds: []string{"api.operation"}, DirectLinks: true, MayActAsPrincipal: true,
		Payload: ResourcePayloadTypePolicy{Storage: "lotor", Slots: []ResourcePayloadSlotPolicy{{Name: "content", SchemaIDs: []string{"avault.vault.v1"}, MaximumObjectSize: 1048576, Required: true}}},
	}
	result, err := client.PutResourceType(t.Context(), "vault", input)
	if err != nil || !reflect.DeepEqual(result, input) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if bodies[0]["direct_links"] != true || bodies[0]["may_act_as_principal"] != true {
		t.Fatalf("lost graph flags: %v", bodies[0])
	}
	_, err = client.PutResourceType(t.Context(), "vault", ResourceTypeDefinition{ResourceType: "vault", Kind: "content", Lifecycle: "application", KeyBehavior: "none", Payload: ResourcePayloadTypePolicy{Storage: "none"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"allowed_parent_types", "relations"} {
		values, ok := bodies[1][field].([]any)
		if !ok || len(values) != 0 {
			t.Fatalf("required array %s=%v", field, bodies[1][field])
		}
	}
	if bodies[1]["direct_links"] != false {
		t.Error("required false flag omitted")
	}
	payload, ok := bodies[1]["payload"].(map[string]any)
	if !ok {
		t.Fatal("payload omitted")
	}
	if slots, valid := payload["slots"].([]any); !valid || len(slots) != 0 {
		t.Fatal("empty slots must encode as array")
	}
}
