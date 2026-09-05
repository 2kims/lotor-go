package lotorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlClientUsesSecretWithoutBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/public/applications/client_test/resources/vault:one" || r.Header.Get("X-Lotor-Secret-Key") != "sk_test_secret" || r.Header.Get("Authorization") != "" {
			t.Fatalf("request=%s secret=%q authorization=%q", r.URL.Path, r.Header.Get("X-Lotor-Secret-Key"), r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"internal","resource":"vault:one","resource_type":"vault","display_name":"One","status":"active","revision":2,"lifecycle_generation":1,"encryption":{"required":false,"status":"not_required"}}`))
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "client_test", SecretKey: "sk_test_secret"})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := client.Resource(t.Context(), "vault:one")
	if err != nil || resource.Resource != "vault:one" || resource.Revision != 2 {
		t.Fatalf("resource=%+v err=%v", resource, err)
	}
}

func TestControlClientLifecycleCarriesFenceAndIdempotency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/public/applications/client_test/resources/vault:one/move" || r.Header.Get("Idempotency-Key") != "move-1" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["parent"] != "project:two" || body["expected_revision"] != float64(4) || body["expected_lifecycle_generation"] != float64(3) {
			t.Fatalf("body=%v err=%v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"operation:one","kind":"resource_move","status":"pending","target_kind":"resource","target_id":"vault:one","request_hash":"hash","created_at":1,"updated_at":1}`))
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "client_test", SecretKey: "sk_test_secret"})
	if err != nil {
		t.Fatal(err)
	}
	operation, err := client.MoveResource(t.Context(), "vault:one", "project:two", ResourceLifecycleFence{ExpectedRevision: 4, ExpectedLifecycleGeneration: 3}, "move-1")
	if err != nil || operation.Kind != "resource_move" {
		t.Fatalf("operation=%+v err=%v", operation, err)
	}
}

func TestControlClientRejectsInsecureRemoteURLAndMissingCredential(t *testing.T) {
	if _, err := NewControlClient(ControlClientOptions{BaseURL: "http://control.example.test", ClientID: "client", SecretKey: "secret"}); err == nil {
		t.Fatal("expected insecure URL rejection")
	}
	if _, err := NewControlClient(ControlClientOptions{BaseURL: "https://api.lotor.dev", ClientID: "client"}); err == nil {
		t.Fatal("expected missing secret rejection")
	}
}

func TestControlClientDoesNotForwardSecretAcrossRedirect(t *testing.T) {
	received := false
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("X-Lotor-Secret-Key") != ""
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: source.URL, ClientID: "client_test", SecretKey: "sk_test_secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Resource(t.Context(), "vault:one"); err == nil {
		t.Fatal("expected redirect rejection")
	}
	if received {
		t.Fatal("application secret reached redirect destination")
	}
}
