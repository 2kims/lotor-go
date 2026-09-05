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

func TestControlClientIssuesResourceCredentialWithExactPrincipalAndIdempotency(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/public/applications/client_test/resources/api_key:key/credentials" ||
			r.Header.Get("X-Lotor-Secret-Key") != "sk_test_secret" || r.Header.Get("Idempotency-Key") != "issue-1" {
			t.Fatalf("unexpected request: %s %s headers=%v", r.Method, r.URL.Path, r.Header)
		}
		var input ResourceCredentialIssueInput
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.IssuedTo != "service_account:worker" {
			t.Fatalf("input=%+v", input)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"rcred_1","resource":"api_key:key","issued_to":"service_account:global","status":"active","display_hint":"ltrc_***","version":1,"created_at":1,"credential":"ltrc_secret"}`))
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "client_test", SecretKey: "sk_test_secret"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := client.IssueResourceCredential(t.Context(), "api_key:key", ResourceCredentialIssueInput{IssuedTo: "service_account:worker"}, "issue-1")
	if err != nil || issued.Credential != "ltrc_secret" || issued.IssuedTo != "service_account:global" {
		t.Fatalf("issued=%+v error=%v", issued, err)
	}
}

func TestControlClientPayloadUploadCarriesOnlyServerIssuedPayloadToken(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			if r.URL.Path != "/v1/public/applications/client_test/resources/integration:slack/payloads/provider_credential/uploads" || r.Header.Get("Lotor-Payload-Token") != "" {
				t.Fatalf("begin request=%s headers=%v", r.URL.Path, r.Header)
			}
			w.Header().Set("Lotor-Payload-Token", "payload_token_abcdefghijklmnopqrstuvwxyz")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"resource":"integration:slack","slot":"provider_credential","payload_version":1,"expected_payload_version":0,"upload_url":"https://objects.example/upload","upload_method":"PUT","required_headers":{},"expires_at":100}`))
		case 2:
			if r.URL.Path != "/v1/public/applications/client_test/resources/integration:slack/payloads/provider_credential/commits" || r.Header.Get("Lotor-Payload-Token") != "payload_token_abcdefghijklmnopqrstuvwxyz" {
				t.Fatalf("commit request=%s headers=%v", r.URL.Path, r.Header)
			}
			_, _ = w.Write([]byte(`{"resource":"integration:slack","slot":"provider_credential","schema_id":"avault.credential.v1","payload_version":1,"representation":"raw","object_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","object_size":2,"resource_revision":2,"lifecycle_generation":1,"state":"committed","committed_at":100}`))
		}
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "client_test", SecretKey: "sk_test_secret"})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := client.BeginResourcePayloadUpload(t.Context(), "integration:slack", "provider_credential", ResourcePayloadUploadInput{SchemaID: "avault.credential.v1", Representation: "raw", ObjectDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObjectSize: 2, ResourceRevision: 2, LifecycleGeneration: 1})
	if err != nil || intent.Token == "" {
		t.Fatalf("intent=%+v error=%v", intent, err)
	}
	manifest, err := client.CommitResourcePayload(t.Context(), "integration:slack", "provider_credential", intent)
	if err != nil || manifest.PayloadVersion != 1 || requests != 2 {
		t.Fatalf("manifest=%+v requests=%d error=%v", manifest, requests, err)
	}
}
