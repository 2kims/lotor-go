package lotorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestControlClientWaitsForDurableOperationWithBoundsAndCancellation(t *testing.T) {
	reads := 0
	var forcePending atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reads++
		status := "running"
		if reads > 1 && !forcePending.Load() {
			status = "failed"
		}
		_, _ = w.Write([]byte(`{"id":"operation:one","kind":"resource_move","status":"` + status + `","target_kind":"resource","target_id":"vault:one","request_hash":"hash","error_code":"resource_conflict","created_at":1,"updated_at":2}`))
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "client", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.WaitForOperation(t.Context(), "operation:one", OperationWaitOptions{MaxAttempts: 3})
	if err != nil || result.Status != "failed" || result.ErrorCode != "resource_conflict" || reads != 2 {
		t.Fatalf("operation=%+v reads=%d err=%v", result, reads, err)
	}
	if _, err = client.WaitForOperation(t.Context(), "operation:one", OperationWaitOptions{MaxAttempts: -1}); err == nil || reads != 2 {
		t.Fatalf("invalid bounds reached transport reads=%d err=%v", reads, err)
	}
	if _, err = client.WaitForOperation(t.Context(), "operation:one", OperationWaitOptions{MaxAttempts: 10_001}); err == nil || reads != 2 {
		t.Fatalf("invalid attempt limit reached transport reads=%d err=%v", reads, err)
	}
	if _, err = client.WaitForOperation(t.Context(), "operation:one", OperationWaitOptions{Interval: -1}); err == nil || reads != 2 {
		t.Fatalf("invalid interval reached transport reads=%d err=%v", reads, err)
	}
	forcePending.Store(true)
	if _, err = client.WaitForOperation(t.Context(), "operation:one", OperationWaitOptions{MaxAttempts: 1}); err == nil || reads != 3 {
		t.Fatalf("bounded wait reads=%d err=%v", reads, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = client.WaitForOperation(cancelled, "operation:one", OperationWaitOptions{MaxAttempts: 3, Interval: time.Minute}); err == nil || reads != 3 {
		t.Fatalf("cancelled wait reached transport reads=%d err=%v", reads, err)
	}
	waiting, stop := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, stop)
	if _, err = client.WaitForOperation(waiting, "operation:one", OperationWaitOptions{MaxAttempts: 3, Interval: time.Minute}); !errors.Is(err, context.Canceled) || reads != 4 {
		t.Fatalf("delayed cancellation reads=%d err=%v", reads, err)
	}
}

func TestControlPayloadRewrapPreservesCustodyAndDelegation(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/public/applications/app/resources/vault:one/payloads/config/rewraps" || r.Header.Get("Authorization") != "Bearer member" {
			t.Error("incorrect rewrap route or delegated authority")
		}
		if calls == 3 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		if body["expected_wrap_revision"] != float64(0) || body["previous_key_version"] != float64(1) || body["key_version"] != float64(2) {
			t.Error("lost rewrap version fences")
		}
		if calls == 1 && body["rewrap_receipt"] != nil {
			t.Error("box request invented browser attestation")
		}
		if calls == 2 && body["rewrap_receipt"] != "receipt" {
			t.Error("lost browser attestation")
		}
		_, _ = w.Write([]byte(`{"resource":"vault:one","slot":"config","payload_version":1,"wrap_revision":1,"previous_key_version":1,"key_version":2,"resource_revision":3,"lifecycle_generation":1,"key_binding_ref":"organization:acme","wrapped_payload_key":"wrapped","aad_hash":"hash","rewrapper_subject":"member","rewrapper_key_id":"key"}`))
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.ForUser("member")
	if err != nil {
		t.Fatal(err)
	}
	input := ResourcePayloadRewrapInput{PayloadVersion: 1, KeyBindingRef: "organization:acme", PreviousKeyVersion: 1, KeyVersion: 2, ResourceRevision: 3, LifecycleGeneration: 1}
	result, err := user.RewrapResourcePayload(t.Context(), "vault:one", "config", input)
	if err != nil || result.WrapRevision != 1 || result.KeyVersion != 2 || result.KeyBindingRef != input.KeyBindingRef {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	input.WrappedPayloadKey, input.RewrapperSubject, input.RewrapperKeyID, input.RewrapReceipt = "wrapped", "member", "key", "receipt"
	if _, err = user.RewrapResourcePayload(t.Context(), "vault:one", "config", input); err != nil {
		t.Fatal(err)
	}
	if _, err = user.RewrapResourcePayload(t.Context(), "vault:one", "config", input); err == nil || calls != 3 {
		t.Fatal("denied rewrap was accepted or retried")
	}
}

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

func TestControlClientReadsTypedEncryptionAndCatalogBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resource":"service_account:worker","principal_subject":"resource_principal:global","encryption":{"required":true,"status":"ready","key_scope":"organization","effective_key_resource":"organization:acme","key_resource":"organization:acme","key_version":3},"catalog_binding":{"resource":"service_account:worker","catalog_id":"cat","snapshot_id":"snap","snapshot_digest":"digest","entry_kinds":["api.operation"],"resource_revision":4}}`))
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "client", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	resource, err := client.Resource(t.Context(), "service_account:worker")
	if err != nil {
		t.Fatal(err)
	}
	if resource.PrincipalSubject != "resource_principal:global" || !resource.Encryption.Required || resource.Encryption.KeyVersion != 3 || resource.Encryption.EffectiveKeyResource != "organization:acme" || resource.Encryption.KeyResource != "organization:acme" {
		t.Fatalf("missing principal/encryption fields: %+v", resource)
	}
	if resource.CatalogBinding == nil || resource.CatalogBinding.Resource != resource.Resource || resource.CatalogBinding.SnapshotID != "snap" || resource.CatalogBinding.ResourceRevision != 4 {
		t.Fatalf("missing binding fields: %+v", resource.CatalogBinding)
	}
	var plain Resource
	if err = json.Unmarshal([]byte(`{"encryption":{"required":false,"status":"not_required"}}`), &plain); err != nil || plain.CatalogBinding != nil || plain.Encryption.Required || plain.Encryption.KeyVersion != 0 {
		t.Fatalf("plain resource invented encryption/binding: %+v, %v", plain, err)
	}
}

func TestControlClientForUserDoesNotMutateApplicationClient(t *testing.T) {
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Lotor-Secret-Key") != "test-secret" {
			t.Error("missing application credential")
		}
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"resource":"vault:one"}`))
	}))
	defer server.Close()
	application, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "client", SecretKey: "test-secret"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := application.ForUser("user-session")
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*ControlClient{user, application, user} {
		if _, err = client.Resource(t.Context(), "vault:one"); err != nil {
			t.Fatal(err)
		}
	}
	if len(authorizations) != 3 || authorizations[0] != "Bearer user-session" || authorizations[1] != "" || authorizations[2] != "Bearer user-session" {
		t.Fatalf("principal isolation failed: %v", authorizations)
	}
	for _, token := range []string{"", " ", "a\nb", "a\rb"} {
		if _, err = application.ForUser(token); err == nil {
			t.Error("invalid user token accepted")
		}
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
