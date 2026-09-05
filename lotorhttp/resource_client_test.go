package lotorhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResourceClientPreflightAndCommitUseProductionCredentialsAndOneToken(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer ltrc_test" || r.Header.Get("X-Lotor-Publishable-Key") != "pk_test" || r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Fatalf("unsafe authentication headers: %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		switch requests {
		case 1:
			if r.URL.Path != "/v1/public/applications/client/resources/integration:slack/executions/preflight" {
				t.Fatalf("path=%s", r.URL.Path)
			}
			w.Header().Set("Lotor-Execution-Token", "execution_token_abcdefghijklmnopqrstuvwxyz")
			_, _ = w.Write([]byte(`{"request_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resource":"integration:slack","resource_revision":2,"lifecycle_generation":1,"catalog_snapshot_id":"snapshot","catalog_entry_id":"entry","catalog_entry_revision":"revision","policy_revision":"policy","payload_slot":"provider_credential","payload_version":1,"payload_representation":"raw","credential_version":1,"execution_mode":"raw","expires_at":100}`))
		case 2:
			if r.Header.Get("Lotor-Execution-Token") != "execution_token_abcdefghijklmnopqrstuvwxyz" {
				t.Fatalf("token=%q", r.Header.Get("Lotor-Execution-Token"))
			}
			_, _ = w.Write([]byte(`{"status":"authorized","request_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resource":"integration:slack","catalog_entry_id":"entry","payload_slot":"provider_credential","payload_version":1,"payload_representation":"raw","execution_mode":"raw","expires_at":100}`))
		}
	}))
	defer server.Close()
	client, err := NewResourceClient(ResourceClientOptions{BaseURL: server.URL, ClientID: "client", PublishableKey: "pk_test", ResourceCredential: "ltrc_test"})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(`{}`))
	preflight, err := client.PreflightExecution(t.Context(), "integration:slack", ResourceExecutionRequest{Method: "POST", Path: "/messages", ContentType: "application/json", RequestBodyDigest: hex.EncodeToString(digest[:]), RequestBodySize: 2})
	if err != nil || preflight.Token == "" {
		t.Fatalf("preflight=%+v error=%v", preflight, err)
	}
	authorization, err := client.CommitExecution(t.Context(), "integration:slack", preflight, ResourceExecutionCommitInput{})
	if err != nil || authorization.Status != "authorized" || requests != 2 {
		t.Fatalf("authorization=%+v requests=%d error=%v", authorization, requests, err)
	}
}

func TestResourceClientDownloadsOnlyExactLeaseWithoutLotorCredentials(t *testing.T) {
	object := []byte("secret")
	objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Lotor-Publishable-Key") != "" {
			t.Fatalf("Lotor credentials reached object store: %v", r.Header)
		}
		_, _ = w.Write(object)
	}))
	defer objectServer.Close()
	client, err := NewResourceClient(ResourceClientOptions{BaseURL: "http://127.0.0.1:1234", ClientID: "client", PublishableKey: "pk", ResourceCredential: "rcred"})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(object)
	raw, err := client.DownloadResourcePayload(context.Background(), ResourcePayloadAccessLease{DownloadURL: objectServer.URL, DownloadMethod: http.MethodGet, ObjectSize: int64(len(object)), ObjectDigest: hex.EncodeToString(digest[:])})
	if err != nil || string(raw) != string(object) {
		t.Fatalf("raw=%q error=%v", raw, err)
	}
}

func TestResourceClientRejectsMissingPublishableOrResourceCredential(t *testing.T) {
	for _, options := range []ResourceClientOptions{
		{BaseURL: "https://api.lotor.dev", ClientID: "client", ResourceCredential: "rcred"},
		{BaseURL: "https://api.lotor.dev", ClientID: "client", PublishableKey: "pk"},
	} {
		if _, err := NewResourceClient(options); err == nil {
			t.Fatalf("accepted incomplete options: %+v", options)
		}
	}
}

func TestProviderExecutionProtectionRoundTripAndBinding(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	requestAAD := []byte("exact-preflight-associated-data")
	requestBody := bytes.Repeat([]byte("a"), 1<<20)
	requestBodyDigest := sha256.Sum256(requestBody)
	preflight := ResourceExecutionPreflight{
		RequestFingerprint: "fingerprint", Resource: "integration:slack", CatalogEntryID: "chat.postMessage",
		PayloadSlot: "provider_credential", PayloadVersion: 3, ExecutionMode: "managed", ExpiresAt: 123,
		PayloadRepresentation: "encrypted-envelope-v1", ResponsePolicyRef: "encrypt_all",
		RequestAAD: base64.RawURLEncoding.EncodeToString(requestAAD), ContentType: "application/json",
		RequestBodyDigest: hex.EncodeToString(requestBodyDigest[:]), RequestBodySize: int64(len(requestBody)),
	}
	protected, err := ProtectProviderRequest(key, preflight, ProviderPlainRequest{
		Headers: map[string]string{"Content-Type": "application/json"}, Body: requestBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ProtectProviderRequest(key, preflight, ProviderPlainRequest{Body: []byte("different")}); err == nil {
		t.Fatal("request body not matching preflight was accepted")
	}
	if _, err = ProtectProviderRequest(key, preflight, ProviderPlainRequest{Body: bytes.Repeat([]byte("a"), (1<<20)+1)}); err == nil {
		t.Fatal("oversized provider body was accepted")
	}
	if _, err = ProtectProviderRequest(key, preflight, ProviderPlainRequest{Body: requestBody, Headers: map[string]string{"Accept": strings.Repeat("a", 8193)}}); err == nil {
		t.Fatal("oversized provider header was accepted")
	}
	plaintext, err := openExecutionPayload(key, protected, requestAAD)
	if err != nil || !bytes.Contains(plaintext, []byte(`"headers"`)) || !bytes.Contains(plaintext, []byte(base64.RawURLEncoding.EncodeToString(requestBody))) {
		t.Fatalf("protected request did not round trip: %s err=%v", plaintext, err)
	}
	requestHash := sha256.Sum256(requestAAD)
	responseAAD := []byte(fmt.Sprintf("lotor-provider-response-v1\x00%x\x00%d", requestHash, 200))
	responsePlaintext, _ := json.Marshal(map[string]any{
		"status": 200, "headers": map[string]string{"Content-Type": "application/json"},
		"body": base64.RawURLEncoding.EncodeToString(requestBody),
	})
	protectedResponse, err := sealExecutionPayload(key, responsePlaintext, responseAAD)
	if err != nil {
		t.Fatal(err)
	}
	authorization := ResourceExecutionAuthorization{
		Status: "completed", RequestFingerprint: preflight.RequestFingerprint, Resource: preflight.Resource,
		CatalogEntryID: preflight.CatalogEntryID, PayloadSlot: preflight.PayloadSlot, PayloadVersion: preflight.PayloadVersion,
		PayloadRepresentation: preflight.PayloadRepresentation, ExecutionMode: preflight.ExecutionMode, ExpiresAt: preflight.ExpiresAt,
		ProviderStatus: 200, ProtectedResponse: protectedResponse,
	}
	opened, err := OpenProviderResponse(key, preflight, authorization)
	if err != nil || opened.Status != 200 || !bytes.Equal(opened.Body, requestBody) {
		t.Fatalf("opened body bytes=%d err=%v", len(opened.Body), err)
	}
	authorization.ProviderStatus = 201
	if _, err = OpenProviderResponse(key, preflight, authorization); err == nil {
		t.Fatal("response was not bound to provider status")
	}
	authorization.ProviderStatus = 200
	authorization.Resource = "integration:other"
	if _, err = OpenProviderResponse(key, preflight, authorization); err == nil {
		t.Fatal("response from a different execution was accepted")
	}
}
