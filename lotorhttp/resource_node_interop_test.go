package lotorhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestNodeProviderExecutionInterop(t *testing.T) {
	script := os.Getenv("LOTOR_NODE_RESOURCE_INTEROP")
	if script == "" {
		t.Skip("cross-language certificate runs explicitly after the Node SDK build in ci-local")
	}
	key := bytes.Repeat([]byte{7}, 32)
	body := bytes.Repeat([]byte("a"), 1<<20)
	aad := []byte("command-bound-associated-data")
	digest := sha256.Sum256(body)
	preflight := ResourceExecutionPreflight{
		RequestFingerprint: "fingerprint", Resource: "integration:slack", CatalogEntryID: "entry",
		PayloadSlot: "provider_credential", PayloadVersion: 1, ExecutionMode: "managed", ExpiresAt: 123,
		PayloadRepresentation: "encrypted-envelope-v1", ResponsePolicyRef: "encrypt_all",
		RequestAAD: base64.RawURLEncoding.EncodeToString(aad), ContentType: "application/json",
		RequestBodyDigest: fmt.Sprintf("%x", digest), RequestBodySize: int64(len(body)),
	}
	responseAAD := []byte(fmt.Sprintf("lotor-provider-response-v1\x00%x\x00%d", sha256.Sum256(aad), 200))
	plaintext, err := json.Marshal(map[string]any{"status": 200, "headers": map[string]string{"Content-Type": "application/json"}, "body": base64.RawURLEncoding.EncodeToString(body)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealExecutionPayload(key, plaintext, responseAAD)
	if err != nil {
		t.Fatal(err)
	}
	authorization := ResourceExecutionAuthorization{
		Status: "completed", RequestFingerprint: preflight.RequestFingerprint, Resource: preflight.Resource,
		CatalogEntryID: preflight.CatalogEntryID, PayloadSlot: preflight.PayloadSlot, PayloadVersion: preflight.PayloadVersion,
		PayloadRepresentation: preflight.PayloadRepresentation, ExecutionMode: preflight.ExecutionMode, ExpiresAt: preflight.ExpiresAt,
		ProviderStatus: 200, ProtectedResponse: sealed,
	}
	fixture, err := json.Marshal(map[string]any{"key": key, "body": body, "preflight": preflight, "authorization": authorization})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", script)
	command.Stdin = bytes.NewReader(fixture)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("Node execution interoperability failed: %v", err)
	}
	var result struct {
		ProtectedRequest string `json:"protected_request"`
		OpenedBody       string `json:"opened_body"`
		OpenedStatus     int    `json:"opened_status"`
	}
	if err = json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	if result.OpenedStatus != 200 || result.OpenedBody != base64.RawURLEncoding.EncodeToString(body) {
		t.Fatal("Node did not decrypt the exact Go response")
	}
	opened, err := openExecutionPayload(key, result.ProtectedRequest, aad)
	if err != nil {
		t.Fatal(err)
	}
	var request struct {
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err = json.Unmarshal(opened, &request); err != nil {
		t.Fatal(err)
	}
	if request.Body != base64.RawURLEncoding.EncodeToString(body) || request.Headers["Content-Type"] != preflight.ContentType || request.Headers["Accept"] != "application/json" {
		t.Fatal("Go did not decrypt the exact Node request")
	}
}
