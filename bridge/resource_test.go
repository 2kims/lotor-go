package bridge

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestResourceClientUsesOnlyCurrentRuntimeInvocationAuthority(t *testing.T) {
	f := setup(t)
	var validations, reads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Lotor-Secret-Key") != "" || r.Header.Get("Cookie") != "" {
			t.Error("resource access forwarded caller credentials")
		}
		var proof SignedMessage
		if json.NewDecoder(r.Body).Decode(&proof) != nil {
			t.Error("invalid proof")
			w.WriteHeader(400)
			return
		}
		public := f.config.SigningKey.Public().(ed25519.PublicKey)
		if strings.HasSuffix(r.URL.Path, "/authorizations/validate") {
			if _, err := VerifyValidation(proof, public); err != nil {
				t.Error(err)
				w.WriteHeader(403)
				return
			}
			validations.Add(1)
			w.WriteHeader(204)
			return
		}
		if r.URL.Path != "/v1/function-bindings/binding-1/resource-payload-accesses" {
			t.Error("incorrect resource route")
		}
		request, err := VerifyResourceAccess(proof, public)
		if err != nil || request.Resource != "resource:one" || request.Slot != "credential" || request.PayloadVersion != 1 {
			t.Error("resource proof lost exact target")
			w.WriteHeader(403)
			return
		}
		if _, _, err := VerifyAuthorization(request.Authorization, f.issuer.Public().(ed25519.PublicKey)); err != nil {
			t.Error("original Control grant was not preserved")
			w.WriteHeader(403)
			return
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		digest := Digest([]byte("ciphertext"))
		_ = json.NewEncoder(w).Encode(ResourcePayloadAccess{
			Manifest: ResourcePayloadManifest{Resource: request.Resource, Slot: request.Slot, State: "committed", Representation: "encrypted-envelope-v1", ObjectDigest: digest, ObjectSize: 10, PayloadVersion: 1},
			Lease:    ResourcePayloadAccessLease{Resource: request.Resource, Slot: request.Slot, Representation: "encrypted-envelope-v1", ObjectDigest: digest, ObjectSize: 10, PayloadVersion: 1, Audience: "function:binding-1", DownloadURL: "https://objects.example/value?signature=fixture", DownloadMethod: "GET", ExpiresAt: (f.auth.ExpiresAt - 1) * 1_000_000},
		})
	}))
	defer server.Close()
	resources, err := NewResourceClient(ControlValidatorOptions{BaseURL: server.URL, HTTPClient: server.Client(), SigningKeyID: f.config.SigningKeyID, SigningKey: f.config.SigningKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resources.AccessPayload(context.Background(), "resource:one", "credential", 1); !errors.Is(err, ErrUnauthorized) || reads.Load() != 0 {
		t.Fatal("payload access worked without a verified invocation")
	}
	f.config.Authorize = resources.Authorize
	f.config.Functions[0].Handler = func(ctx context.Context, authorization Authorization) (json.RawMessage, error) {
		actual, original, ok := InvocationFromContext(ctx)
		if !ok || actual.ID != authorization.ID || original.KeyID != "issuer-key" {
			t.Fatal("verified grant was not available to handler")
		}
		access, accessErr := resources.AccessPayload(ctx, "resource:one", "credential", 1)
		if accessErr != nil || access.Manifest.Representation != "encrypted-envelope-v1" {
			t.Fatalf("scoped payload access failed: %v", accessErr)
		}
		if _, deniedErr := resources.AccessPayload(ctx, "resource:other", "credential", 1); !errors.Is(deniedErr, ErrUnauthorized) {
			t.Fatal("unrelated resource reached Control")
		}
		return json.RawMessage(`{"ok":true}`), nil
	}
	f.runtime, err = NewRuntime(f.config)
	if err != nil {
		t.Fatal(err)
	}
	response, result := f.call(t, f.auth, "/v1/functions/invoke")
	if response.Code != 200 || result.ErrorCode != "" || validations.Load() != 1 || reads.Load() != 1 {
		t.Fatalf("runtime validation=%d reads=%d status=%d error=%s", validations.Load(), reads.Load(), response.Code, result.ErrorCode)
	}
}

func TestResourceClientPreservesSafeDependencyFailureClasses(t *testing.T) {
	f := setup(t)
	var status atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte("private diagnostic and signed storage URL must not escape"))
	}))
	defer server.Close()
	resources, err := NewResourceClient(ControlValidatorOptions{BaseURL: server.URL, HTTPClient: server.Client(), SigningKeyID: f.config.SigningKeyID, SigningKey: f.config.SigningKey})
	if err != nil {
		t.Fatal(err)
	}
	message, err := SignAuthorization(f.auth, "issuer-key", f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), invocationContextKey{}, invocationState{authorization: f.auth, signed: message})
	for _, test := range []struct {
		expected error
		status   int32
	}{{status: 400, expected: ErrInvalid}, {status: 403, expected: ErrUnauthorized}, {status: 404, expected: ErrNotFound}, {status: 409, expected: ErrConflict}, {status: 503, expected: ErrUnavailable}} {
		status.Store(test.status)
		if _, err := resources.AccessPayload(ctx, "resource:one", "credential", 1); !errors.Is(err, test.expected) {
			t.Fatalf("status=%d error=%v", test.status, err)
		}
	}
}
