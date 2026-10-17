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

func TestWorkloadContextRequiresVerifiedHandlerAndExactRuntimeProof(t *testing.T) {
	f := setup(t)
	original, _ := SignAuthorization(f.auth, "issuer-key", f.issuer)
	want := WorkloadContext{InvocationID: f.auth.ID, BindingID: f.auth.BindingID, Scope: f.auth.Scope, Principal: f.auth.Principal, AuthorityKind: "resource_credential", AuthorityResource: "key:original"}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/function-bindings/binding-1/authorizations/context" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("wrong route or caller credential forwarded")
		}
		var proof SignedMessage
		if json.NewDecoder(r.Body).Decode(&proof) != nil {
			t.Error("invalid proof")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		value, err := VerifyValidation(proof, f.config.SigningKey.Public().(ed25519.PublicKey))
		if err != nil || value.Authorization != original {
			t.Error("lost original authorization or runtime signature")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer server.Close()
	client, err := NewResourceClient(ControlValidatorOptions{BaseURL: server.URL, HTTPClient: server.Client(), SigningKeyID: f.config.SigningKeyID, SigningKey: f.config.SigningKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, contextErr := client.WorkloadContext(t.Context()); !errors.Is(contextErr, ErrUnauthorized) || calls.Load() != 0 {
		t.Fatal("context worked outside verified handler", contextErr)
	}
	f.config.Functions[0].Handler = func(ctx context.Context, _ Authorization) (json.RawMessage, error) {
		for range 2 {
			got, contextErr := client.WorkloadContext(ctx)
			if contextErr != nil || got != want {
				t.Errorf("wrong fresh context: %+v %v", got, contextErr)
			}
		}
		return json.RawMessage(`{"ok":true}`), nil
	}
	f.runtime, err = NewRuntime(f.config)
	if err != nil {
		t.Fatal(err)
	}
	response, _ := f.call(t, f.auth, "/v1/functions/invoke")
	if response.Code != 200 || calls.Load() != 2 {
		t.Fatal("context was cached or handler failed", calls.Load())
	}
}

func TestWorkloadContextRejectsMismatchedMalformedAndUnavailableResponses(t *testing.T) {
	f := setup(t)
	original, _ := SignAuthorization(f.auth, "issuer-key", f.issuer)
	ctx := context.WithValue(t.Context(), invocationContextKey{}, invocationState{authorization: f.auth, signed: original})
	valid := WorkloadContext{InvocationID: f.auth.ID, BindingID: f.auth.BindingID, Scope: f.auth.Scope, Principal: f.auth.Principal, AuthorityKind: "subject"}
	for _, name := range []string{"valid-subject", "invocation", "binding", "tenant", "application", "environment", "owner", "principal", "kind", "missing-native-resource", "empty-native-resource", "null-native-resource", "invalid-native-resource", "unexpected-subject-resource", "unexpected-subject-empty-resource", "unexpected-subject-null-resource", "unknown-field", "trailing-json", "oversized", "unauthorized", "unavailable", "redirect"} {
		t.Run(name, func(t *testing.T) {
			value := valid
			code := http.StatusOK
			switch name {
			case "invocation":
				value.InvocationID = "another"
			case "binding":
				value.BindingID = "another"
			case "tenant":
				value.Scope.TenantID = "another"
			case "application":
				value.Scope.ApplicationID = "another"
			case "environment":
				value.Scope.EnvironmentID = "another"
			case "owner":
				value.Scope.OwnerResource = "another"
			case "principal":
				value.Principal = "another"
			case "kind":
				value.AuthorityKind = "unknown"
			case "missing-native-resource", "empty-native-resource", "null-native-resource":
				value.AuthorityKind = "resource_credential"
			case "invalid-native-resource":
				value.AuthorityKind, value.AuthorityResource = "resource_credential", "key with whitespace"
			case "unexpected-subject-resource":
				value.AuthorityResource = "key:forged"
			case "unauthorized":
				code = 403
			case "unavailable":
				code = 503
			case "redirect":
				code = 307
			}
			body, _ := json.Marshal(value)
			if name == "unexpected-subject-empty-resource" || name == "empty-native-resource" {
				body = append(body[:len(body)-1], []byte(`,"authority_resource":""}`)...)
			}
			if name == "unexpected-subject-null-resource" || name == "null-native-resource" {
				body = append(body[:len(body)-1], []byte(`,"authority_resource":null}`)...)
			}
			if name == "unknown-field" {
				body = append(body[:len(body)-1], []byte(`,"private_key":"do-not-trust"}`)...)
			}
			if name == "trailing-json" {
				body = append(body, []byte(` {}`)...)
			}
			if name == "oversized" {
				body = []byte(strings.Repeat("x", 16<<10+1))
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirected" {
					t.Error("runtime proof followed redirect")
				}
				w.Header().Set("Location", "/redirected")
				w.WriteHeader(code)
				_, _ = w.Write(body)
			}))
			defer server.Close()
			client, _ := NewResourceClient(ControlValidatorOptions{BaseURL: server.URL, HTTPClient: server.Client(), SigningKeyID: f.config.SigningKeyID, SigningKey: f.config.SigningKey})
			got, err := client.WorkloadContext(ctx)
			if name == "valid-subject" {
				if err != nil || got != valid {
					t.Fatal(got, err)
				}
				return
			}
			want := ErrUnavailable
			if name == "unauthorized" {
				want = ErrUnauthorized
			}
			if !errors.Is(err, want) || got != (WorkloadContext{}) {
				t.Fatal("unsafe context returned", got, err)
			}
		})
	}
}
