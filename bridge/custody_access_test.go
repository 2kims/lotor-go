package bridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testPayloadCustodian func(context.Context, ResourceKeyBinding, func(*ResourceCipher) error) error

func (f testPayloadCustodian) UseResourceKey(ctx context.Context, b ResourceKeyBinding, use func(*ResourceCipher) error) error {
	return f(ctx, b, use)
}

func TestPayloadCustodyRevalidatesBeforeTouchingLocalKeyStore(t *testing.T) {
	for _, scenario := range []string{"authorized", "no-custody-capability", "revoked", "foreign-principal", "foreign-manifest", "raw", "missing-owner", "foreign-owner", "missing-key", "rotated"} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			if scenario != "no-custody-capability" {
				f.auth.Capabilities = append(f.auth.Capabilities, "custody.use")
			}
			original, _ := SignAuthorization(f.auth, "issuer-key", f.issuer)
			reads, uses := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Lotor-Secret-Key") != "" {
					t.Error("caller credentials crossed custody boundary")
				}
				if scenario == "revoked" {
					w.WriteHeader(403)
					return
				}
				var proof SignedMessage
				if json.NewDecoder(r.Body).Decode(&proof) != nil {
					t.Error("invalid runtime proof")
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/authorizations/context") {
					request, err := VerifyValidation(proof, f.config.SigningKey.Public().(ed25519.PublicKey))
					if err != nil || request.Authorization != original {
						t.Error("lost original signed principal")
						w.WriteHeader(403)
						return
					}
					identity := WorkloadContext{InvocationID: f.auth.ID, BindingID: f.auth.BindingID, Scope: f.auth.Scope, Principal: f.auth.Principal, AuthorityKind: "subject"}
					if scenario == "foreign-principal" {
						identity.Principal = "user:foreign"
					}
					_ = json.NewEncoder(w).Encode(identity)
					return
				}
				request, err := VerifyResourceAccess(proof, f.config.SigningKey.Public().(ed25519.PublicKey))
				if err != nil || request.Authorization != original || !request.UseCustody {
					t.Error("invalid scoped resource proof")
					w.WriteHeader(403)
					return
				}
				reads++
				manifest := ResourcePayloadManifest{Resource: request.Resource, Slot: request.Slot, SchemaID: "credential.v1", State: "committed", Representation: "encrypted-envelope-v1", EncryptionSuite: "AES-256-GCM", KeyBindingRef: "organization:one", KeyVersion: 2, ObjectDigest: Digest([]byte("ciphertext")), ObjectSize: 10, PayloadVersion: 1, ResourceRevision: 3, LifecycleGeneration: 1}
				switch scenario {
				case "foreign-manifest":
					manifest.Resource = "resource:foreign"
				case "raw":
					manifest.Representation = "raw"
				case "rotated":
					manifest.KeyVersion = 3
				}
				owner := strings.Repeat("c", 64)
				if scenario == "missing-owner" {
					owner = ""
				}
				if scenario == "foreign-owner" {
					owner = strings.Repeat("d", 64)
				}
				_ = json.NewEncoder(w).Encode(ResourcePayloadAccess{CustodyOwner: owner, Manifest: manifest, Lease: ResourcePayloadAccessLease{Resource: request.Resource, Slot: request.Slot, Representation: manifest.Representation, ObjectDigest: manifest.ObjectDigest, ObjectSize: manifest.ObjectSize, PayloadVersion: 1, ResourceRevision: 3, LifecycleGeneration: 1, Audience: "function:" + f.auth.BindingID, ExpiresAt: (f.auth.ExpiresAt - 1) * 1_000_000}})
			}))
			defer server.Close()
			resources, err := NewResourceClient(ControlValidatorOptions{BaseURL: server.URL, HTTPClient: server.Client(), SigningKeyID: f.config.SigningKeyID, SigningKey: f.config.SigningKey})
			if err != nil {
				t.Fatal(err)
			}
			provider := testPayloadCustodian(func(ctx context.Context, b ResourceKeyBinding, use func(*ResourceCipher) error) error {
				uses++
				if scenario == "missing-key" || b.KeyVersion != 2 || b.CustodyOwner != strings.Repeat("c", 64) {
					return ErrNotFound
				}
				if b.Scope != f.auth.Scope || b.Principal != f.auth.Principal || b.Resource != "resource:one" || b.Slot != "credential" || b.KeyResource != "organization:one" {
					t.Error("key context was not bound to current original authority")
				}
				return WithResourceKey(ctx, b, bytes.Repeat([]byte{7}, 32), use)
			})
			if err = resources.WithPayloadCustody(t.Context(), "client", "resource:one", "credential", 1, provider, func(*ResourceCipher, ResourcePayloadManifest) error { return nil }); !errors.Is(err, ErrUnauthorized) || uses != 0 || reads != 0 {
				t.Fatal("custody usable without verified invocation")
			}
			var operationErr error
			f.config.Functions[0].Handler = func(ctx context.Context, _ Authorization) (json.RawMessage, error) {
				operationErr = resources.WithPayloadCustody(ctx, "client", "resource:one", "credential", 1, provider, func(c *ResourceCipher, m ResourcePayloadManifest) error {
					if m.Resource != "resource:one" {
						t.Error("foreign manifest reached handler")
					}
					_, encryptErr := c.EncryptValue(ctx, "value", []byte("private-canary"))
					return encryptErr
				})
				return json.RawMessage(`{"ok":true}`), nil
			}
			f.runtime, err = NewRuntime(f.config)
			if err != nil {
				t.Fatal(err)
			}
			response, _ := f.call(t, f.auth, "/v1/functions/invoke")
			if response.Code != 200 {
				t.Fatal("test handler did not run")
			}
			if scenario == "authorized" {
				if operationErr != nil || uses != 1 || reads != 1 {
					t.Fatal("valid custody failed", operationErr)
				}
			} else if operationErr == nil {
				t.Fatal("unavailable/foreign custody accepted")
			}
			if scenario == "no-custody-capability" || scenario == "revoked" || scenario == "foreign-principal" || scenario == "foreign-manifest" || scenario == "raw" || scenario == "missing-owner" {
				if uses != 0 {
					t.Fatal("denied metadata reached key store")
				}
			}
		})
	}
}
