package bridge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestCustodyDecryptsSharedNodeBrowserVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/resource-value-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Key       string
		Plaintext string
		Value     ResourceValue
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid vector")
	}
	key, err := base64.RawURLEncoding.DecodeString(fixture.Key)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptResourceValue(key, fixture.Value, fixture.Value.Context)
	if err != nil || string(plain) != fixture.Plaintext {
		t.Fatal("cross-language ciphertext drift", err)
	}
	for _, suffix := range []string{"\r", "\n", "\r\n", " ", "\t", "="} {
		value := fixture.Value
		value.Ciphertext = value.Ciphertext[:4] + suffix + value.Ciphertext[4:]
		if _, err := DecryptResourceValue(key, value, value.Context); !errors.Is(err, ErrInvalid) {
			t.Fatalf("non-canonical ciphertext containing %q accepted: %v", suffix, err)
		}
	}
}

func TestCustodyOpensOnlyTheExactCommittedEncryptedPayload(t *testing.T) {
	ctx, binding, key := custodyTestBinding(t)
	manifest := ResourcePayloadManifest{
		Resource: binding.Resource, Slot: binding.Slot, SchemaID: "example.credential.v1", KeyBindingRef: binding.KeyResource, KeyVersion: binding.KeyVersion,
		ResourceRevision: binding.ResourceRevision, LifecycleGeneration: binding.LifecycleGeneration, PayloadVersion: binding.PayloadVersion, State: "committed", Representation: "encrypted-envelope-v1", EncryptionSuite: "AES-256-GCM",
	}
	aadRaw, _ := json.Marshal(struct {
		ClientID            string `json:"client_id"`
		Resource            string `json:"resource"`
		Slot                string `json:"slot"`
		SchemaID            string `json:"schema_id"`
		ResourceRevision    int64  `json:"resource_revision"`
		LifecycleGeneration int64  `json:"lifecycle_generation"`
	}{binding.ClientID, binding.Resource, binding.Slot, manifest.SchemaID, binding.ResourceRevision, binding.LifecycleGeneration})
	aad := sha256.Sum256(aadRaw)
	manifest.AADHash = base64.RawURLEncoding.EncodeToString(aad[:])
	nonce := bytes.Repeat([]byte{8}, 12)
	dataKey := bytes.Repeat([]byte{9}, 32)
	aead, _ := resourceAEAD(key)
	wrapped := append([]byte{1}, nonce...)
	wrapped = aead.Seal(wrapped, nonce, dataKey, aad[:])
	manifest.WrappedPayloadKey = base64.RawURLEncoding.EncodeToString(wrapped)
	aead, _ = resourceAEAD(dataKey)
	ciphertext := append([]byte{1}, nonce...)
	ciphertext = aead.Seal(ciphertext, nonce, []byte(`{"token":"private-canary"}`), aad[:])
	manifest.ObjectSize = int64(len(ciphertext))
	manifest.ObjectDigest = Digest(ciphertext)
	binding.ObjectDigest = manifest.ObjectDigest
	for _, scenario := range []string{"committed", "slot", "schema", "digest", "revision", "generation", "version", "key_version", "key_resource", "aad", "wrapper", "oversized_wrapper", "state", "ciphertext"} {
		t.Run(scenario, func(t *testing.T) {
			current := manifest
			object := append([]byte(nil), ciphertext...)
			switch scenario {
			case "slot":
				current.Slot = "foreign"
			case "schema":
				current.SchemaID = "foreign"
			case "digest":
				current.ObjectDigest = Digest([]byte("foreign"))
			case "revision":
				current.ResourceRevision++
			case "generation":
				current.LifecycleGeneration++
			case "version":
				current.PayloadVersion++
			case "key_version":
				current.KeyVersion++
			case "key_resource":
				current.KeyBindingRef = "organization:foreign"
			case "aad":
				current.AADHash = "AAAA"
			case "wrapper":
				current.WrappedPayloadKey = "AAAA"
			case "oversized_wrapper":
				current.WrappedPayloadKey = strings.Repeat("A", MaximumInputBytes)
			case "state":
				current.State = "pending"
			case "ciphertext":
				object[len(object)-1] ^= 1
			}
			err := WithResourceKey(ctx, binding, key, func(c *ResourceCipher) error {
				if scenario == "oversized_wrapper" {
					if allocations := testing.AllocsPerRun(10, func() {
						_, _ = c.OpenPayload(ctx, current, object)
					}); allocations != 0 {
						t.Fatalf("invalid wrapper length allocated before rejection: %v", allocations)
					}
				}
				plain, err := c.OpenPayload(ctx, current, object)
				if scenario == "committed" {
					if err != nil || string(plain) != `{"token":"private-canary"}` {
						t.Fatal("valid encrypted payload failed", err)
					}
				} else if err == nil || len(plain) != 0 {
					t.Fatal("unverified payload opened")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func custodyTestBinding(t *testing.T) (context.Context, ResourceKeyBinding, []byte) {
	t.Helper()
	f := setup(t)
	grant := f.auth
	grant.Capabilities = append(grant.Capabilities, "custody.use")
	grant.PolicyDigest = Digest([]byte("policy"))
	ctx := context.WithValue(t.Context(), invocationContextKey{}, invocationState{authorization: grant})
	binding := ResourceKeyBinding{
		Scope: grant.Scope, ClientID: "client", Resource: grant.Resources[0], Slot: "credential", KeyResource: "organization:one", CustodyOwner: strings.Repeat("c", 64), KeyVersion: 2,
		ResourceRevision: 3, LifecycleGeneration: 1, PayloadVersion: 4, ObjectDigest: Digest([]byte("payload")),
		InvocationID: grant.ID, BindingID: grant.BindingID, BindingRevision: grant.BindingRevision, Principal: grant.Principal, PolicyDigest: grant.PolicyDigest, ExpiresAt: grant.ExpiresAt,
	}
	return ctx, binding, bytes.Repeat([]byte{7}, 32)
}

func TestCustodyValueRoundTripAndCallbackLifetime(t *testing.T) {
	ctx, binding, key := custodyTestBinding(t)
	original := append([]byte(nil), key...)
	var escaped *ResourceCipher
	var envelope ResourceValue
	err := WithResourceKey(ctx, binding, key, func(cipher *ResourceCipher) error {
		escaped = cipher
		if diagnostic := fmt.Sprintf("%v %+v %#v", cipher, cipher, cipher); diagnostic != "ResourceCipher([redacted]) ResourceCipher([redacted]) ResourceCipher([redacted])" {
			t.Fatal("cipher diagnostic exposed private state")
		}
		var err error
		envelope, err = cipher.EncryptValue(ctx, "users.email", []byte(`"private@example.test"`))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, original) {
		t.Fatal("provider-owned buffer was modified")
	}
	plain, err := DecryptResourceValue(key, envelope, envelope.Context)
	if err != nil || string(plain) != `"private@example.test"` {
		t.Fatal("round trip failed", err)
	}
	if _, err = escaped.EncryptValue(ctx, "users.email", []byte(`"secret"`)); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("cipher escaped callback lifetime")
	}
	if len(escaped.state.key) != 0 {
		t.Fatal("callback retained the resource key")
	}
}

func TestCustodyValueRejectsForeignContextCiphertextAndKeys(t *testing.T) {
	ctx, binding, key := custodyTestBinding(t)
	var envelope ResourceValue
	if err := WithResourceKey(ctx, binding, key, func(c *ResourceCipher) error {
		var err error
		envelope, err = c.EncryptValue(ctx, "users.email", []byte(`"secret"`))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"resource", "key_resource", "key_version", "scope", "principal", "invocation", "binding", "binding_revision", "policy", "path", "payload_version", "generation", "revision", "digest", "client"} {
		t.Run(field, func(t *testing.T) {
			expected := envelope.Context
			switch field {
			case "resource":
				expected.Binding.Resource = "resource:foreign"
			case "key_resource":
				expected.Binding.KeyResource = "organization:foreign"
			case "key_version":
				expected.Binding.KeyVersion++
			case "scope":
				expected.Binding.Scope.EnvironmentID = "foreign"
			case "principal":
				expected.Binding.Principal = "user:foreign"
			case "invocation":
				expected.Binding.InvocationID = "foreign"
			case "binding":
				expected.Binding.BindingID = "foreign"
			case "binding_revision":
				expected.Binding.BindingRevision++
			case "policy":
				expected.Binding.PolicyDigest = Digest([]byte("changed"))
			case "path":
				expected.Path = "users.password"
			case "payload_version":
				expected.Binding.PayloadVersion++
			case "generation":
				expected.Binding.LifecycleGeneration++
			case "revision":
				expected.Binding.ResourceRevision++
			case "digest":
				expected.Binding.ObjectDigest = Digest([]byte("changed"))
			case "client":
				expected.Binding.ClientID = "foreign"
			}
			if _, err := DecryptResourceValue(key, envelope, expected); err == nil {
				t.Fatal("foreign expected context accepted")
			}
			changed := envelope
			changed.Context = expected
			if _, err := DecryptResourceValue(key, changed, expected); err == nil {
				t.Fatal("tampered authenticated context accepted")
			}
		})
	}
	changed := envelope
	changed.Ciphertext = "AAAA"
	if _, err := DecryptResourceValue(key, changed, envelope.Context); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if _, err := DecryptResourceValue(bytes.Repeat([]byte{8}, 32), envelope, envelope.Context); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestCustodyRequiresOriginalLiveInvocationAndClosesOnFailure(t *testing.T) {
	ctx, binding, key := custodyTestBinding(t)
	for _, scenario := range []string{"missing", "foreign_resource", "foreign_principal", "foreign_revision", "expired", "cancelled", "missing_policy"} {
		t.Run(scenario, func(t *testing.T) {
			current := binding
			callCtx := ctx
			switch scenario {
			case "missing":
				callCtx = t.Context()
			case "foreign_resource":
				current.Resource = "resource:foreign"
			case "foreign_principal":
				current.Principal = "user:foreign"
			case "foreign_revision":
				current.BindingRevision++
			case "expired":
				current.ExpiresAt = 1
			case "cancelled":
				var cancel context.CancelFunc
				callCtx, cancel = context.WithCancel(ctx)
				cancel()
			case "missing_policy":
				current.PolicyDigest = ""
			}
			called := false
			if err := WithResourceKey(callCtx, current, key, func(*ResourceCipher) error { called = true; return nil }); err == nil || called {
				t.Fatal("unauthorized key use reached callback")
			}
		})
	}
	var escaped *ResourceCipher
	want := errors.New("application handler failed")
	err := WithResourceKey(ctx, binding, key, func(c *ResourceCipher) error { escaped = c; return want })
	if !errors.Is(err, want) || len(escaped.state.key) != 0 {
		t.Fatal("failure did not release key")
	}
	// Ciphertexts have no plaintext-bearing JSON fields.
	var value ResourceValue
	_ = WithResourceKey(ctx, binding, key, func(c *ResourceCipher) error {
		value, _ = c.EncryptValue(ctx, "value", []byte("private-canary"))
		return nil
	})
	raw, _ := json.Marshal(value)
	if bytes.Contains(raw, []byte("private-canary")) {
		t.Fatal("plaintext in value envelope")
	}
}

func TestCustodyCopiesShareCallbackLifetime(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			ctx, binding, key := custodyTestBinding(t)
			var copied ResourceCipher
			var retainedKey []byte
			want := errors.New("callback failed")
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						recoveredErr, ok := recovered.(error)
						if outcome != "panic" || !ok || !errors.Is(recoveredErr, want) {
							t.Fatalf("unexpected panic: %v", recovered)
						}
					}
				}()
				err := WithResourceKey(ctx, binding, key, func(c *ResourceCipher) error {
					copied = *c
					retainedKey = c.state.key
					if _, err := copied.EncryptValue(ctx, "value", []byte("canary")); err != nil {
						t.Fatal("copy unusable during callback", err)
					}
					if diagnostic := fmt.Sprintf("%v %+v %#v", copied, copied, copied); strings.Count(diagnostic, "ResourceCipher([redacted])") != 3 {
						t.Fatal("value-copy diagnostic exposed private state")
					}
					if outcome == "panic" {
						panic(want)
					}
					if outcome == "error" {
						return want
					}
					return nil
				})
				if (outcome == "error" && !errors.Is(err, want)) || (outcome == "success" && err != nil) {
					t.Fatal("unexpected callback result", err)
				}
				if outcome == "panic" {
					t.Fatal("callback panic was swallowed")
				}
			}()
			if _, err := copied.EncryptValue(ctx, "value", []byte("canary")); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("copied cipher encrypted after callback", err)
			}
			if _, err := copied.OpenPayload(ctx, ResourcePayloadManifest{}, nil); !errors.Is(err, ErrUnauthorized) {
				t.Fatal("copied cipher opened payload after callback", err)
			}
			if len(copied.state.key) != 0 || !bytes.Equal(retainedKey, make([]byte, 32)) {
				t.Fatal("callback did not erase shared key state")
			}
		})
	}
}

func TestCustodyCopiedCipherConcurrentWithCleanup(t *testing.T) {
	ctx, binding, key := custodyTestBinding(t)
	started, done := make(chan struct{}), make(chan struct{})
	var copied ResourceCipher
	err := WithResourceKey(ctx, binding, key, func(c *ResourceCipher) error {
		copied = *c
		go func() {
			defer close(done)
			close(started)
			for range 100 {
				_, err := copied.EncryptValue(ctx, "value", []byte("canary"))
				if err != nil && !errors.Is(err, ErrUnauthorized) {
					t.Error("unexpected concurrent encryption error", err)
				}
			}
		}()
		<-started
		return nil
	})
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if _, err := copied.EncryptValue(ctx, "value", nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("copy remained usable after concurrent cleanup", err)
	}
}

func TestCustodyUninitializedCipherRejectsUse(t *testing.T) {
	for _, c := range []*ResourceCipher{nil, {}} {
		if _, err := c.EncryptValue(t.Context(), "value", nil); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("uninitialized cipher encrypted", err)
		}
		if _, err := c.OpenPayload(t.Context(), ResourcePayloadManifest{}, nil); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("uninitialized cipher opened payload", err)
		}
	}
}

func TestCustodyRejectsNonceLengthBeforeAllocation(t *testing.T) {
	_, binding, key := custodyTestBinding(t)
	for _, size := range []int{0, 15, 17, MaximumInputBytes} {
		value := ResourceValue{Format: ResourceValueFormat, Context: ResourceValueContext{Binding: binding, Path: "value"}, Nonce: strings.Repeat("A", size), Ciphertext: strings.Repeat("A", 24)}
		if _, err := DecryptResourceValue(key, value, value.Context); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid nonce length %d accepted: %v", size, err)
		}
		if allocations := testing.AllocsPerRun(10, func() {
			_, _ = DecryptResourceValue(key, value, value.Context)
		}); allocations != 0 {
			t.Fatalf("nonce length %d allocated before rejection: %v", size, allocations)
		}
	}
}
