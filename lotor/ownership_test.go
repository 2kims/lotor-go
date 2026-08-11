package lotor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func signedOwnership(t *testing.T, privateKey ed25519.PrivateKey, now time.Time) Ownership {
	t.Helper()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	hash := sha256.Sum256(publicKey)
	value := Ownership{
		TenantID: "tnt_a", ApplicationID: "app_a", EnvironmentID: "env_a",
		Endpoint: "lwps://owner.internal:7443", OwnerInstanceID: "lotord-a", OwnershipEpoch: 7,
		IssuedAt: now.UnixMicro(), ExpiresAt: now.Add(30 * time.Second).UnixMicro(),
		Version: 1, KeyID: hex.EncodeToString(hash[:8]),
	}
	value.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, ownershipPayload(value)))
	return value
}

func keySet(publicKey ed25519.PublicKey) runtimeSigningKeySet {
	hash := sha256.Sum256(publicKey)
	return runtimeSigningKeySet{Keys: []runtimeSigningKey{{
		KeyID: hex.EncodeToString(hash[:8]), Algorithm: "Ed25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}}}
}

func TestOwnershipResolverDerivesScopeAndKeyFromControl(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	value := signedOwnership(t, privateKey, now)
	var ownershipRequests, keyRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/runtime/ownership":
			ownershipRequests.Add(1)
			if request.Header.Get("Authorization") != "Bearer runtime-secret" ||
				request.URL.RawQuery != "" {
				t.Errorf("ownership request exposed caller scope: auth=%q query=%q", request.Header.Get("Authorization"), request.URL.RawQuery)
			}
			_ = json.NewEncoder(response).Encode(value)
		case "/.well-known/lotor-runtime-keys.json":
			keyRequests.Add(1)
			if request.Header.Get("Authorization") != "" {
				t.Errorf("public key request included authorization")
			}
			_ = json.NewEncoder(response).Encode(keySet(publicKey))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	resolver, err := NewOwnershipResolver(DiscoveryOptions{
		ControlURL: server.URL, APIKey: "runtime-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.TenantID != "tnt_a" || first.ApplicationID != "app_a" || first.EnvironmentID != "env_a" {
		t.Fatalf("scope was not derived from signed ownership: %+v", first)
	}
	address, tlsRequired, err := first.Address()
	if err != nil || address != "owner.internal:7443" || !tlsRequired {
		t.Fatalf("address=%q tls=%v err=%v", address, tlsRequired, err)
	}
	if _, err = resolver.Resolve(context.Background()); err != nil ||
		ownershipRequests.Load() != 1 || keyRequests.Load() != 1 {
		t.Fatalf("cache ownership=%d keys=%d err=%v", ownershipRequests.Load(), keyRequests.Load(), err)
	}
	resolver.Invalidate()
	if _, err = resolver.Resolve(context.Background()); err != nil ||
		ownershipRequests.Load() != 2 || keyRequests.Load() != 1 {
		t.Fatalf("invalidated ownership=%d keys=%d err=%v", ownershipRequests.Load(), keyRequests.Load(), err)
	}
}

func TestDiscoveryOptionsExposeNoScopeOrTrustMaterial(t *testing.T) {
	typ := reflect.TypeOf(DiscoveryOptions{})
	if typ.NumField() != 2 {
		t.Fatalf("DiscoveryOptions has %d fields, want exactly ControlURL and APIKey", typ.NumField())
	}
	for _, forbidden := range []string{
		"Scope", "TenantID", "ApplicationID", "EnvironmentID", "PublicKey",
	} {
		if _, ok := typ.FieldByName(forbidden); ok {
			t.Fatalf("DiscoveryOptions unexpectedly exposes %s", forbidden)
		}
	}
}

func TestOwnershipResolverRequiresHTTPSExceptLoopback(t *testing.T) {
	if _, err := NewOwnershipResolver(DiscoveryOptions{
		ControlURL: "http://control.example", APIKey: "key",
	}); err == nil {
		t.Fatal("non-loopback plaintext Control URL was accepted")
	}
	if _, err := NewOwnershipResolver(DiscoveryOptions{
		ControlURL: "http://127.0.0.1:8080", APIKey: "key",
	}); err != nil {
		t.Fatalf("loopback development Control URL rejected: %v", err)
	}
}

func TestOwnershipResolverRejectsTamperingExpiredAndInvalidKeys(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	base := signedOwnership(t, privateKey, now)
	for name, mutate := range map[string]func(*Ownership){
		"scope":        func(value *Ownership) { value.EnvironmentID = "" },
		"endpoint":     func(value *Ownership) { value.Endpoint = "lwp://attacker.internal:7420" },
		"signature":    func(value *Ownership) { value.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64)) },
		"expired":      func(value *Ownership) { value.ExpiresAt = now.Add(-time.Second).UnixMicro() },
		"wrong key id": func(value *Ownership) { value.KeyID = "wrong" },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if err := verifyOwnership(value, publicKey, now.UnixMicro()); err == nil {
				t.Fatalf("accepted invalid ownership: %+v", value)
			}
		})
	}
}

func TestOwnershipResolverAcceptsOnlyNewerSameScopeMovedAssertion(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	prior := signedOwnership(t, privateKey, now)
	prior.Endpoint, prior.OwnerInstanceID, prior.OwnershipEpoch = "lwp://old.internal:7420", "old", 4
	prior.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, ownershipPayload(prior)))
	moved := prior
	moved.Endpoint, moved.OwnerInstanceID, moved.OwnershipEpoch = "lwp://new.internal:7420", "new", 5
	moved.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, ownershipPayload(moved)))
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.well-known/lotor-runtime-keys.json" {
			http.NotFound(response, request)
			return
		}
		_ = json.NewEncoder(response).Encode(keySet(publicKey))
	}))
	defer server.Close()
	resolver, err := NewOwnershipResolver(DiscoveryOptions{
		ControlURL: server.URL, APIKey: "key",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(moved)
	if accepted, acceptErr := resolver.acceptMoved(context.Background(), string(raw), prior); acceptErr != nil || accepted.OwnershipEpoch != 5 {
		t.Fatalf("accepted=%+v err=%v", accepted, acceptErr)
	}
	if _, acceptErr := resolver.acceptMoved(context.Background(), string(raw), moved); acceptErr == nil {
		t.Fatal("redirect loop was accepted")
	}
	crossScope := moved
	crossScope.EnvironmentID = "env_other"
	crossScope.OwnershipEpoch = 6
	crossScope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, ownershipPayload(crossScope)))
	raw, _ = json.Marshal(crossScope)
	if _, acceptErr := resolver.acceptMoved(context.Background(), string(raw), prior); acceptErr == nil {
		t.Fatal("cross-scope redirect was accepted")
	}
}
