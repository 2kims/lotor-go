package lambda

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/2kims/lotor-go/bridge"
)

type testStore struct{ result *bridge.Result }

func (store *testStore) Reserve(context.Context, string, string) (*bridge.Result, error) {
	return store.result, nil
}

func (store *testStore) Complete(_ context.Context, _, _ string, result bridge.Result) error {
	store.result = &result
	return nil
}

func TestAdaptersProduceEquivalentSignedResults(t *testing.T) {
	pub, issuer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fn := bridge.Function{Name: "customer.echo", Version: "1", InputSchemaDigest: bridge.Digest([]byte("input")), OutputSchemaDigest: bridge.Digest([]byte("output"))}
	manifest, err := bridge.ManifestDigest(bridge.Manifest{ProtocolVersion: 1, Functions: []bridge.Function{fn}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	scope := bridge.Scope{TenantID: "tenant", ApplicationID: "app", EnvironmentID: "sandbox", OwnerResource: "organization:customer"}
	auth := bridge.Authorization{ProtocolVersion: 1, Kind: "invocation", ID: "invocation", Issuer: "lotor", Audience: "runtime", BindingID: "binding", BindingRevision: 1, ManifestDigest: manifest, Scope: scope, IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Function: &fn, Principal: "user:one", Input: json.RawMessage(`{"hello":"world"}`)}
	auth.InputDigest = bridge.Digest(auth.Input)
	// Keep service/Lambda contract equivalence at Avault's existing protected
	// envelope ceiling, not merely with a tiny JSON example. This tests adapter
	// framing, not a deployed AWS payload limit or cryptographic decryption.
	auth.Input = json.RawMessage(`{"protected_request":"` + strings.Repeat("x", 3<<20) + `"}`)
	auth.InputDigest = bridge.Digest(auth.Input)
	message, err := bridge.SignAuthorization(auth, "issuer", issuer)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	newRuntime := func() *bridge.Runtime {
		runtime, err := bridge.NewRuntime(bridge.Config{Issuer: "lotor", Audience: "runtime", BindingID: "binding", BindingRevision: 1, Scope: scope, SigningKeyID: "runtime", SigningKey: signing, TrustedKeys: map[string]ed25519.PublicKey{"issuer": pub}, Store: &testStore{}, Authorize: func(context.Context, bridge.Authorization, bridge.SignedMessage) error { return nil }, Now: func() time.Time { return now }, Functions: []bridge.Registration{{Function: fn, Handler: func(_ context.Context, a bridge.Authorization) (json.RawMessage, error) { return a.Input, nil }}}})
		if err != nil {
			t.Fatal(err)
		}
		return runtime
	}
	t.Run("invalid events with a configured runtime", func(t *testing.T) {
		for _, event := range []Request{
			{Version: "1.0"},
			{Version: "2.0", RawPath: "/v1/functions/invoke", Body: "!", IsBase64Encoded: true},
			{Version: "2.0", RawPath: "/v1/functions/invoke?unexpected=true"},
			{Version: "2.0", RawPath: "/v1/functions/invoke", Body: strings.Repeat("x", bridge.MaximumBodyBytes+1)},
		} {
			result, err := NewHandler(newRuntime())(context.Background(), event)
			if err != nil || result.StatusCode != 400 || result.Headers["Cache-Control"] != "no-store" {
				t.Fatalf("invalid event accepted: status=%d err=%v", result.StatusCode, err)
			}
		}
	})
	httpRequest := httptest.NewRequest("POST", "/v1/functions/invoke", bytes.NewReader(body))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResult := httptest.NewRecorder()
	newRuntime().ServeHTTP(httpResult, httpRequest)
	for _, encoded := range []bool{false, true} {
		event := Request{Version: "2.0", RawPath: "/v1/functions/invoke", Headers: map[string]string{"content-type": "application/json"}, Body: string(body), IsBase64Encoded: encoded}
		event.RequestContext.HTTP.Method = "POST"
		if encoded {
			event.Body = base64.StdEncoding.EncodeToString(body)
		}
		result, err := NewHandler(newRuntime())(context.Background(), event)
		if err != nil || result.StatusCode != httpResult.Code || result.Body != httpResult.Body.String() || result.Headers["Cache-Control"] != "no-store" {
			t.Fatalf("adapter mismatch: status=%d err=%v", result.StatusCode, err)
		}
	}
}

func TestLambdaRejectsInvalidEnvelopeWithoutRuntime(t *testing.T) {
	for _, event := range []Request{{Version: "1.0"}, {Version: "2.0", RawPath: "/v1/functions/invoke", Body: "!", IsBase64Encoded: true}, {Version: "2.0", RawPath: "//other.example/invoke"}} {
		result, err := NewHandler(nil)(context.Background(), event)
		if err != nil || result.StatusCode != 400 {
			t.Fatal("invalid event accepted")
		}
	}
}
