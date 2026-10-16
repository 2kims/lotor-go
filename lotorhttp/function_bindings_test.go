package lotorhttp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/2kims/lotor-go/bridge"
	"github.com/2kims/lotor-go/bridge/transport"
)

func TestFunctionBindingClientPreservesOwnerDelegationAndLifecycle(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Lotor-Secret-Key") != "application-secret" || r.Header.Get("Authorization") != "Bearer owner-session" {
			t.Error("function management lost application scope or owner delegation")
		}
		base := "/v1/public/applications/app/resources/organization:acme/function-bindings"
		switch calls {
		case 1:
			if r.Method != http.MethodPost || r.URL.Path != base || r.Header.Get("Idempotency-Key") != "registration-one" {
				t.Error("incorrect registration route or idempotency")
			}
			var input FunctionBindingRegistration
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Manifest.Functions[0].Name != "customer.echo" || input.SigningPublicKey != "public-only" {
				t.Error("registration contract changed")
			}
			w.WriteHeader(http.StatusCreated)
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != base+"/binding/verify" || r.ContentLength > 0 {
				t.Error("verification must queue an empty-body challenge")
			}
			w.WriteHeader(http.StatusAccepted)
		case 3:
			if r.Method != http.MethodGet || r.URL.Path != base+"/binding" {
				t.Error("incorrect binding read")
			}
		case 4:
			if r.Method != http.MethodGet || r.URL.Path != base || r.URL.Query().Get("cursor") != "next+page" || r.URL.Query().Get("limit") != "25" {
				t.Error("incorrect binding pagination")
			}
			_, _ = w.Write([]byte(`{"bindings":[{"id":"binding","status":"ready"}],"next_cursor":null}`))
			return
		case 5:
			if r.Method != http.MethodDelete || r.URL.Path != base+"/binding" {
				t.Error("incorrect binding revocation")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		case 6:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"forbidden","error":"resource management required"}`))
			return
		default:
			t.Error("unexpected retry or call")
		}
		_, _ = w.Write([]byte(`{"id":"binding","resource":"organization:acme","status":"verifying","revision":1,"challenge":{"id":"challenge","status":"queued","expires_at":123}}`))
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "application-secret"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := app.ForUser("owner-session")
	if err != nil {
		t.Fatal(err)
	}
	input := FunctionBindingRegistration{EndpointURL: "https://customer.example", SigningKeyID: "key", SigningPublicKey: "public-only", AuthenticationMode: "signed_https", Manifest: bridge.Manifest{ProtocolVersion: 1, Functions: []bridge.Function{{Name: "customer.echo", Version: "1"}}}}
	registered, err := owner.RegisterFunctionBinding(t.Context(), "organization:acme", input, "registration-one")
	if err != nil || registered.ID != "binding" {
		t.Fatalf("registration: %+v %v", registered, err)
	}
	verifying, err := owner.VerifyFunctionBinding(t.Context(), "organization:acme", registered.ID)
	if err != nil || verifying.Challenge == nil || verifying.Challenge.Status != "queued" {
		t.Fatalf("verification: %+v %v", verifying, err)
	}
	if _, err = owner.FunctionBinding(t.Context(), "organization:acme", registered.ID); err != nil {
		t.Fatal(err)
	}
	list, err := owner.FunctionBindings(t.Context(), "organization:acme", "next+page", 25)
	if err != nil || len(list.Bindings) != 1 || list.NextCursor != nil {
		t.Fatalf("list: %+v %v", list, err)
	}
	if err := owner.RevokeFunctionBinding(t.Context(), "organization:acme", registered.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.FunctionBinding(t.Context(), "organization:acme", registered.ID); err == nil {
		t.Fatal("denied read accepted")
	}
	if calls != 6 {
		t.Fatalf("unexpected calls: %d", calls)
	}
	if app.userToken != "" {
		t.Fatal("delegation mutated application client")
	}
}

func TestFunctionInvocationClientNormalizesInputAndDoesNotSendAuthorityToRuntime(t *testing.T) {
	controlPublic, controlPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/v1/public/applications/app/resources/organization:acme/function-bindings/binding/invocations" || r.Header.Get("Idempotency-Key") != "operation" || r.Header.Get("Authorization") != "Bearer member" || r.Header.Get("X-Lotor-Secret-Key") != "secret" {
			t.Error("grant lost invocation identity or authority")
		}
		var input FunctionInvocationInput
		if decodeErr := json.NewDecoder(r.Body).Decode(&input); decodeErr != nil || input.InputDigest != bridge.Digest(input.Input) {
			t.Fatal("wire input digest changed during serialization")
		}
		authorization := bridge.Authorization{ProtocolVersion: 1, Kind: "invocation", ID: "operation", Issuer: "lotor", Audience: "binding", BindingID: "binding", BindingRevision: input.ExpectedBindingRevision, Scope: bridge.Scope{TenantID: "tenant", ApplicationID: "application", EnvironmentID: "sandbox", OwnerResource: "organization:acme"}, ManifestDigest: bridge.Digest([]byte("manifest")), Principal: "user:member", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(30 * time.Second).Unix(), Function: &input.Function, Resources: input.Resources, Capabilities: input.Capabilities, Input: input.Input, InputDigest: input.InputDigest}
		if calls == 2 {
			authorization.BindingID = "outside-request"
		}
		signed, signingErr := bridge.SignAuthorization(authorization, "control", controlPrivate)
		if signingErr != nil {
			t.Error(signingErr)
			return
		}
		_ = json.NewEncoder(w).Encode(FunctionInvocationAuthorization{EndpointURL: "https://customer.example", AuthenticationMode: "signed_https", SigningKeyID: "runtime", SigningPublicKey: base64.RawURLEncoding.EncodeToString(runtimePublic), Authorization: signed, ExpiresAt: authorization.ExpiresAt})
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
	input := FunctionInvocationInput{ExpectedBindingRevision: 1, Function: bridge.Function{Name: "customer.echo", Version: "1", InputSchemaDigest: bridge.Digest([]byte("input")), OutputSchemaDigest: bridge.Digest([]byte("output"))}, Resources: []string{"vault:one"}, Capabilities: []string{"resource.read"}, Input: json.RawMessage("{\n \"text\": \"<>&\"\n}")}
	input.InputDigest = bridge.Digest(input.Input)
	if _, err = app.AuthorizeFunctionInvocation(t.Context(), "organization:acme", "binding", input, "operation"); err == nil {
		t.Fatal("application-only grant accepted")
	}
	grant, err := user.AuthorizeFunctionInvocation(t.Context(), "organization:acme", "binding", input, "operation")
	if err != nil || grant.Authorization.KeyID != "control" || grant.ExpiresAt <= 0 || calls != 1 {
		t.Fatalf("grant=%+v calls=%d err=%v", grant, calls, err)
	}
	caller, err := grant.NewClient(bridge.ControlKeys{Issuer: "lotor", Keys: map[string]ed25519.PublicKey{"control": controlPublic}}, transport.Options{})
	if err != nil {
		t.Fatal("normal grant could not construct a result-verifying client:", err)
	}
	caller.CloseIdleConnections()
	if _, callErr := user.AuthorizeFunctionInvocation(t.Context(), "organization:acme", "binding", input, "operation"); callErr == nil || calls != 2 {
		t.Fatal("grant outside requested binding was accepted")
	}
	input.InputDigest = "changed"
	if _, callErr := user.AuthorizeFunctionInvocation(t.Context(), "organization:acme", "binding", input, "operation"); callErr == nil || calls != 2 {
		t.Fatal("invalid digest reached transport")
	}
	input.Input = json.RawMessage(`{"protected_request":"` + strings.Repeat("x", 3<<20) + `"}`)
	input.InputDigest = bridge.Digest(input.Input)
	large, err := user.AuthorizeFunctionInvocation(t.Context(), "organization:acme", "binding", input, "operation")
	if err != nil || len(large.Authorization.Payload) <= 4<<20 || calls != 3 {
		t.Fatalf("protected grant was truncated by the ordinary response limit: %v", err)
	}
	largeCaller, err := large.NewClient(bridge.ControlKeys{Issuer: "lotor", Keys: map[string]ed25519.PublicKey{"control": controlPublic}}, transport.Options{})
	if err != nil {
		t.Fatalf("large grant could not construct a verified caller: %v", err)
	}
	largeCaller.CloseIdleConnections()
}
