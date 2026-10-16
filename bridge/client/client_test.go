package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/2kims/lotor-go/bridge"
)

type fixtureDispatcher struct {
	alter            func(*bridge.Result)
	control          ed25519.PublicKey
	runtime          ed25519.PrivateKey
	calls            int
	mutualCalls      int
	mutualConfigured bool
	fail             bool
}

func (f *fixtureDispatcher) MutualTLSConfigured() bool { return f.mutualConfigured }
func (f *fixtureDispatcher) SendMutualTLS(ctx context.Context, endpoint, operation string, message bridge.SignedMessage) (bridge.SignedMessage, error) {
	f.mutualCalls++
	return f.Send(ctx, endpoint, operation, message)
}

func (f *fixtureDispatcher) Send(_ context.Context, endpoint, operation string, message bridge.SignedMessage) (bridge.SignedMessage, error) {
	f.calls++
	if endpoint != "https://bridge.example" || operation != "invoke" {
		return bridge.SignedMessage{}, bridge.ErrInvalid
	}
	if f.fail {
		return bridge.SignedMessage{}, bridge.ErrUnavailable
	}
	authorization, raw, err := bridge.VerifyAuthorization(message, f.control)
	if err != nil {
		return bridge.SignedMessage{}, err
	}
	result := bridge.Result{ProtocolVersion: 1, ID: authorization.ID, Kind: authorization.Kind, BindingID: authorization.BindingID, BindingRevision: authorization.BindingRevision, ManifestDigest: authorization.ManifestDigest, AuthorizationDigest: bridge.Digest(raw), CompletedAt: time.Now().Unix(), Output: authorization.Input}
	if f.alter != nil {
		f.alter(&result)
	}
	return bridge.SignResult(result, "runtime", f.runtime)
}

func clientFixture(t *testing.T) (Options, bridge.Authorization, ed25519.PrivateKey, *fixtureDispatcher) {
	t.Helper()
	public, control, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimePublic, runtimeKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dispatch := &fixtureDispatcher{control: public, runtime: runtimeKey}
	scope := bridge.Scope{TenantID: "tenant", ApplicationID: "app", EnvironmentID: "sandbox", OwnerResource: "organization:acme"}
	manifest := bridge.Digest([]byte("manifest"))
	options := Options{EndpointURL: "https://bridge.example", AuthenticationMode: "signed_https", BindingID: "binding", Audience: "binding", BindingRevision: 1, Scope: scope, ManifestDigest: manifest, Issuer: "lotor", TrustedKeys: map[string]ed25519.PublicKey{"control": public}, SigningKeyID: "runtime", SigningPublicKey: runtimePublic, Dispatcher: dispatch}
	authorization := bridge.Authorization{ProtocolVersion: 1, Kind: "invocation", ID: "operation", Issuer: "lotor", Audience: "binding", BindingID: "binding", BindingRevision: 1, Scope: scope, ManifestDigest: manifest, IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(30 * time.Second).Unix(), Principal: "user:one", Function: &bridge.Function{Name: "customer.echo", Version: "1", InputSchemaDigest: bridge.Digest([]byte("input")), OutputSchemaDigest: bridge.Digest([]byte("output"))}, Input: json.RawMessage(`{"value":true}`)}
	authorization.InputDigest = bridge.Digest(authorization.Input)
	return options, authorization, control, dispatch
}

func TestClientInvokesExactGrantAndVerifiesResult(t *testing.T) {
	options, authorization, control, dispatch := clientFixture(t)
	client, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	message, _ := bridge.SignAuthorization(authorization, "control", control)
	result, err := client.Invoke(t.Context(), message)
	if err != nil || result.ID != authorization.ID || dispatch.calls != 1 || string(result.Output) != string(authorization.Input) {
		t.Fatalf("result=%+v calls=%d err=%v", result, dispatch.calls, err)
	}
	options.AuthenticationMode = "mtls"
	if _, err = New(options); err == nil {
		t.Fatal("required mTLS accepted an unconfigured transport")
	}
	dispatch.mutualConfigured = true
	client, err = New(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Invoke(t.Context(), message); err != nil || dispatch.mutualCalls != 1 {
		t.Fatalf("required mTLS was not used: %v", err)
	}
}

func TestClientRejectsWrongGrantBeforeNetwork(t *testing.T) {
	for name, alter := range map[string]func(*bridge.Authorization){
		"scope":     func(a *bridge.Authorization) { a.Scope.EnvironmentID = "production" },
		"audience":  func(a *bridge.Authorization) { a.Audience = "other" },
		"binding":   func(a *bridge.Authorization) { a.BindingID = "other" },
		"revision":  func(a *bridge.Authorization) { a.BindingRevision++ },
		"manifest":  func(a *bridge.Authorization) { a.ManifestDigest = bridge.Digest([]byte("changed")) },
		"expired":   func(a *bridge.Authorization) { a.ExpiresAt = a.IssuedAt - 1 },
		"challenge": func(a *bridge.Authorization) { a.Kind = "challenge" },
	} {
		t.Run(name, func(t *testing.T) {
			options, authorization, control, dispatch := clientFixture(t)
			client, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			alter(&authorization)
			message, _ := bridge.SignAuthorization(authorization, "control", control)
			if _, err := client.Invoke(t.Context(), message); !errors.Is(err, bridge.ErrUnauthorized) || dispatch.calls != 0 {
				t.Fatalf("invalid grant reached network: calls=%d err=%v", dispatch.calls, err)
			}
		})
	}
}

func TestClientPreservesUnknownOutcomeAndNeverAutomaticallyRetries(t *testing.T) {
	for _, mode := range []string{"transport", "wrong result", "handler failure"} {
		t.Run(mode, func(t *testing.T) {
			options, authorization, control, dispatch := clientFixture(t)
			switch mode {
			case "transport":
				dispatch.fail = true
			case "wrong result":
				dispatch.alter = func(r *bridge.Result) { r.ID = "different" }
			case "handler failure":
				dispatch.alter = func(r *bridge.Result) { r.ErrorCode = "outcome_unknown"; r.Output = nil }
			}
			client, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			message, _ := bridge.SignAuthorization(authorization, "control", control)
			if _, err := client.Invoke(context.Background(), message); !errors.Is(err, bridge.ErrOutcomeUnknown) || dispatch.calls != 1 {
				t.Fatalf("unsafe outcome/retry: calls=%d err=%v", dispatch.calls, err)
			}
		})
	}
}
