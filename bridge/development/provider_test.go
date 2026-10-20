package development

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2kims/lotor-go/bridge"
)

type proofRoundTripper func(*http.Request) (*http.Response, error)

func (round proofRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return round(r) }

func TestProofProviderShouldRenewWithFreshRegisteredKeyProofsAndNoAmbientAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := bridge.Scope{TenantID: "tenant", ApplicationID: "app", EnvironmentID: "sandbox", OwnerResource: "organization:one"}
	var mu sync.Mutex
	nonces := map[string]bool{}
	client := &http.Client{Transport: proofRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.String() != "https://control.example.com/v1/development-connections/dvc_one/sessions" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("proof request changed route or leaked ambient authority")
		}
		var signed bridge.SignedMessage
		if decodeErr := json.NewDecoder(r.Body).Decode(&signed); decodeErr != nil {
			t.Error(decodeErr)
		}
		proof, verifyErr := VerifyConnectionProof(signed, "runtime-key", public, time.Now())
		if verifyErr != nil || proof.Scope != scope || proof.BindingID != "fnb_one" || proof.ConnectionID != "dvc_one" {
			t.Error("renewal lost registered identity", verifyErr)
		}
		mu.Lock()
		if nonces[proof.Nonce] {
			t.Error("proof nonce reused")
		}
		nonces[proof.Nonce] = true
		mu.Unlock()
		raw, _ := json.Marshal(Session{ConnectionID: "dvc_one", ConnectorURL: "wss://relay.example.com/v1/development-connections/dvc_one/connect", Credential: "connector-only", ExpiresAt: time.Now().Add(4 * time.Minute).UnixMicro()})
		return &http.Response{StatusCode: 201, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}, nil
	})}
	provider, err := NewProofSessionProvider(ProofSessionOptions{ControlURL: "https://control.example.com", EndpointURL: "https://relay.example.com/t/dvc_one", ConnectionID: "dvc_one", BindingID: "fnb_one", SigningKeyID: "runtime-key", SigningKey: private, Scope: scope, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	clear(private) // The provider must own the registered signing material copy.
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := provider(t.Context()); err != nil {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	if len(nonces) != 8 {
		t.Fatal("missing independent proof requests")
	}
}

func TestProofProviderShouldRejectRedirectsWrongRoutesMalformedAndOversizedAdmission(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"redirect", "denied", "wrong-route", "wrong-connection", "expired", "too-long", "extra-json", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			status := 201
			session := Session{ConnectionID: "dvc_one", ConnectorURL: "wss://relay.example.com/v1/development-connections/dvc_one/connect", Credential: "connector-only", ExpiresAt: time.Now().Add(4 * time.Minute).UnixMicro()}
			switch scenario {
			case "redirect":
				status = 307
			case "denied":
				status = 403
			case "wrong-route":
				session.ConnectorURL = "wss://other.example.com/v1/development-connections/dvc_one/connect"
			case "wrong-connection":
				session.ConnectionID = "dvc_other"
			case "expired":
				session.ExpiresAt = time.Now().Add(-time.Minute).UnixMicro()
			case "too-long":
				session.ExpiresAt = time.Now().Add(6 * time.Minute).UnixMicro()
			}
			raw, _ := json.Marshal(session)
			if scenario == "extra-json" {
				raw = append(raw, []byte(` {}`)...)
			}
			if scenario == "oversize" {
				raw = []byte(strings.Repeat(" ", 65537))
			}
			calls := 0
			provider, err := NewProofSessionProvider(ProofSessionOptions{ControlURL: "https://control.example.com", EndpointURL: "https://relay.example.com/t/dvc_one", ConnectionID: "dvc_one", BindingID: "fnb_one", SigningKeyID: "runtime-key", SigningKey: private, Scope: bridge.Scope{TenantID: "tenant", ApplicationID: "app", EnvironmentID: "sandbox", OwnerResource: "organization:one"}, HTTPClient: &http.Client{Transport: proofRoundTripper(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Header: http.Header{"Location": {"https://other.example.com"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider(t.Context())
			if err == nil || calls != 1 {
				t.Fatal("invalid admission accepted or redirected")
			}
			if scenario == "denied" && !errors.Is(err, bridge.ErrUnauthorized) {
				t.Fatal("permanent denial must stop reconnect", err)
			}
		})
	}
}
