package bridge

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestWorkloadPolicyMustBeRevalidatedBeforeReservationAndReplay(t *testing.T) {
	f := setup(t)
	var denied atomic.Bool
	var checks atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		checks.Add(1)
		var proof SignedMessage
		if json.NewDecoder(request.Body).Decode(&proof) != nil {
			t.Error("missing proof")
			w.WriteHeader(400)
			return
		}
		validation, err := VerifyValidation(proof, f.config.SigningKey.Public().(ed25519.PublicKey))
		if err != nil {
			t.Error("invalid runtime proof")
			w.WriteHeader(403)
			return
		}
		grant, _, err := VerifyAuthorization(validation.Authorization, f.issuer.Public().(ed25519.PublicKey))
		if err != nil {
			t.Error("invalid original grant")
			w.WriteHeader(403)
			return
		}
		if denied.Load() {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(WorkloadContext{InvocationID: grant.ID, BindingID: grant.BindingID, Scope: grant.Scope, Principal: grant.Principal, AuthorityKind: "subject"})
	}))
	defer server.Close()
	client, err := NewResourceClient(ControlValidatorOptions{BaseURL: server.URL, HTTPClient: server.Client(), SigningKeyID: f.config.SigningKeyID, SigningKey: f.config.SigningKey})
	if err != nil {
		t.Fatal(err)
	}
	f.config.Authorize = func(ctx context.Context, grant Authorization, signed SignedMessage) error {
		state, original, ok := InvocationFromContext(ctx)
		if !ok || state.ID != grant.ID || original != signed {
			t.Error("verified original invocation unavailable before replay")
			return ErrUnauthorized
		}
		_, contextErr := client.WorkloadContext(ctx)
		return contextErr
	}
	f.runtime, err = NewRuntime(f.config)
	if err != nil {
		t.Fatal(err)
	}
	foreign := f.auth
	foreign.Scope.OwnerResource = "organization:foreign"
	response, _ := f.call(t, foreign, "/v1/functions/invoke")
	if response.Code != 401 || checks.Load() != 0 {
		t.Fatal("foreign scope reached context resolution")
	}
	denied.Store(true)
	response, _ = f.call(t, f.auth, "/v1/functions/invoke")
	if response.Code != 401 || len(f.store.hashes) != 0 || f.calls != 0 {
		t.Fatal("rejection reserved or executed work")
	}
	denied.Store(false)
	for range 2 {
		response, _ = f.call(t, f.auth, "/v1/functions/invoke")
		if response.Code != 200 || f.calls != 1 {
			t.Fatal("valid replay failed or repeated execution")
		}
	}
	denied.Store(true)
	response, _ = f.call(t, f.auth, "/v1/functions/invoke")
	if response.Code != 401 || f.calls != 1 || checks.Load() != 4 {
		t.Fatal("cached result bypassed fresh policy check")
	}
}
