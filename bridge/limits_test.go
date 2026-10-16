package bridge

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestItShouldCarryProtectedAvaultBodiesAndNestedProofsWithoutTruncation(t *testing.T) {
	f := setup(t)
	f.auth.Input = json.RawMessage(`{"protected_request":"` + strings.Repeat("x", 3<<20) + `"}`)
	f.auth.InputDigest = Digest(f.auth.Input)
	signed, err := SignAuthorization(f.auth, "issuer-key", f.issuer)
	if err != nil {
		t.Fatalf("existing protected request limit does not fit: %v", err)
	}
	validation, err := SignValidation(ValidationRequest{Authorization: signed}, f.config.SigningKeyID, f.config.SigningKey)
	if err != nil {
		t.Fatalf("current-authorization proof does not fit: %v", err)
	}
	verified, err := VerifyValidation(validation, f.config.SigningKey.Public().(ed25519.PublicKey))
	if err != nil || verified.Authorization != signed {
		t.Fatal("nested proof changed authorization")
	}
	access, err := SignResourceAccess(ResourceAccessRequest{Authorization: signed, Resource: "credential:one", Slot: "provider_credential", PayloadVersion: 1}, f.config.SigningKeyID, f.config.SigningKey)
	if err != nil {
		t.Fatalf("scoped payload proof does not fit: %v", err)
	}
	for _, message := range []SignedMessage{signed, validation, access} {
		wire, err := json.Marshal(message)
		if err != nil || len(wire) > MaximumBodyBytes {
			t.Fatal("valid proof exceeds HTTP frame bound")
		}
	}
	response, result := f.call(t, f.auth, "/v1/functions/invoke")
	if response.Code != 200 || result.ErrorCode != "" || string(result.Output) != string(f.auth.Input) || f.calls != 1 {
		t.Fatalf("large invocation failed: status=%d error=%s calls=%d", response.Code, result.ErrorCode, f.calls)
	}
}

func TestItShouldRejectInlinePayloadsAboveFourMiBBeforeDispatch(t *testing.T) {
	f := setup(t)
	f.auth.Input = json.RawMessage(`"` + strings.Repeat("x", 4<<20) + `"`)
	f.auth.InputDigest = Digest(f.auth.Input)
	if _, err := SignAuthorization(f.auth, "issuer-key", f.issuer); err == nil {
		t.Fatal("accepted oversized input")
	}
	if _, err := SignResult(Result{Output: f.auth.Input}, f.config.SigningKeyID, f.config.SigningKey); err == nil {
		t.Fatal("accepted oversized output")
	}
	// A trusted-key signature cannot bypass the receiver's independent bound.
	response, _ := f.call(t, f.auth, "/v1/functions/invoke")
	if response.Code != 401 || f.calls != 0 || len(f.store.hashes) != 0 {
		t.Fatal("oversized input reached reservation or execution")
	}
	result := Result{ProtocolVersion: 1, ID: f.auth.ID, Kind: f.auth.Kind, BindingID: f.auth.BindingID, BindingRevision: f.auth.BindingRevision, ManifestDigest: f.auth.ManifestDigest, AuthorizationDigest: Digest(nil), Output: f.auth.Input}
	signed, err := sign(result, resultPurpose, f.config.SigningKeyID, f.config.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResult(signed, f.config.SigningKey.Public().(ed25519.PublicKey), f.auth, nil); err == nil {
		t.Fatal("accepted signed oversized result")
	}
}
