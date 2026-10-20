package development

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/2kims/lotor-go/bridge"
)

const connectionPurpose = "lotor-development-connect-v1\n"

// ConnectionProof authenticates a registered bridge signing identity, not an
// application secret or the original business caller. It can obtain only a
// connector session for that binding's exact development endpoint.
type ConnectionProof struct {
	Scope        bridge.Scope `json:"scope"`
	ConnectionID string       `json:"connection_id"`
	BindingID    string       `json:"binding_id"`
	Nonce        string       `json:"nonce"`
	IssuedAt     int64        `json:"issued_at"`
	ExpiresAt    int64        `json:"expires_at"`
}

func SignConnectionProof(proof ConnectionProof, keyID string, key ed25519.PrivateKey) (bridge.SignedMessage, error) {
	if len(key) != ed25519.PrivateKeySize || !validProof(proof) || keyID == "" || len(keyID) > 256 {
		return bridge.SignedMessage{}, bridge.ErrInvalid
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return bridge.SignedMessage{}, bridge.ErrInvalid
	}
	return bridge.SignedMessage{KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(connectionPurpose), raw...)))}, nil
}

// UnverifiedConnectionProof is an indexed public-key lookup hint only. Never
// establish identity from it until VerifyConnectionProof succeeds.
func UnverifiedConnectionProof(message bridge.SignedMessage) (ConnectionProof, error) {
	if len(message.Payload) > 8192 {
		return ConnectionProof{}, bridge.ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(message.Payload)
	if err != nil {
		return ConnectionProof{}, bridge.ErrUnauthorized
	}
	var proof ConnectionProof
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || decoder.Decode(new(any)) != io.EOF || !validProof(proof) {
		return ConnectionProof{}, bridge.ErrUnauthorized
	}
	return proof, nil
}

func VerifyConnectionProof(message bridge.SignedMessage, keyID string, key ed25519.PublicKey, now time.Time) (ConnectionProof, error) {
	proof, err := UnverifiedConnectionProof(message)
	if err != nil || len(key) != ed25519.PublicKeySize || message.KeyID != keyID || proof.IssuedAt > now.Unix() || proof.ExpiresAt <= now.Unix() {
		return ConnectionProof{}, bridge.ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(message.Payload)
	if err != nil {
		return ConnectionProof{}, bridge.ErrUnauthorized
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(message.Signature)
	if err != nil || !ed25519.Verify(key, append([]byte(connectionPurpose), raw...), signature) {
		return ConnectionProof{}, bridge.ErrUnauthorized
	}
	return proof, nil
}

func validProof(proof ConnectionProof) bool {
	if !connectionIdentifier(proof.ConnectionID) {
		return false
	}
	for _, value := range []string{proof.Scope.TenantID, proof.Scope.ApplicationID, proof.Scope.EnvironmentID, proof.Scope.OwnerResource, proof.ConnectionID, proof.BindingID, proof.Nonce} {
		if value == "" || len(value) > 256 || strings.IndexFunc(value, func(c rune) bool { return c <= 32 || c >= 127 }) >= 0 {
			return false
		}
	}
	return proof.IssuedAt > 0 && proof.ExpiresAt > proof.IssuedAt && proof.ExpiresAt-proof.IssuedAt <= 30
}

func connectionIdentifier(value string) bool {
	if !strings.HasPrefix(value, "dvc_") || len(value) <= 4 || len(value) > 256 {
		return false
	}
	for _, c := range value[4:] {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
