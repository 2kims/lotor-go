// Package bridge implements the generic, authenticated function runtime contract.
// Application function implementations and durable storage are supplied by the caller.
package bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
)

const (
	ProtocolVersion = 1
	// Inline data includes application-level encryption/base64 envelopes. Wire
	// frames also carry base64 signatures and nested runtime identity proofs.
	MaximumInputBytes     = 4 << 20
	MaximumBodyBytes      = 16 << 20
	authorizationPurpose  = "lotor-function-authorization-v1\n"
	resultPurpose         = "lotor-function-result-v1\n"
	validationPurpose     = "lotor-function-validation-v1\n"
	resourceAccessPurpose = "lotor-function-resource-access-v1\n"
)

var (
	ErrInvalid        = errors.New("invalid function protocol")
	ErrUnauthorized   = errors.New("unauthorized function operation")
	ErrUnavailable    = errors.New("function dependency unavailable")
	ErrNotFound       = errors.New("function dependency not found")
	ErrConflict       = errors.New("function operation conflicts")
	ErrInProgress     = errors.New("function operation already reserved")
	ErrOutcomeUnknown = errors.New("function outcome unknown; preserve the invocation identity")
)

type Scope struct {
	TenantID      string `json:"tenant_id"`
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
	OwnerResource string `json:"owner_resource"`
}

type Function struct {
	Name               string `json:"name"`
	Version            string `json:"version"`
	InputSchemaDigest  string `json:"input_schema_digest"`
	OutputSchemaDigest string `json:"output_schema_digest"`
}

type Manifest struct {
	Functions       []Function `json:"functions"`
	ProtocolVersion int        `json:"protocol_version"`
}

type SignedMessage struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type ValidationRequest struct {
	Authorization SignedMessage `json:"authorization"`
}

type ResourceAccessRequest struct {
	Authorization  SignedMessage `json:"authorization"`
	Resource       string        `json:"resource"`
	Slot           string        `json:"slot"`
	PayloadVersion int64         `json:"payload_version"`
	UseCustody     bool          `json:"use_custody,omitempty"`
}

func SignResourceAccess(value ResourceAccessRequest, keyID string, key ed25519.PrivateKey) (SignedMessage, error) {
	return sign(value, resourceAccessPurpose, keyID, key)
}

func VerifyResourceAccess(message SignedMessage, key ed25519.PublicKey) (ResourceAccessRequest, error) {
	var value ResourceAccessRequest
	raw, err := verify(message, resourceAccessPurpose, key)
	if err != nil || strictJSON(raw, &value) != nil {
		return ResourceAccessRequest{}, ErrUnauthorized
	}
	return value, nil
}

func SignValidation(value ValidationRequest, keyID string, key ed25519.PrivateKey) (SignedMessage, error) {
	return sign(value, validationPurpose, keyID, key)
}

func VerifyValidation(message SignedMessage, key ed25519.PublicKey) (ValidationRequest, error) {
	var value ValidationRequest
	raw, err := verify(message, validationPurpose, key)
	if err != nil || strictJSON(raw, &value) != nil {
		return ValidationRequest{}, ErrUnauthorized
	}
	return value, nil
}

type Authorization struct {
	Function        *Function       `json:"function,omitempty"`
	Scope           Scope           `json:"scope"`
	Kind            string          `json:"kind"`
	Issuer          string          `json:"issuer"`
	Audience        string          `json:"audience"`
	BindingID       string          `json:"binding_id"`
	PolicyDigest    string          `json:"policy_digest,omitempty"`
	ManifestDigest  string          `json:"manifest_digest"`
	InputDigest     string          `json:"input_digest,omitempty"`
	ID              string          `json:"id"`
	Nonce           string          `json:"nonce,omitempty"`
	Principal       string          `json:"principal,omitempty"`
	Resources       []string        `json:"resources,omitempty"`
	Capabilities    []string        `json:"capabilities,omitempty"`
	Input           json.RawMessage `json:"input,omitempty"`
	ExpiresAt       int64           `json:"expires_at"`
	IssuedAt        int64           `json:"issued_at"`
	ProtocolVersion int             `json:"protocol_version"`
	BindingRevision int64           `json:"binding_revision"`
}

type Result struct {
	ID                  string          `json:"id"`
	BindingID           string          `json:"binding_id"`
	ManifestDigest      string          `json:"manifest_digest"`
	AuthorizationDigest string          `json:"authorization_digest"`
	Kind                string          `json:"kind"`
	Nonce               string          `json:"nonce,omitempty"`
	ErrorCode           string          `json:"error_code,omitempty"`
	Output              json.RawMessage `json:"output,omitempty"`
	ProtocolVersion     int             `json:"protocol_version"`
	BindingRevision     int64           `json:"binding_revision"`
	CompletedAt         int64           `json:"completed_at"`
}

func Digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// ManifestDigest sorts a copy; function registration order is not semantic.
func ManifestDigest(manifest Manifest) (string, error) {
	if manifest.ProtocolVersion != ProtocolVersion || len(manifest.Functions) < 1 || len(manifest.Functions) > 64 {
		return "", ErrInvalid
	}
	manifest.Functions = append([]Function(nil), manifest.Functions...)
	sort.Slice(manifest.Functions, func(i, j int) bool {
		a, b := manifest.Functions[i], manifest.Functions[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	for i, function := range manifest.Functions {
		if !identifier(function.Name, 128) || !identifier(function.Version, 128) || !isDigest(function.InputSchemaDigest) || !isDigest(function.OutputSchemaDigest) {
			return "", ErrInvalid
		}
		if i > 0 && function.Name == manifest.Functions[i-1].Name && function.Version == manifest.Functions[i-1].Version {
			return "", ErrInvalid
		}
	}
	functions, err := json.Marshal(manifest.Functions)
	if err != nil {
		return "", ErrInvalid
	}
	// Hash the protocol's fixed field order, not the Go struct's memory layout.
	// Keep these bytes stable when reordering fields for alignment. A protocol
	// change needs an explicitly versioned canonical encoding.
	encoded := append([]byte(`{"protocol_version":`+strconv.Itoa(ProtocolVersion)+`,"functions":`), functions...)
	encoded = append(encoded, '}')
	return Digest(encoded), nil
}

func SignAuthorization(value Authorization, keyID string, key ed25519.PrivateKey) (SignedMessage, error) {
	// encoding/json compacts embedded RawMessage values. Bind the digest to
	// exactly those transmitted bytes, not the caller's formatting whitespace.
	if len(value.Input) != 0 {
		if len(value.Input) > MaximumInputBytes || value.InputDigest != Digest(value.Input) {
			return SignedMessage{}, ErrInvalid
		}
		compact, err := json.Marshal(value.Input)
		if err != nil || len(compact) > MaximumInputBytes {
			return SignedMessage{}, ErrInvalid
		}
		value.Input = append(json.RawMessage(nil), compact...)
		value.InputDigest = Digest(value.Input)
	}
	return sign(value, authorizationPurpose, keyID, key)
}

func VerifyAuthorization(message SignedMessage, key ed25519.PublicKey) (Authorization, []byte, error) {
	var value Authorization
	raw, err := verify(message, authorizationPurpose, key)
	if err != nil || strictJSON(raw, &value) != nil {
		return Authorization{}, nil, ErrUnauthorized
	}
	return value, raw, nil
}

func SignResult(value Result, keyID string, key ed25519.PrivateKey) (SignedMessage, error) {
	if len(value.Output) > MaximumInputBytes {
		return SignedMessage{}, ErrInvalid
	}
	if len(value.Output) != 0 {
		canonical, err := json.Marshal(value.Output)
		if err != nil || len(canonical) > MaximumInputBytes {
			return SignedMessage{}, ErrInvalid
		}
		value.Output = canonical
	}
	return sign(value, resultPurpose, keyID, key)
}

// VerifyResult checks exact invocation binding. Callers must also ensure the
// supplied authorization is the currently authorized operation they initiated.
func VerifyResult(message SignedMessage, key ed25519.PublicKey, authorization Authorization, rawAuthorization []byte) (Result, error) {
	var value Result
	raw, err := verify(message, resultPurpose, key)
	if err != nil || strictJSON(raw, &value) != nil || len(value.Output) > MaximumInputBytes {
		return Result{}, ErrUnauthorized
	}
	if value.ProtocolVersion != ProtocolVersion || value.ID != authorization.ID || value.Kind != authorization.Kind || value.BindingID != authorization.BindingID || value.BindingRevision != authorization.BindingRevision || value.ManifestDigest != authorization.ManifestDigest || value.AuthorizationDigest != Digest(rawAuthorization) || value.Nonce != authorization.Nonce {
		return Result{}, ErrUnauthorized
	}
	return value, nil
}

func sign(value any, purpose, keyID string, key ed25519.PrivateKey) (SignedMessage, error) {
	if !identifier(keyID, 256) || len(key) != ed25519.PrivateKeySize {
		return SignedMessage{}, ErrInvalid
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaximumBodyBytes/2 {
		return SignedMessage{}, ErrInvalid
	}
	signature := ed25519.Sign(key, append([]byte(purpose), raw...))
	return SignedMessage{KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func verify(message SignedMessage, purpose string, key ed25519.PublicKey) ([]byte, error) {
	if !identifier(message.KeyID, 256) || len(key) != ed25519.PublicKeySize || len(message.Signature) != base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize) || len(message.Payload) > base64.RawURLEncoding.EncodedLen(MaximumBodyBytes/2) {
		return nil, ErrUnauthorized
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(message.Payload)
	if err != nil {
		return nil, ErrUnauthorized
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(message.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(purpose), raw...), signature) {
		return nil, ErrUnauthorized
	}
	return raw, nil
}

func strictJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrInvalid
	}
	if decoder.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}

func identifier(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for _, c := range value {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

func isDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
