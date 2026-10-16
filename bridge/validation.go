package bridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

type ControlValidatorOptions struct {
	BaseURL      string
	HTTPClient   *http.Client
	SigningKeyID string
	SigningKey   ed25519.PrivateKey
}

// ControlValidator performs current-permission checks using only the registered
// runtime identity. It never holds an application secret or user credential.
type ControlValidator struct {
	baseURL string
	client  *http.Client
	keyID   string
	key     ed25519.PrivateKey
}

func NewControlValidator(options ControlValidatorOptions) (*ControlValidator, error) {
	base, err := controlBaseURL(options.BaseURL)
	if err != nil || !identifier(options.SigningKeyID, 256) || len(options.SigningKey) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(options.SigningKey[:ed25519.SeedSize]), options.SigningKey) {
		return nil, ErrInvalid
	}
	return &ControlValidator{baseURL: base, client: isolatedControlClient(options.HTTPClient), keyID: options.SigningKeyID, key: append(ed25519.PrivateKey(nil), options.SigningKey...)}, nil
}

// Authorize is used as Config.Authorize, after the SDK verifies the original
// Control signature and static scope. Ownership challenges have no execution
// effects and are consumed by Control's separate one-use verification worker.
func (validator *ControlValidator) Authorize(ctx context.Context, authorization Authorization, original SignedMessage) error {
	if authorization.Kind == "challenge" {
		return nil
	}
	if authorization.Kind != "invocation" || !identifier(authorization.BindingID, 256) {
		return ErrUnauthorized
	}
	proof, err := SignValidation(ValidationRequest{Authorization: original}, validator.keyID, validator.key)
	if err != nil {
		return ErrUnauthorized
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, validator.baseURL+"/v1/function-bindings/"+url.PathEscape(authorization.BindingID)+"/authorizations/validate", bytes.NewReader(body))
	if err != nil {
		return ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := validator.client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		return nil
	}
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	return ErrUnavailable
}
