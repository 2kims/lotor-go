package lotorhttp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/2kims/lotor-go/bridge"
	bridgeclient "github.com/2kims/lotor-go/bridge/client"
	"github.com/2kims/lotor-go/bridge/transport"
)

// FunctionBindingRegistration contains public identity and protocol metadata.
// Never supply a private signing key or application/provider secret here.
type FunctionBindingRegistration struct {
	EndpointURL         string          `json:"endpoint_url"`
	SigningKeyID        string          `json:"signing_key_id"`
	SigningPublicKey    string          `json:"signing_public_key"`
	EncryptionPublicKey string          `json:"encryption_public_key,omitempty"`
	AuthenticationMode  string          `json:"authentication_mode"`
	Manifest            bridge.Manifest `json:"manifest"`
}

type FunctionBindingChallenge struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	ExpiresAt int64  `json:"expires_at"`
}

// FunctionBinding timestamps are Unix microseconds. Ready means endpoint
// ownership/protocol verification, not permission to access a resource or key.
type FunctionBinding struct {
	Challenge           *FunctionBindingChallenge `json:"challenge,omitempty"`
	VerifiedAt          *int64                    `json:"verified_at,omitempty"`
	Scope               bridge.Scope              `json:"scope"`
	SigningPublicKey    string                    `json:"signing_public_key"`
	Audience            string                    `json:"audience"`
	Status              string                    `json:"status"`
	SigningKeyID        string                    `json:"signing_key_id"`
	ID                  string                    `json:"id"`
	EncryptionPublicKey string                    `json:"encryption_public_key,omitempty"`
	AuthenticationMode  string                    `json:"authentication_mode"`
	ManifestDigest      string                    `json:"manifest_digest"`
	EndpointURL         string                    `json:"endpoint_url"`
	Resource            string                    `json:"resource"`
	Manifest            bridge.Manifest           `json:"manifest"`
	Revision            int64                     `json:"revision"`
	CreatedAt           int64                     `json:"created_at"`
}

type FunctionBindingList struct {
	NextCursor *string           `json:"next_cursor"`
	Bindings   []FunctionBinding `json:"bindings"`
}

type FunctionInvocationInput struct {
	Function                bridge.Function `json:"function"`
	InputDigest             string          `json:"input_digest"`
	PolicyDigest            string          `json:"policy_digest,omitempty"`
	Resources               []string        `json:"resources"`
	Capabilities            []string        `json:"capabilities"`
	Input                   json.RawMessage `json:"input"`
	ExpectedBindingRevision int64           `json:"expected_binding_revision"`
}

type FunctionInvocationAuthorization struct {
	EndpointURL        string               `json:"endpoint_url"`
	AuthenticationMode string               `json:"authentication_mode"`
	SigningKeyID       string               `json:"signing_key_id"`
	SigningPublicKey   string               `json:"signing_public_key"`
	Authorization      bridge.SignedMessage `json:"authorization"`
	ExpiresAt          int64                `json:"expires_at"`
}

// NewClient builds the caller from this trusted Control response and the keys
// discovered at the configured Control origin. No binding-management permission
// or application secret is needed by the returned invocation client.
func (grant FunctionInvocationAuthorization) NewClient(keys bridge.ControlKeys, network transport.Options) (*bridgeclient.Client, error) {
	key, ok := keys.Keys[grant.Authorization.KeyID]
	if !ok {
		return nil, bridge.ErrUnauthorized
	}
	authorization, _, err := bridge.VerifyAuthorization(grant.Authorization, key)
	if err != nil {
		return nil, bridge.ErrUnauthorized
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(grant.SigningPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, bridge.ErrInvalid
	}
	return bridgeclient.New(bridgeclient.Options{EndpointURL: grant.EndpointURL, AuthenticationMode: grant.AuthenticationMode, BindingID: authorization.BindingID, Audience: authorization.Audience, BindingRevision: authorization.BindingRevision, Scope: authorization.Scope, ManifestDigest: authorization.ManifestDigest, Issuer: keys.Issuer, TrustedKeys: keys.Keys, SigningKeyID: grant.SigningKeyID, SigningPublicKey: ed25519.PublicKey(public), TransportOptions: network})
}

// AuthorizeFunctionInvocation obtains a short-lived grant without executing the
// function. Use a delegated user/workload client and preserve the idempotency key
// across retries. The application secret and principal token go only to Control,
// never to the returned customer function endpoint.
func (c *ControlClient) AuthorizeFunctionInvocation(ctx context.Context, resource, bindingID string, input FunctionInvocationInput, key string) (FunctionInvocationAuthorization, error) {
	if c.userToken == "" {
		return FunctionInvocationAuthorization{}, errors.New("function invocation requires ForUser delegation")
	}
	if len(input.Input) == 0 || len(input.Input) > bridge.MaximumInputBytes || input.InputDigest != bridge.Digest(input.Input) {
		return FunctionInvocationAuthorization{}, bridge.ErrInvalid
	}
	canonical, err := json.Marshal(input.Input)
	if err != nil || len(canonical) > bridge.MaximumInputBytes {
		return FunctionInvocationAuthorization{}, bridge.ErrInvalid
	}
	input.Input = canonical
	input.InputDigest = bridge.Digest(canonical)
	var out FunctionInvocationAuthorization
	_, err = c.requestHeadersLimit(ctx, http.MethodPost, functionBindingPath(resource)+"/"+url.PathEscape(requiredControl(bindingID, "binding ID"))+"/invocations", key, nil, input, &out, bridge.MaximumBodyBytes)
	if err == nil && !matchesFunctionGrant(out, requiredControl(resource, "resource"), requiredControl(bindingID, "binding ID"), input) {
		return FunctionInvocationAuthorization{}, bridge.ErrUnauthorized
	}
	return out, err
}

// This checks response/request correspondence over the authenticated Control
// channel. NewClient independently verifies the Control signature before use.
func matchesFunctionGrant(grant FunctionInvocationAuthorization, resource, bindingID string, input FunctionInvocationInput) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(grant.Authorization.Payload)
	if err != nil {
		return false
	}
	var authorization bridge.Authorization
	if json.Unmarshal(raw, &authorization) != nil {
		return false
	}
	return authorization.ProtocolVersion == bridge.ProtocolVersion && authorization.Kind == "invocation" && authorization.BindingID == bindingID && authorization.Audience == bindingID && authorization.Scope.OwnerResource == resource && authorization.BindingRevision == input.ExpectedBindingRevision && authorization.Function != nil && *authorization.Function == input.Function && authorization.InputDigest == input.InputDigest && bridge.Digest(authorization.Input) == input.InputDigest && authorization.PolicyDigest == input.PolicyDigest && slices.Equal(authorization.Resources, input.Resources) && slices.Equal(authorization.Capabilities, input.Capabilities) && authorization.ExpiresAt == grant.ExpiresAt
}

func functionBindingPath(resource string) string {
	return "/resources/" + url.PathEscape(requiredControl(resource, "resource")) + "/function-bindings"
}

// RegisterFunctionBinding requires a delegated resource manager (ForUser).
// Registration creates a pending binding; it does not call the endpoint.
func (c *ControlClient) RegisterFunctionBinding(ctx context.Context, resource string, input FunctionBindingRegistration, key string) (FunctionBinding, error) {
	var out FunctionBinding
	err := c.request(ctx, http.MethodPost, functionBindingPath(resource), key, input, &out)
	return out, err
}

func (c *ControlClient) FunctionBindings(ctx context.Context, resource, cursor string, limit int) (FunctionBindingList, error) {
	var out FunctionBindingList
	err := c.request(ctx, http.MethodGet, functionBindingPath(resource)+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) FunctionBinding(ctx context.Context, resource, bindingID string) (FunctionBinding, error) {
	var out FunctionBinding
	err := c.request(ctx, http.MethodGet, functionBindingPath(resource)+"/"+url.PathEscape(requiredControl(bindingID, "binding ID")), "", nil, &out)
	return out, err
}

// VerifyFunctionBinding queues verification. Inspect FunctionBinding for its
// eventual outcome; an accepted request does not mean the binding is ready.
func (c *ControlClient) VerifyFunctionBinding(ctx context.Context, resource, bindingID string) (FunctionBinding, error) {
	var out FunctionBinding
	err := c.request(ctx, http.MethodPost, functionBindingPath(resource)+"/"+url.PathEscape(requiredControl(bindingID, "binding ID"))+"/verify", "", nil, &out)
	return out, err
}

// RevokeFunctionBinding invalidates pending verification without deleting keys
// or selecting another custody provider.
func (c *ControlClient) RevokeFunctionBinding(ctx context.Context, resource, bindingID string) error {
	return c.request(ctx, http.MethodDelete, functionBindingPath(resource)+"/"+url.PathEscape(requiredControl(bindingID, "binding ID")), "", nil, nil)
}
