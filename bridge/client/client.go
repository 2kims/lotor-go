// Package client invokes a verified function using only the signed grant.
// It adds no application or user authentication headers; callers control the
// function input. Both service and Lambda deployments use the same contract.
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/2kims/lotor-go/bridge"
	"github.com/2kims/lotor-go/bridge/transport"
)

type Dispatcher interface {
	Send(context.Context, string, string, bridge.SignedMessage) (bridge.SignedMessage, error)
	SendMutualTLS(context.Context, string, string, bridge.SignedMessage) (bridge.SignedMessage, error)
	MutualTLSConfigured() bool
}

type Options struct {
	TransportOptions   transport.Options
	Dispatcher         Dispatcher
	Now                func() time.Time
	TrustedKeys        map[string]ed25519.PublicKey
	Scope              bridge.Scope
	ManifestDigest     string
	EndpointURL        string
	Issuer             string
	SigningKeyID       string
	Audience           string
	BindingID          string
	AuthenticationMode string
	SigningPublicKey   ed25519.PublicKey
	BindingRevision    int64
}

type Client struct {
	dispatcher Dispatcher
	options    Options
}

func New(options Options) (*Client, error) {
	if _, err := transport.ValidateEndpoint(options.EndpointURL); err != nil {
		return nil, bridge.ErrInvalid
	}
	for _, value := range []string{options.BindingID, options.Audience, options.Issuer, options.SigningKeyID, options.Scope.TenantID, options.Scope.ApplicationID, options.Scope.EnvironmentID, options.Scope.OwnerResource} {
		if !identifier(value, 256) {
			return nil, bridge.ErrInvalid
		}
	}
	if options.BindingRevision < 1 || !digest(options.ManifestDigest) || len(options.SigningPublicKey) != ed25519.PublicKeySize || len(options.TrustedKeys) == 0 || options.AuthenticationMode != "signed_https" && options.AuthenticationMode != "mtls" {
		return nil, bridge.ErrInvalid
	}
	keys := make(map[string]ed25519.PublicKey, len(options.TrustedKeys))
	for keyID, key := range options.TrustedKeys {
		if !identifier(keyID, 256) || len(key) != ed25519.PublicKeySize {
			return nil, bridge.ErrInvalid
		}
		keys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	options.TrustedKeys = keys
	options.SigningPublicKey = append(ed25519.PublicKey(nil), options.SigningPublicKey...)
	dispatcher := options.Dispatcher
	if dispatcher == nil {
		var err error
		dispatcher, err = transport.New(options.TransportOptions)
		if err != nil {
			return nil, err
		}
	}
	if options.AuthenticationMode == "mtls" && !dispatcher.MutualTLSConfigured() {
		return nil, bridge.ErrInvalid
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Client{options: options, dispatcher: dispatcher}, nil
}

// Invoke performs no automatic retries or fallback. Once dispatch begins, a
// timeout, invalid response or signed handler failure cannot prove no effect
// occurred. Retry only with the same durable invocation identity and unchanged
// semantic content, obtaining a renewed grant from Control when necessary.
func (client *Client) Invoke(ctx context.Context, message bridge.SignedMessage) (bridge.Result, error) {
	key, ok := client.options.TrustedKeys[message.KeyID]
	if !ok {
		return bridge.Result{}, bridge.ErrUnauthorized
	}
	authorization, raw, err := bridge.VerifyAuthorization(message, key)
	if err != nil || !client.validGrant(authorization) {
		return bridge.Result{}, bridge.ErrUnauthorized
	}
	if ctx.Err() != nil {
		return bridge.Result{}, bridge.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(authorization.ExpiresAt, 0))
	defer cancel()
	var response bridge.SignedMessage
	if client.options.AuthenticationMode == "mtls" {
		response, err = client.dispatcher.SendMutualTLS(ctx, client.options.EndpointURL, "invoke", message)
	} else {
		response, err = client.dispatcher.Send(ctx, client.options.EndpointURL, "invoke", message)
	}
	if err != nil || response.KeyID != client.options.SigningKeyID {
		return bridge.Result{}, bridge.ErrOutcomeUnknown
	}
	result, err := bridge.VerifyResult(response, client.options.SigningPublicKey, authorization, raw)
	if err != nil || result.CompletedAt <= 0 || result.CompletedAt > client.options.Now().Unix()+5 {
		return bridge.Result{}, bridge.ErrOutcomeUnknown
	}
	if result.ErrorCode != "" || !json.Valid(result.Output) {
		return result, bridge.ErrOutcomeUnknown
	}
	return result, nil
}

func (client *Client) CloseIdleConnections() {
	if closer, ok := client.dispatcher.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (client *Client) validGrant(authorization bridge.Authorization) bool {
	if len(authorization.Input) > bridge.MaximumInputBytes {
		return false
	}
	options := client.options
	now := options.Now().Unix()
	if authorization.ProtocolVersion != bridge.ProtocolVersion || authorization.Kind != "invocation" || authorization.Scope != options.Scope || authorization.BindingID != options.BindingID || authorization.BindingRevision != options.BindingRevision || authorization.Audience != options.Audience || authorization.ManifestDigest != options.ManifestDigest || authorization.Issuer != options.Issuer || !identifier(authorization.ID, 256) || !identifier(authorization.Principal, 256) || authorization.Nonce != "" || authorization.Function == nil || authorization.IssuedAt <= 0 || authorization.IssuedAt > now || authorization.ExpiresAt <= now || authorization.ExpiresAt <= authorization.IssuedAt || authorization.ExpiresAt-authorization.IssuedAt > 300 || !json.Valid(authorization.Input) || authorization.InputDigest != bridge.Digest(authorization.Input) || authorization.PolicyDigest != "" && !digest(authorization.PolicyDigest) {
		return false
	}
	function := authorization.Function
	if !identifier(function.Name, 128) || !identifier(function.Version, 128) || !digest(function.InputSchemaDigest) || !digest(function.OutputSchemaDigest) || len(authorization.Resources) > 128 || len(authorization.Capabilities) > 64 {
		return false
	}
	for _, value := range append(append([]string(nil), authorization.Resources...), authorization.Capabilities...) {
		if !identifier(value, 256) {
			return false
		}
	}
	return true
}

func identifier(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.IndexFunc(value, func(character rune) bool { return character <= 32 || character >= 127 }) == -1
}

func digest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
