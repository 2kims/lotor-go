package development

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/2kims/lotor-go/bridge"
	"github.com/2kims/lotor-go/bridge/transport"
)

type ProofSessionOptions struct {
	HTTPClient   *http.Client
	Scope        bridge.Scope
	ControlURL   string
	EndpointURL  string
	ConnectionID string
	BindingID    string
	SigningKeyID string
	SigningKey   ed25519.PrivateKey
}

// NewProofSessionProvider reconnects using the existing registered bridge key.
// No user session, application secret or separate device key is persisted.
func NewProofSessionProvider(options ProofSessionOptions) (SessionProvider, error) {
	control, err := transport.ValidateEndpoint(options.ControlURL)
	if err != nil {
		return nil, bridge.ErrInvalid
	}
	endpoint, err := transport.ValidateEndpoint(options.EndpointURL)
	if err != nil || options.ConnectionID == "" || endpoint.Path != "/t/"+options.ConnectionID || len(options.SigningKey) != ed25519.PrivateKeySize {
		return nil, bridge.ErrInvalid
	}
	proof := ConnectionProof{Scope: options.Scope, ConnectionID: options.ConnectionID, BindingID: options.BindingID, Nonce: "validate", IssuedAt: 1, ExpiresAt: 2}
	if !validProof(proof) || options.SigningKeyID == "" {
		return nil, bridge.ErrInvalid
	}
	options.SigningKey = append(ed25519.PrivateKey(nil), options.SigningKey...)
	client := http.DefaultClient
	if options.HTTPClient != nil {
		client = options.HTTPClient
	}
	isolated := *client
	isolated.Jar = nil
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	requestURL := strings.TrimRight(control.String(), "/") + "/v1/development-connections/" + options.ConnectionID + "/sessions"
	expectedConnector := "wss://" + endpoint.Host + "/v1/development-connections/" + options.ConnectionID + "/connect"
	return func(ctx context.Context) (Session, error) {
		current := proof
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return Session{}, bridge.ErrUnavailable
		}
		now := time.Now()
		current.Nonce, current.IssuedAt, current.ExpiresAt = hex.EncodeToString(nonce[:]), now.Unix(), now.Add(30*time.Second).Unix()
		signed, err := SignConnectionProof(current, options.SigningKeyID, options.SigningKey)
		if err != nil {
			return Session{}, err
		}
		raw, err := json.Marshal(signed)
		if err != nil {
			return Session{}, bridge.ErrInvalid
		}
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewReader(raw))
		if err != nil {
			return Session{}, bridge.ErrInvalid
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := isolated.Do(request)
		if err != nil {
			return Session{}, bridge.ErrUnavailable
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return Session{}, bridge.ErrUnauthorized
		}
		if response.StatusCode != 201 {
			return Session{}, bridge.ErrUnavailable
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(body) > 65536 {
			return Session{}, bridge.ErrUnavailable
		}
		var session Session
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&session) != nil || decoder.Decode(new(any)) != io.EOF || session.ConnectionID != options.ConnectionID || session.ConnectorURL != expectedConnector || !validSession(session) {
			return Session{}, bridge.ErrUnauthorized
		}
		return session, nil
	}, nil
}
