package lotorhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	// ErrGatewayAssertionRejected is returned for every untrusted, malformed,
	// expired, or request-mismatched assertion. Callers should not expose its
	// wrapped diagnostic to an untrusted client.
	ErrGatewayAssertionRejected = errors.New("gateway assertion rejected")
	// ErrGatewayReplayUnavailable means a replay-ineligible request could not
	// be checked against the configured one-time store.
	ErrGatewayReplayUnavailable = errors.New("gateway assertion replay check unavailable")
)

// GatewayAssertionClaims is the minimal signed identity and routing context
// emitted by a Lotor application gateway. It contains no bearer, runtime
// credential, email, encryption key, or application payload.
//
//nolint:govet // Field order mirrors the canonical gateway assertion JSON contract.
type GatewayAssertionClaims struct {
	Issuer                 string `json:"iss"`
	KeyID                  string `json:"kid"`
	Audience               string `json:"aud"`
	Subject                string `json:"sub,omitempty"`
	SessionIDHash          string `json:"sid_hash,omitempty"`
	TenantID               string `json:"tenant_id"`
	ApplicationID          string `json:"application_id"`
	EnvironmentID          string `json:"environment_id"`
	BindingID              string `json:"binding_id"`
	RouteID                string `json:"route_id"`
	RoutePin               string `json:"route_pin"`
	GatewayPlacementID     string `json:"gateway_placement_id"`
	GatewayOwnershipEpoch  int64  `json:"gateway_ownership_epoch"`
	RuntimePlacementID     string `json:"runtime_placement_id"`
	RuntimeOwnershipEpoch  int64  `json:"runtime_ownership_epoch"`
	Operation              string `json:"operation,omitempty"`
	Method                 string `json:"method"`
	Path                   string `json:"path"`
	RequestID              string `json:"request_id"`
	BodySHA256             string `json:"body_sha256"`
	QuerySHA256            string `json:"query_sha256"`
	IdempotencyKeySHA256   string `json:"idempotency_key_sha256,omitempty"`
	IssuedAt               int64  `json:"iat"`
	ExpiresAt              int64  `json:"exp"`
	ConfigurationVersion   int64  `json:"configuration_version"`
	BindingActivationEpoch int64  `json:"binding_activation_epoch"`
	ReplayEligible         bool   `json:"replay_eligible"`
}

// GatewayAssertionAuthority is the exact trusted route and placement tuple
// expected by one upstream handler. Values come from deployment
// configuration, never from the assertion or browser request.
type GatewayAssertionAuthority struct {
	Issuer                 string
	Audience               string
	TenantID               string
	ApplicationID          string
	EnvironmentID          string
	BindingID              string
	RouteID                string
	RoutePin               string
	GatewayPlacementID     string
	RuntimePlacementID     string
	Operation              string
	GatewayOwnershipEpoch  int64
	RuntimeOwnershipEpoch  int64
	ConfigurationVersion   int64
	BindingActivationEpoch int64
}

// GatewayAssertionRequest contains the exact bytes and URL representation
// received by the protected origin.
type GatewayAssertionRequest struct {
	Method         string
	Path           string
	RawQuery       string
	IdempotencyKey string
	Body           []byte
}

// GatewayAssertionReplayStore atomically consumes a request ID. It returns
// true only for the first observation through expiresAt. Production stores
// must be shared by every replica serving the same assertion audience.
type GatewayAssertionReplayStore interface {
	Consume(ctx context.Context, requestID string, expiresAt time.Time) (bool, error)
}

// GatewayAssertionVerifierOptions configures an exact upstream verifier.
type GatewayAssertionVerifierOptions struct {
	Keys      map[string]ed25519.PublicKey
	Replay    GatewayAssertionReplayStore
	Now       func() time.Time
	Authority GatewayAssertionAuthority
	ClockSkew time.Duration
}

// GatewayAssertionVerifier verifies v1 Ed25519 assertions without contacting
// Control or a runtime on the request hot path.
type GatewayAssertionVerifier struct {
	keys      map[string]ed25519.PublicKey
	replay    GatewayAssertionReplayStore
	now       func() time.Time
	authority GatewayAssertionAuthority
	clockSkew time.Duration
}

// NewGatewayAssertionVerifier constructs an immutable verifier.
func NewGatewayAssertionVerifier(options GatewayAssertionVerifierOptions) (*GatewayAssertionVerifier, error) {
	if len(options.Keys) == 0 || !validGatewayAuthority(options.Authority) ||
		options.ClockSkew < 0 || options.ClockSkew > 30*time.Second {
		return nil, ErrGatewayAssertionRejected
	}
	keys := make(map[string]ed25519.PublicKey, len(options.Keys))
	for keyID, publicKey := range options.Keys {
		if !gatewayToken(keyID, 160) || len(publicKey) != ed25519.PublicKeySize {
			return nil, ErrGatewayAssertionRejected
		}
		keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &GatewayAssertionVerifier{
		keys: keys, authority: options.Authority, replay: options.Replay,
		now: options.Now, clockSkew: options.ClockSkew,
	}, nil
}

// Verify validates the signature, canonical claims, exact authority tuple,
// request binding, time bounds, and replay policy.
func (v *GatewayAssertionVerifier) Verify(
	ctx context.Context,
	encoded string,
	request GatewayAssertionRequest,
) (GatewayAssertionClaims, error) {
	if v == nil || !validGatewayRequest(request) {
		return GatewayAssertionClaims{}, ErrGatewayAssertionRejected
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return GatewayAssertionClaims{}, ErrGatewayAssertionRejected
	}
	body, bodyErr := base64.RawURLEncoding.DecodeString(parts[1])
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[2])
	if bodyErr != nil || signatureErr != nil || len(body) == 0 || len(body) > 16<<10 ||
		len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(body) != parts[1] ||
		base64.RawURLEncoding.EncodeToString(signature) != parts[2] {
		return GatewayAssertionClaims{}, ErrGatewayAssertionRejected
	}
	var claims GatewayAssertionClaims
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil || !gatewayJSONEOF(decoder) {
		return GatewayAssertionClaims{}, ErrGatewayAssertionRejected
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(canonical, body) {
		return GatewayAssertionClaims{}, ErrGatewayAssertionRejected
	}
	publicKey := v.keys[claims.KeyID]
	if len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, body, signature) {
		return GatewayAssertionClaims{}, ErrGatewayAssertionRejected
	}
	if !v.validClaims(claims, request) {
		return GatewayAssertionClaims{}, ErrGatewayAssertionRejected
	}
	if !claims.ReplayEligible {
		if v.replay == nil {
			return GatewayAssertionClaims{}, ErrGatewayReplayUnavailable
		}
		first, replayErr := v.replay.Consume(ctx, claims.RequestID, time.Unix(claims.ExpiresAt, 0))
		if replayErr != nil {
			return GatewayAssertionClaims{}, errors.Join(ErrGatewayReplayUnavailable, replayErr)
		}
		if !first {
			return GatewayAssertionClaims{}, ErrGatewayAssertionRejected
		}
	}
	return claims, nil
}

func (v *GatewayAssertionVerifier) validClaims(claims GatewayAssertionClaims, request GatewayAssertionRequest) bool {
	now := v.now().UTC()
	authority := v.authority
	if claims.Issuer != authority.Issuer || claims.Audience != authority.Audience ||
		claims.TenantID != authority.TenantID || claims.ApplicationID != authority.ApplicationID ||
		claims.EnvironmentID != authority.EnvironmentID || claims.BindingID != authority.BindingID ||
		claims.RouteID != authority.RouteID || claims.RoutePin != authority.RoutePin ||
		claims.GatewayPlacementID != authority.GatewayPlacementID ||
		claims.GatewayOwnershipEpoch != authority.GatewayOwnershipEpoch ||
		claims.RuntimePlacementID != authority.RuntimePlacementID ||
		claims.RuntimeOwnershipEpoch != authority.RuntimeOwnershipEpoch ||
		claims.Operation != authority.Operation || claims.ConfigurationVersion != authority.ConfigurationVersion ||
		claims.BindingActivationEpoch != authority.BindingActivationEpoch {
		return false
	}
	if claims.IssuedAt < 1 || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 30 ||
		time.Unix(claims.IssuedAt, 0).After(now.Add(v.clockSkew)) ||
		!time.Unix(claims.ExpiresAt, 0).After(now.Add(-v.clockSkew)) {
		return false
	}
	if !gatewayToken(claims.RequestID, 300) || !gatewayHash(claims.BodySHA256) ||
		!gatewayHash(claims.QuerySHA256) || (claims.Subject == "") != (claims.SessionIDHash == "") ||
		(claims.SessionIDHash != "" && !gatewayHash(claims.SessionIDHash)) {
		return false
	}
	if claims.Method != request.Method || claims.Path != request.Path ||
		!constantGatewayHash(claims.BodySHA256, request.Body) ||
		!constantGatewayHash(claims.QuerySHA256, []byte(request.RawQuery)) {
		return false
	}
	idempotencyHash := ""
	if request.IdempotencyKey != "" {
		idempotencyHash = gatewaySHA256([]byte(request.IdempotencyKey))
	}
	if subtle.ConstantTimeCompare([]byte(claims.IdempotencyKeySHA256), []byte(idempotencyHash)) != 1 {
		return false
	}
	safe := request.Method == http.MethodGet || request.Method == http.MethodHead || request.Method == http.MethodOptions
	return (!safe || claims.ReplayEligible) && (safe || !claims.ReplayEligible || idempotencyHash != "")
}

// GatewayAssertionMiddlewareOptions configures HTTP request verification.
// AuthenticateOrigin is mandatory and should check mTLS, private ingress, or
// another deployment-owned origin boundary independent of the assertion.
type GatewayAssertionMiddlewareOptions struct {
	Verifier           *GatewayAssertionVerifier
	AuthenticateOrigin func(*http.Request) bool
	MaxBodyBytes       int64
}

type gatewayAssertionContextKey struct{}

// GatewayAssertionMiddleware returns middleware that verifies an assertion
// before invoking next, strips the raw assertion, and restores the exact body
// bytes for the application handler.
func GatewayAssertionMiddleware(options GatewayAssertionMiddlewareOptions, next http.Handler) (http.Handler, error) {
	if options.Verifier == nil || options.AuthenticateOrigin == nil || next == nil ||
		options.MaxBodyBytes < 0 || options.MaxBodyBytes > 1<<30 {
		return nil, ErrGatewayAssertionRejected
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !options.AuthenticateOrigin(r) {
			gatewayAssertionHTTPError(w, http.StatusUnauthorized)
			return
		}
		values := r.Header.Values("X-Lotor-Assertion")
		idempotencyValues := r.Header.Values("Idempotency-Key")
		if len(values) != 1 || len(idempotencyValues) > 1 {
			gatewayAssertionHTTPError(w, http.StatusUnauthorized)
			return
		}
		var reader io.Reader = http.NoBody
		if r.Body != nil {
			reader = r.Body
		}
		body, err := io.ReadAll(io.LimitReader(reader, options.MaxBodyBytes+1))
		if err != nil || int64(len(body)) > options.MaxBodyBytes {
			gatewayAssertionHTTPError(w, http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		idempotencyKey := ""
		if len(idempotencyValues) == 1 {
			idempotencyKey = idempotencyValues[0]
		}
		claims, err := options.Verifier.Verify(r.Context(), values[0], GatewayAssertionRequest{
			Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
			IdempotencyKey: idempotencyKey, Body: body,
		})
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrGatewayReplayUnavailable) {
				status = http.StatusServiceUnavailable
			}
			gatewayAssertionHTTPError(w, status)
			return
		}
		r.Header.Del("X-Lotor-Assertion")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), gatewayAssertionContextKey{}, claims)))
	}), nil
}

// GatewayAssertionFromContext returns claims installed by the middleware.
func GatewayAssertionFromContext(ctx context.Context) (GatewayAssertionClaims, bool) {
	claims, ok := ctx.Value(gatewayAssertionContextKey{}).(GatewayAssertionClaims)
	return claims, ok
}

// VerifiedClientCertificateOrigin accepts only requests whose TLS client
// certificate chain was verified by net/http using the server TLS policy.
func VerifiedClientCertificateOrigin(request *http.Request) bool {
	return request != nil && request.TLS != nil && len(request.TLS.VerifiedChains) > 0
}

func validGatewayAuthority(authority GatewayAssertionAuthority) bool {
	return gatewayToken(authority.Issuer, 320) && gatewayToken(authority.Audience, 512) &&
		gatewayToken(authority.TenantID, 300) && gatewayToken(authority.ApplicationID, 300) &&
		gatewayToken(authority.EnvironmentID, 300) && gatewayToken(authority.BindingID, 200) &&
		gatewayToken(authority.RouteID, 160) && gatewayHash(authority.RoutePin) &&
		gatewayToken(authority.GatewayPlacementID, 200) && gatewayToken(authority.RuntimePlacementID, 200) &&
		authority.GatewayOwnershipEpoch > 0 && authority.RuntimeOwnershipEpoch > 0 &&
		authority.ConfigurationVersion > 0 && authority.BindingActivationEpoch > 0 &&
		(authority.Operation == "" || gatewayToken(authority.Operation, 256))
}

func validGatewayRequest(request GatewayAssertionRequest) bool {
	if !gatewayMethod(request.Method) || request.Path == "" ||
		len(request.Method) > 32 || len(request.Path) > 8<<10 || len(request.RawQuery) > 8<<10 ||
		!strings.HasPrefix(request.Path, "/") ||
		strings.ContainsAny(request.Path, "\x00\r\n\\") || strings.ContainsAny(request.RawQuery, "\x00\r\n") ||
		strings.TrimSpace(request.IdempotencyKey) != request.IdempotencyKey ||
		len(request.IdempotencyKey) > 512 || strings.ContainsAny(request.IdempotencyKey, "\x00\r\n") {
		return false
	}
	return true
}

func gatewayMethod(value string) bool {
	if value == "" || value != strings.ToUpper(value) {
		return false
	}
	for _, character := range value {
		if (character >= 'A' && character <= 'Z') || strings.ContainsRune("!#$%&'*+-.^_`|~", character) {
			continue
		}
		return false
	}
	return true
}

func gatewayJSONEOF(decoder *json.Decoder) bool {
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func gatewayToken(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func gatewayHash(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func constantGatewayHash(expected string, value []byte) bool {
	actual := gatewaySHA256(value)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func gatewaySHA256(value []byte) string {
	hash := sha256.Sum256(value)
	return hex.EncodeToString(hash[:])
}

func gatewayAssertionHTTPError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"gateway request rejected"}`+"\n")
}
