package lotor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxOwnershipResponse = 64 << 10

// Ownership is a short-lived, signed owner assertion returned by Control. Scope
// is diagnostic output derived from the runtime credential, never SDK input.
//
//nolint:govet // JSON field order is the signed wire contract.
type Ownership struct {
	TenantID        string `json:"tenant_id"`
	ApplicationID   string `json:"application_id"`
	EnvironmentID   string `json:"environment_id"`
	Endpoint        string `json:"endpoint"`
	OwnerInstanceID string `json:"owner_instance_id"`
	OwnershipEpoch  int64  `json:"ownership_epoch"`
	IssuedAt        int64  `json:"issued_at"`
	ExpiresAt       int64  `json:"expires_at"`
	Version         int    `json:"version"`
	KeyID           string `json:"key_id"`
	Signature       string `json:"signature"`
}

// Address returns the validated TCP host:port and whether the owner requires TLS.
func (o Ownership) Address() (address string, tls bool, err error) {
	parsed, err := url.Parse(o.Endpoint)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false, errors.New("invalid ownership endpoint")
	}
	if parsed.Scheme != "lwp" && parsed.Scheme != "lwps" {
		return "", false, errors.New("unsupported ownership endpoint scheme")
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if host == "" || port == "" {
		return "", false, errors.New("ownership endpoint requires host and port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", false, errors.New("invalid ownership endpoint port")
	}
	return net.JoinHostPort(host, port), parsed.Scheme == "lwps", nil
}

// DiscoveryOptions has exactly the two application configuration values needed
// for runtime discovery.
type DiscoveryOptions struct {
	ControlURL string
	APIKey     string
}

type runtimeSigningKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

type runtimeSigningKeySet struct {
	Keys []runtimeSigningKey `json:"keys"`
}

// OwnershipResolver verifies and briefly caches signed owner assertions.
type OwnershipResolver struct {
	options DiscoveryOptions
	client  *http.Client
	now     func() time.Time
	keys    map[string]ed25519.PublicKey
	cached  Ownership
	mu      sync.Mutex
}

// NewOwnershipResolver constructs a resolver that discovers and verifies the
// runtime owner selected by the supplied environment-scoped API key.
func NewOwnershipResolver(options DiscoveryOptions) (*OwnershipResolver, error) {
	options.ControlURL = strings.TrimRight(strings.TrimSpace(options.ControlURL), "/")
	options.APIKey = strings.TrimSpace(options.APIKey)
	if options.ControlURL == "" || options.APIKey == "" {
		return nil, errors.New("control URL and API key are required")
	}
	parsedControl, err := url.ParseRequestURI(options.ControlURL)
	if err != nil || parsedControl.Scheme == "" || parsedControl.Host == "" ||
		parsedControl.User != nil || parsedControl.RawQuery != "" || parsedControl.Fragment != "" ||
		(parsedControl.Scheme != "http" && parsedControl.Scheme != "https") {
		return nil, errors.New("invalid control URL")
	}
	if parsedControl.Scheme == "http" && !loopbackHost(parsedControl.Hostname()) {
		return nil, errors.New("non-loopback control URL must use HTTPS")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &OwnershipResolver{
		options: options, client: client, now: time.Now,
		keys: map[string]ed25519.PublicKey{},
	}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Resolve returns a verified assertion. Cached assertions are discarded five seconds before expiry.
func (r *OwnershipResolver) Resolve(ctx context.Context) (Ownership, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().UnixMicro()
	if r.cached.Version != 0 && now+int64(5*time.Second/time.Microsecond) < r.cached.ExpiresAt {
		return r.cached, nil
	}
	ownership, err := r.fetchOwnership(ctx, now)
	if err != nil {
		return Ownership{}, err
	}
	r.cached = ownership
	return ownership, nil
}

// Invalidate drops a cached assertion after a MOVED response or connection failure.
func (r *OwnershipResolver) Invalidate() {
	r.mu.Lock()
	r.cached = Ownership{}
	r.mu.Unlock()
}

// DialOwned discovers the exact owner immediately before connecting.
func DialOwned(
	ctx context.Context, resolver *OwnershipResolver, tlsConfig *tls.Config,
) (*Client, Ownership, error) {
	if resolver == nil {
		return nil, Ownership{}, errors.New("ownership resolver is required")
	}
	ownership, err := resolver.Resolve(ctx)
	if err != nil {
		return nil, Ownership{}, err
	}
	client, err := dialOwnership(ctx, ownership, tlsConfig)
	if err != nil {
		resolver.Invalidate()
		return nil, Ownership{}, err
	}
	return client, ownership, nil
}

// WithOwnerRetry runs one logical operation against the discovered owner and follows at most one
// authenticated MOVED assertion. Mutation callbacks must reuse the same idempotency key on retry.
func WithOwnerRetry[T any](
	ctx context.Context,
	resolver *OwnershipResolver,
	tlsConfig *tls.Config,
	operation func(*Client) (T, error),
) (T, error) {
	var zero T
	if operation == nil {
		return zero, errors.New("ownership operation is required")
	}
	client, first, err := DialOwned(ctx, resolver, tlsConfig)
	if err != nil {
		return zero, err
	}
	if err = client.Auth(resolver.options.APIKey); err != nil {
		_ = client.Close()
		return zero, err
	}
	result, err := operation(client)
	_ = client.Close()
	if !IsLWPError(err, 0x0014) {
		return result, err
	}
	var movedError *LWPError
	if !errors.As(err, &movedError) {
		return zero, err
	}
	moved, err := resolver.acceptMoved(ctx, movedError.Message, first)
	if err != nil {
		return zero, err
	}
	client, err = dialOwnership(ctx, moved, tlsConfig)
	if err != nil {
		return zero, err
	}
	defer client.Close()
	if err = client.Auth(resolver.options.APIKey); err != nil {
		return zero, err
	}
	return operation(client)
}

func (r *OwnershipResolver) acceptMoved(ctx context.Context, raw string, prior Ownership) (Ownership, error) {
	if len(raw) > maxOwnershipResponse {
		return Ownership{}, errors.New("MOVED ownership assertion is too large")
	}
	var moved Ownership
	if err := json.Unmarshal([]byte(raw), &moved); err != nil {
		return Ownership{}, errors.New("invalid MOVED ownership assertion")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	publicKey, err := r.signingKey(ctx, moved.KeyID)
	if err != nil {
		return Ownership{}, err
	}
	if err = verifyOwnership(moved, publicKey, r.now().UnixMicro()); err != nil {
		return Ownership{}, err
	}
	if !sameOwnershipScope(moved, prior) {
		return Ownership{}, errors.New("MOVED assertion changed credential scope")
	}
	if moved.OwnershipEpoch <= prior.OwnershipEpoch || moved.Endpoint == prior.Endpoint {
		return Ownership{}, errors.New("MOVED assertion did not advance ownership")
	}
	r.cached = moved
	return moved, nil
}

func sameOwnershipScope(a, b Ownership) bool {
	return a.TenantID == b.TenantID &&
		a.ApplicationID == b.ApplicationID &&
		a.EnvironmentID == b.EnvironmentID
}

func dialOwnership(ctx context.Context, ownership Ownership, tlsConfig *tls.Config) (*Client, error) {
	address, tlsRequired, err := ownership.Address()
	if err != nil {
		return nil, err
	}
	if tlsRequired {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		return DialTLS(ctx, address, tlsConfig)
	}
	if tlsConfig != nil {
		return nil, errors.New("ownership endpoint requires plaintext LWP but TLS was configured")
	}
	return Dial(ctx, address)
}

func (r *OwnershipResolver) fetchOwnership(ctx context.Context, now int64) (Ownership, error) {
	endpoint := r.options.ControlURL + "/v1/runtime/ownership"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Ownership{}, err
	}
	request.Header.Set("Authorization", "Bearer "+r.options.APIKey)
	var ownership Ownership
	if err = r.fetchJSON(request, &ownership, "ownership discovery"); err != nil {
		return Ownership{}, err
	}
	publicKey, err := r.signingKey(ctx, ownership.KeyID)
	if err != nil {
		return Ownership{}, err
	}
	if err = verifyOwnership(ownership, publicKey, now); err != nil {
		return Ownership{}, err
	}
	return ownership, nil
}

func (r *OwnershipResolver) signingKey(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	if key := r.keys[keyID]; len(key) == ed25519.PublicKeySize {
		return key, nil
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, r.options.ControlURL+"/.well-known/lotor-runtime-keys.json", nil,
	)
	if err != nil {
		return nil, err
	}
	var keySet runtimeSigningKeySet
	if err = r.fetchJSON(request, &keySet, "runtime key discovery"); err != nil {
		return nil, err
	}
	refreshed := make(map[string]ed25519.PublicKey, len(keySet.Keys))
	for _, item := range keySet.Keys {
		if item.KeyID == "" || item.Algorithm != "Ed25519" {
			return nil, errors.New("invalid runtime signing key metadata")
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(item.PublicKey)
		if decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("invalid runtime signing public key")
		}
		publicKey := ed25519.PublicKey(append([]byte(nil), decoded...))
		hash := sha256.Sum256(publicKey)
		if item.KeyID != hex.EncodeToString(hash[:8]) {
			return nil, errors.New("runtime signing key ID mismatch")
		}
		if _, duplicate := refreshed[item.KeyID]; duplicate {
			return nil, errors.New("duplicate runtime signing key")
		}
		refreshed[item.KeyID] = publicKey
	}
	r.keys = refreshed
	if key := r.keys[keyID]; len(key) == ed25519.PublicKeySize {
		return key, nil
	}
	return nil, errors.New("ownership signing key is unavailable")
}

func (r *OwnershipResolver) fetchJSON(request *http.Request, destination any, operation string) error {
	response, err := r.client.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxOwnershipResponse))
		return fmt.Errorf("%s returned HTTP %d", operation, response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxOwnershipResponse+1))
	if err != nil {
		return fmt.Errorf("read %s response: %w", operation, err)
	}
	if len(raw) > maxOwnershipResponse {
		return fmt.Errorf("%s response is too large", operation)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid %s response: %w", operation, err)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid trailing %s response", operation)
	}
	return nil
}

func verifyOwnership(value Ownership, publicKey ed25519.PublicKey, now int64) error {
	if value.Version != 1 || value.OwnershipEpoch < 1 || value.OwnerInstanceID == "" ||
		value.TenantID == "" || value.ApplicationID == "" || value.EnvironmentID == "" {
		return errors.New("ownership assertion has invalid credential scope")
	}
	if value.IssuedAt > now+int64(time.Minute/time.Microsecond) || value.ExpiresAt <= now ||
		value.ExpiresAt-value.IssuedAt > int64(time.Minute/time.Microsecond) {
		return errors.New("ownership assertion is expired or outside its validity window")
	}
	if _, _, err := value.Address(); err != nil {
		return err
	}
	publicHash := sha256.Sum256(publicKey)
	if value.KeyID != hex.EncodeToString(publicHash[:8]) {
		return errors.New("ownership signing key mismatch")
	}
	signature, err := base64.RawURLEncoding.DecodeString(value.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid ownership signature")
	}
	if !ed25519.Verify(publicKey, ownershipPayload(value), signature) {
		return errors.New("ownership signature verification failed")
	}
	return nil
}

func ownershipPayload(value Ownership) []byte {
	var payload bytes.Buffer
	fmt.Fprintf(
		&payload, "%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%d\x00%s",
		value.Version, value.TenantID, value.ApplicationID, value.EnvironmentID,
		value.Endpoint, value.OwnerInstanceID, value.OwnershipEpoch, value.IssuedAt,
		value.ExpiresAt, value.KeyID,
	)
	return payload.Bytes()
}
