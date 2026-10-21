package bridge

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const ResourceValueFormat = "lotor.resource-value.v1"

// ResourceKeyBinding is an invocation-scoped key-use description, not a bearer
// credential. Populate it from current Control validation and payload metadata.
// No principal key, passphrase, or plaintext resource key is a wire field.
type ResourceKeyBinding struct { //nolint:govet // Field order is part of the authenticated Go/browser wire contract.
	Scope               Scope  `json:"scope"`
	ClientID            string `json:"client_id"`
	Resource            string `json:"resource"`
	Slot                string `json:"slot"`
	KeyResource         string `json:"key_resource"`
	CustodyOwner        string `json:"custody_owner"`
	KeyVersion          int64  `json:"key_version"`
	ResourceRevision    int64  `json:"resource_revision"`
	LifecycleGeneration int64  `json:"lifecycle_generation"`
	PayloadVersion      int64  `json:"payload_version"`
	ObjectDigest        string `json:"object_digest"`
	InvocationID        string `json:"invocation_id"`
	BindingID           string `json:"binding_id"`
	BindingRevision     int64  `json:"binding_revision"`
	Principal           string `json:"principal"`
	PolicyDigest        string `json:"policy_digest"`
	ExpiresAt           int64  `json:"expires_at"`
}

type ResourceValueContext struct { //nolint:govet // Field order is part of the authenticated Go/browser wire contract.
	Binding ResourceKeyBinding `json:"binding"`
	Path    string             `json:"path"`
}

// ResourceValue is a generic authenticated value, independent of provider,
// transport, or application policy. Recipients must supply expected context.
type ResourceValue struct {
	Format     string               `json:"format"`
	Context    ResourceValueContext `json:"context"`
	Nonce      string               `json:"nonce"`
	Ciphertext string               `json:"ciphertext"`
}

// PayloadCustodian is implemented only inside the selected custody deployment.
// Implementations use the existing sealed resource key; they must never generate
// a replacement key or expose this callback through a key-export HTTP endpoint.
type PayloadCustodian interface {
	UseResourceKey(context.Context, ResourceKeyBinding, func(*ResourceCipher) error) error
}

// ResourceCipher is usable only during its custody callback and original live
// invocation. It exposes cryptographic operations, never the resource key.
// Copies share the same synchronized key state and callback lifetime.
type ResourceCipher struct {
	state   *resourceCipherState
	binding ResourceKeyBinding
}

type resourceCipherState struct {
	key []byte
	mu  sync.Mutex
}

// Diagnostic formatting must never dump the private key buffer, even while the
// callback is active. Reflection deliberately bypassing this boundary is not a
// supported application interface.
func (ResourceCipher) String() string   { return "ResourceCipher([redacted])" }
func (ResourceCipher) GoString() string { return "ResourceCipher([redacted])" }

// WithResourceKey is a local composition primitive for trusted custody code,
// NOT authorization by itself. The caller must first freshly validate the
// original grant and derive key metadata with WithPayloadCustody (or equivalent
// authoritative local checks). The provider owns and clears its input buffer;
// this function owns and clears a separate copy, including on panic/error.
func WithResourceKey(ctx context.Context, binding ResourceKeyBinding, key []byte, use func(*ResourceCipher) error) error {
	if len(key) != 32 || use == nil || !validResourceKeyBinding(binding) || !binding.matchesInvocation(ctx) {
		return ErrUnauthorized
	}
	state := &resourceCipherState{key: append([]byte(nil), key...)}
	c := &ResourceCipher{binding: binding, state: state}
	defer func() { state.mu.Lock(); defer state.mu.Unlock(); clear(state.key); state.key = nil }()
	return use(c)
}

// WithPayloadCustody revalidates the original principal and exact payload with
// Control before touching local custody. The manifest is returned to the
// callback, not selected by application/browser input. No key reaches Control.
func (client *ResourceClient) WithPayloadCustody(ctx context.Context, clientID, resource, slot string, version int64, provider PayloadCustodian, use func(*ResourceCipher, ResourcePayloadManifest) error) error {
	if provider == nil || use == nil || !identifier(clientID, 256) {
		return ErrInvalid
	}
	identity, err := client.WorkloadContext(ctx)
	if err != nil {
		return err
	}
	access, err := client.accessPayload(ctx, resource, slot, version, true)
	if err != nil {
		return err
	}
	manifest := access.Manifest
	grant, _, ok := InvocationFromContext(ctx)
	if !ok || manifest.State != "committed" || manifest.Representation != "encrypted-envelope-v1" || manifest.EncryptionSuite != "AES-256-GCM" {
		return ErrUnauthorized
	}
	binding := ResourceKeyBinding{
		Scope: identity.Scope, ClientID: clientID, Resource: resource, Slot: slot, KeyResource: manifest.KeyBindingRef, CustodyOwner: access.CustodyOwner, KeyVersion: manifest.KeyVersion,
		ResourceRevision: manifest.ResourceRevision, LifecycleGeneration: manifest.LifecycleGeneration, PayloadVersion: manifest.PayloadVersion, ObjectDigest: manifest.ObjectDigest,
		InvocationID: grant.ID, BindingID: grant.BindingID, BindingRevision: grant.BindingRevision, Principal: identity.Principal, PolicyDigest: grant.PolicyDigest, ExpiresAt: grant.ExpiresAt,
	}
	if !validResourceKeyBinding(binding) || !binding.matchesInvocation(ctx) {
		return ErrUnauthorized
	}
	return provider.UseResourceKey(ctx, binding, func(cipher *ResourceCipher) error {
		if cipher == nil || cipher.binding != binding {
			return ErrUnauthorized
		}
		return use(cipher, manifest)
	})
}

func (binding ResourceKeyBinding) matchesInvocation(ctx context.Context) bool {
	grant, _, ok := InvocationFromContext(ctx)
	return ctx.Err() == nil && ok && grant.Kind == "invocation" && grant.Scope == binding.Scope && grant.ID == binding.InvocationID &&
		grant.BindingID == binding.BindingID && grant.BindingRevision == binding.BindingRevision && grant.Principal == binding.Principal &&
		grant.PolicyDigest == binding.PolicyDigest && grant.ExpiresAt == binding.ExpiresAt && grant.ExpiresAt > time.Now().Unix() &&
		slices.Contains(grant.Resources, binding.Resource) && slices.Contains(grant.Capabilities, "payload.read") && slices.Contains(grant.Capabilities, "custody.use")
}

func validResourceKeyBinding(b ResourceKeyBinding) bool {
	return validScope(b.Scope) && identifier(b.ClientID, 256) && identifier(b.Resource, 256) && identifier(b.Slot, 128) && identifier(b.KeyResource, 256) && isDigest(b.CustodyOwner) &&
		identifier(b.InvocationID, 256) && identifier(b.BindingID, 256) && identifier(b.Principal, 256) && b.KeyVersion > 0 && b.ResourceRevision > 0 &&
		b.LifecycleGeneration > 0 && b.PayloadVersion > 0 && b.BindingRevision > 0 && isDigest(b.ObjectDigest) && (b.PolicyDigest == "" || isDigest(b.PolicyDigest)) &&
		b.KeyVersion <= maxSafeInteger && b.ResourceRevision <= maxSafeInteger && b.LifecycleGeneration <= maxSafeInteger &&
		b.PayloadVersion <= maxSafeInteger && b.BindingRevision <= maxSafeInteger && b.ExpiresAt > 0 && b.ExpiresAt <= maxSafeInteger
}

const maxSafeInteger int64 = 1<<53 - 1

// CustodyOwnerFingerprint binds the public identity to key bytes as well as
// labels. It preserves the existing resource-key custody-owner hash format.
func CustodyOwnerFingerprint(subject, keyID string, publicKey []byte) string {
	if !identifier(subject, 256) || !identifier(keyID, 256) || len(publicKey) != 32 {
		return ""
	}
	wire, _ := json.Marshal([]string{"lotor-resource-custody-owner-v1", subject, keyID, base64.RawURLEncoding.EncodeToString(publicKey)})
	return Digest(wire)
}

func validResourceValueContext(context ResourceValueContext) bool {
	return validResourceKeyBinding(context.Binding) && isDigest(context.Binding.PolicyDigest) && len(context.Path) > 0 && len(context.Path) <= 1024 &&
		utf8.ValidString(context.Path) && !strings.ContainsAny(context.Path, "\x00\r\n")
}

func resourceValueAAD(context ResourceValueContext) ([]byte, error) {
	if !validResourceValueContext(context) {
		return nil, ErrInvalid
	}
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		Format  string               `json:"format"`
		Context ResourceValueContext `json:"context"`
	}{ResourceValueFormat, context}); err != nil {
		return nil, ErrInvalid
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

func resourceAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	return cipher.NewGCM(block)
}

// Strict checks trailing pad bits but still ignores CR/LF. Reject every byte
// outside the unpadded URL alphabet so Go and browser recipients agree.
func decodeResourceBase64(value string) ([]byte, error) {
	for i := range len(value) {
		b := value[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return nil, ErrInvalid
		}
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, ErrInvalid
	}
	return decoded, nil
}

func (c *ResourceCipher) EncryptValue(ctx context.Context, path string, plaintext []byte) (ResourceValue, error) {
	if c == nil || c.state == nil {
		return ResourceValue{}, ErrUnauthorized
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if len(c.state.key) != 32 || !c.binding.matchesInvocation(ctx) {
		return ResourceValue{}, ErrUnauthorized
	}
	context := ResourceValueContext{Binding: c.binding, Path: path}
	aad, err := resourceValueAAD(context)
	if err != nil || len(plaintext) > MaximumInputBytes {
		return ResourceValue{}, ErrInvalid
	}
	aead, err := resourceAEAD(c.state.key)
	if err != nil {
		return ResourceValue{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return ResourceValue{}, ErrUnavailable
	}
	return ResourceValue{Format: ResourceValueFormat, Context: context, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, aad))}, nil
}

// DecryptResourceValue is recipient-side decryption. Expiry limits runtime key
// use, not a recipient's ability to read an already-delivered ciphertext later.
func DecryptResourceValue(key []byte, value ResourceValue, expected ResourceValueContext) ([]byte, error) {
	if value.Format != ResourceValueFormat || value.Context != expected || len(value.Nonce) != base64.RawURLEncoding.EncodedLen(12) || len(value.Ciphertext) > base64.RawURLEncoding.EncodedLen(MaximumInputBytes+16) {
		return nil, ErrInvalid
	}
	aad, err := resourceValueAAD(expected)
	if err != nil {
		return nil, ErrInvalid
	}
	aead, err := resourceAEAD(key)
	if err != nil {
		return nil, ErrInvalid
	}
	nonce, err := decodeResourceBase64(value.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return nil, ErrInvalid
	}
	ciphertext, err := decodeResourceBase64(value.Ciphertext)
	if err != nil {
		return nil, ErrInvalid
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrInvalid
	}
	return plaintext, nil
}

// OpenPayload opens the existing encrypted-envelope-v1 storage format without
// changing its data-key wrapping or AAD contract. Verify the entire committed
// manifest, wrapper, object digest/size, and key binding before returning bytes.
func (c *ResourceCipher) OpenPayload(ctx context.Context, manifest ResourcePayloadManifest, ciphertext []byte) ([]byte, error) {
	if c == nil || c.state == nil {
		return nil, ErrUnauthorized
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	b := c.binding
	if len(c.state.key) != 32 || !b.matchesInvocation(ctx) || !isDigest(b.PolicyDigest) {
		return nil, ErrUnauthorized
	}
	if len(manifest.WrappedPayloadKey) != base64.RawURLEncoding.EncodedLen(61) || manifest.Resource != b.Resource || manifest.Slot != b.Slot || manifest.KeyBindingRef != b.KeyResource || manifest.KeyVersion != b.KeyVersion || manifest.ResourceRevision != b.ResourceRevision ||
		manifest.LifecycleGeneration != b.LifecycleGeneration || manifest.PayloadVersion != b.PayloadVersion || manifest.ObjectDigest != b.ObjectDigest ||
		manifest.State != "committed" || manifest.Representation != "encrypted-envelope-v1" || manifest.EncryptionSuite != "AES-256-GCM" ||
		manifest.ObjectSize != int64(len(ciphertext)) || len(ciphertext) < 29 || len(ciphertext) > MaximumInputBytes || ciphertext[0] != 1 || Digest(ciphertext) != b.ObjectDigest {
		return nil, ErrInvalid
	}
	aadRaw, _ := json.Marshal(struct {
		ClientID            string `json:"client_id"`
		Resource            string `json:"resource"`
		Slot                string `json:"slot"`
		SchemaID            string `json:"schema_id"`
		ResourceRevision    int64  `json:"resource_revision"`
		LifecycleGeneration int64  `json:"lifecycle_generation"`
	}{b.ClientID, b.Resource, manifest.Slot, manifest.SchemaID, b.ResourceRevision, b.LifecycleGeneration})
	hash := sha256.Sum256(aadRaw)
	if !identifier(manifest.Slot, 128) || !identifier(manifest.SchemaID, 256) || manifest.AADHash != base64.RawURLEncoding.EncodeToString(hash[:]) {
		return nil, ErrInvalid
	}
	wrapped, err := decodeResourceBase64(manifest.WrappedPayloadKey)
	if err != nil || len(wrapped) != 61 || wrapped[0] != 1 {
		return nil, ErrInvalid
	}
	aead, err := resourceAEAD(c.state.key)
	if err != nil {
		return nil, ErrInvalid
	}
	dataKey, err := aead.Open(nil, wrapped[1:13], wrapped[13:], hash[:])
	if err != nil || len(dataKey) != 32 {
		clear(dataKey)
		return nil, ErrInvalid
	}
	defer clear(dataKey)
	aead, err = resourceAEAD(dataKey)
	if err != nil {
		return nil, ErrInvalid
	}
	plaintext, err := aead.Open(nil, ciphertext[1:13], ciphertext[13:], hash[:])
	if err != nil {
		return nil, ErrInvalid
	}
	return plaintext, nil
}
