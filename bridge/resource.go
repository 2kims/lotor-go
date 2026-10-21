package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// ResourcePayloadManifest and ResourcePayloadAccessLease are shared wire types
// used by both ordinary Control clients and runtime-scoped resource access.
type ResourcePayloadManifest struct {
	Resource            string `json:"resource"`
	Slot                string `json:"slot"`
	SchemaID            string `json:"schema_id"`
	Representation      string `json:"representation"`
	ObjectDigest        string `json:"object_digest"`
	EncryptionSuite     string `json:"encryption_suite,omitempty"`
	KeyBindingRef       string `json:"key_binding_ref,omitempty"`
	WrappedPayloadKey   string `json:"wrapped_payload_key,omitempty"`
	AADHash             string `json:"aad_hash,omitempty"`
	EncryptorSubject    string `json:"encryptor_subject,omitempty"`
	EncryptorKeyID      string `json:"encryptor_key_id,omitempty"`
	State               string `json:"state"`
	PayloadVersion      int64  `json:"payload_version"`
	ObjectSize          int64  `json:"object_size"`
	KeyVersion          int64  `json:"key_version,omitempty"`
	ResourceRevision    int64  `json:"resource_revision"`
	LifecycleGeneration int64  `json:"lifecycle_generation"`
	CommittedAt         int64  `json:"committed_at"`
}

type ResourcePayloadAccessLease struct {
	Resource            string `json:"resource"`
	Slot                string `json:"slot"`
	Representation      string `json:"representation"`
	ObjectDigest        string `json:"object_digest"`
	DownloadURL         string `json:"download_url"`
	DownloadMethod      string `json:"download_method"`
	Audience            string `json:"audience"`
	PayloadVersion      int64  `json:"payload_version"`
	ObjectSize          int64  `json:"object_size"`
	ExpiresAt           int64  `json:"expires_at"`
	ResourceRevision    int64  `json:"resource_revision"`
	LifecycleGeneration int64  `json:"lifecycle_generation"`
}

type ResourcePayloadAccess struct {
	CustodyOwner string                     `json:"custody_owner,omitempty"`
	Lease        ResourcePayloadAccessLease `json:"lease"`
	Manifest     ResourcePayloadManifest    `json:"manifest"`
}

// ResourceClient uses the registered runtime's signing identity, not an app
// secret or forwarded user credential. It never unwraps cryptographic keys.
type ResourceClient struct{ validator *ControlValidator }

func NewResourceClient(options ControlValidatorOptions) (*ResourceClient, error) {
	validator, err := NewControlValidator(options)
	if err != nil {
		return nil, err
	}
	return &ResourceClient{validator: validator}, nil
}

func (client *ResourceClient) Authorize(ctx context.Context, authorization Authorization, original SignedMessage) error {
	return client.validator.Authorize(ctx, authorization, original)
}

// AccessPayload is available only inside a verified handler context. It returns
// the stored representation and a short-lived download lease, never a key or an
// implicitly decrypted object. PayloadVersion must be the exact planned version.
func (client *ResourceClient) AccessPayload(ctx context.Context, resource, slot string, payloadVersion int64) (ResourcePayloadAccess, error) {
	return client.accessPayload(ctx, resource, slot, payloadVersion, false)
}

func (client *ResourceClient) accessPayload(ctx context.Context, resource, slot string, payloadVersion int64, useCustody bool) (ResourcePayloadAccess, error) {
	authorization, original, ok := InvocationFromContext(ctx)
	if !ok || !slices.Contains(authorization.Resources, resource) || !slices.Contains(authorization.Capabilities, "payload.read") || useCustody && !slices.Contains(authorization.Capabilities, "custody.use") {
		return ResourcePayloadAccess{}, ErrUnauthorized
	}
	if !identifier(resource, 256) || !identifier(slot, 128) || payloadVersion < 1 {
		return ResourcePayloadAccess{}, ErrInvalid
	}
	proof, err := SignResourceAccess(ResourceAccessRequest{Authorization: original, Resource: resource, Slot: slot, PayloadVersion: payloadVersion, UseCustody: useCustody}, client.validator.keyID, client.validator.key)
	if err != nil {
		return ResourcePayloadAccess{}, ErrInvalid
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return ResourcePayloadAccess{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.validator.baseURL+"/v1/function-bindings/"+url.PathEscape(authorization.BindingID)+"/resource-payload-accesses", bytes.NewReader(body))
	if err != nil {
		return ResourcePayloadAccess{}, ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.validator.client.Do(request)
	if err != nil {
		return ResourcePayloadAccess{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return ResourcePayloadAccess{}, ErrUnauthorized
	}
	if response.StatusCode == http.StatusConflict {
		return ResourcePayloadAccess{}, ErrConflict
	}
	if response.StatusCode == http.StatusNotFound {
		return ResourcePayloadAccess{}, ErrNotFound
	}
	if response.StatusCode == http.StatusBadRequest {
		return ResourcePayloadAccess{}, ErrInvalid
	}
	if response.StatusCode != http.StatusOK {
		return ResourcePayloadAccess{}, ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaximumBodyBytes+1))
	if err != nil || len(raw) > MaximumBodyBytes {
		return ResourcePayloadAccess{}, ErrUnavailable
	}
	var result ResourcePayloadAccess
	if strictJSON(raw, &result) != nil {
		return ResourcePayloadAccess{}, ErrUnavailable
	}
	manifest, lease := result.Manifest, result.Lease
	if manifest.Resource != resource || lease.Resource != resource || manifest.Slot != slot || lease.Slot != slot || manifest.PayloadVersion != payloadVersion || lease.PayloadVersion != payloadVersion || manifest.ObjectDigest != lease.ObjectDigest || manifest.ObjectSize != lease.ObjectSize || manifest.Representation != lease.Representation || manifest.ResourceRevision != lease.ResourceRevision || manifest.LifecycleGeneration != lease.LifecycleGeneration || lease.Audience != "function:"+authorization.BindingID || lease.ExpiresAt <= time.Now().UnixMicro() || lease.ExpiresAt > authorization.ExpiresAt*1_000_000 {
		return ResourcePayloadAccess{}, ErrUnauthorized
	}
	return result, nil
}
