package lotorhttp

import (
	"context"
	"net/http"
)

// ResourcePayload reads the manifest under this client's authority. Use ForUser
// when acting on behalf of a signed-in user rather than the application.
func (c *ControlClient) ResourcePayload(ctx context.Context, resource, slot string) (ResourcePayloadManifest, error) {
	var out ResourcePayloadManifest
	err := c.request(ctx, http.MethodGet, resourcePayloadPath(resource, slot), "", nil, &out)
	return out, err
}

// AccessResourcePayload obtains a short-lived lease for an authorized version.
func (c *ControlClient) AccessResourcePayload(ctx context.Context, resource, slot string, payloadVersion int64) (ResourcePayloadAccessLease, error) {
	var out ResourcePayloadAccessLease
	body := struct {
		PayloadVersion int64 `json:"payload_version,omitempty"`
	}{payloadVersion}
	err := c.request(ctx, http.MethodPost, resourcePayloadPath(resource, slot)+"/access", "", body, &out)
	return out, err
}

// DownloadResourcePayload verifies object size and digest without attaching
// Lotor authentication headers to the signed object URL. It does not decrypt.
func (c *ControlClient) DownloadResourcePayload(ctx context.Context, lease ResourcePayloadAccessLease) ([]byte, error) {
	return downloadResourcePayload(ctx, c.httpClient, lease)
}
