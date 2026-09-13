package lotorhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ControlClient calls the public Control API as an application adapter. Its
// secret key must only be used from trusted server or CLI processes.
type ControlClient struct {
	httpClient *http.Client
	baseURL    string
	clientID   string
	secretKey  string
	userToken  string
}

type ControlClientOptions struct {
	HTTPClient *http.Client
	BaseURL    string
	ClientID   string
	SecretKey  string
}

type ResourceLifecycleFence struct {
	ExpectedRevision            int64 `json:"expected_revision"`
	ExpectedLifecycleGeneration int64 `json:"expected_lifecycle_generation"`
}

type ResourceRegistration struct {
	References   map[string]string `json:"references,omitempty"`
	ResourceType string            `json:"resource_type"`
	DisplayName  string            `json:"display_name,omitempty"`
	Parent       string            `json:"parent,omitempty"`
	KeyScope     string            `json:"key_scope,omitempty"`
}

// MarshalJSON preserves the difference between an omitted reference map and
// an explicitly supplied empty map. PUT uses omission to preserve immutable
// references; an explicit map must equal the complete stored map.
func (r ResourceRegistration) MarshalJSON() ([]byte, error) {
	wire := map[string]any{"resource_type": r.ResourceType}
	if r.DisplayName != "" {
		wire["display_name"] = r.DisplayName
	}
	if r.Parent != "" {
		wire["parent"] = r.Parent
	}
	if r.KeyScope != "" {
		wire["key_scope"] = r.KeyScope
	}
	if r.References != nil {
		wire["references"] = r.References
	}
	return json.Marshal(wire)
}

type Resource struct {
	CatalogBinding      *ResourceCatalogBinding `json:"catalog_binding,omitempty"`
	References          map[string]string       `json:"references,omitempty"`
	ID                  string                  `json:"id"`
	Resource            string                  `json:"resource"`
	ResourceType        string                  `json:"resource_type"`
	DisplayName         string                  `json:"display_name"`
	Parent              string                  `json:"parent,omitempty"`
	Status              string                  `json:"status"`
	PrincipalSubject    string                  `json:"principal_subject,omitempty"`
	Encryption          ResourceEncryption      `json:"encryption"`
	Revision            int64                   `json:"revision"`
	LifecycleGeneration int64                   `json:"lifecycle_generation"`
}

type ResourceEncryption struct {
	Status               string `json:"status"`
	KeyScope             string `json:"key_scope,omitempty"`
	EffectiveKeyResource string `json:"effective_key_resource,omitempty"`
	KeyResource          string `json:"key_resource,omitempty"`
	KeyVersion           int64  `json:"key_version,omitempty"`
	Required             bool   `json:"required"`
}

type ResourceCatalogBinding struct {
	Resource         string   `json:"resource"`
	CatalogID        string   `json:"catalog_id"`
	SnapshotID       string   `json:"snapshot_id"`
	SnapshotDigest   string   `json:"snapshot_digest"`
	EntryKinds       []string `json:"entry_kinds"`
	ResourceRevision int64    `json:"resource_revision"`
}

type DurableOperation struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Status      string `json:"status"`
	TargetKind  string `json:"target_kind"`
	TargetID    string `json:"target_id"`
	RequestHash string `json:"request_hash"`
	ErrorCode   string `json:"error_code,omitempty"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

type OperationWaitOptions struct {
	MaxAttempts int
	Interval    time.Duration
}

type ResourceCredentialMetadata struct {
	ID          string `json:"id"`
	Resource    string `json:"resource"`
	IssuedTo    string `json:"issued_to"`
	Status      string `json:"status"`
	DisplayHint string `json:"display_hint"`
	Version     int64  `json:"version"`
	CreatedAt   int64  `json:"created_at"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
	RevokeAt    int64  `json:"revoke_at,omitempty"`
	RevokedAt   int64  `json:"revoked_at,omitempty"`
	LastUsedAt  int64  `json:"last_used_at,omitempty"`
}

type IssuedResourceCredential struct {
	Credential string `json:"credential"`
	ResourceCredentialMetadata
}

type ResourceCredentialIssueInput struct {
	IssuedTo  string `json:"issued_to"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

type ResourceCredentialRotateInput struct {
	RevokePreviousAt int64 `json:"revoke_previous_at"`
	ExpiresAt        int64 `json:"expires_at,omitempty"`
}

type ControlError struct {
	Code    string
	Message string
	Status  int
}

func (e *ControlError) Error() string { return e.Message }

func NewControlClient(options ControlClientOptions) (*ControlClient, error) {
	base, err := validatedControlURL(options.BaseURL)
	if err != nil {
		return nil, err
	}
	clientID, secret := strings.TrimSpace(options.ClientID), strings.TrimSpace(options.SecretKey)
	if clientID == "" || secret == "" {
		return nil, errors.New("client ID and secret key are required")
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	isolatedClient := *httpClient
	isolatedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &ControlClient{baseURL: base, clientID: clientID, secretKey: secret, httpClient: &isolatedClient}, nil
}

// ForUser returns a separate client acting with the supplied user's permissions.
// The application secret still selects the application/environment but does not
// elevate the user. Invalid sessions fail closed; privileged application-only
// methods will be rejected. The original application client is unchanged.
func (c *ControlClient) ForUser(accessToken string) (*ControlClient, error) {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" || strings.ContainsAny(accessToken, "\r\n") {
		return nil, errors.New("user access token is required and must not contain line breaks")
	}
	delegated := *c
	delegated.userToken = accessToken
	return &delegated, nil
}

func (c *ControlClient) Resource(ctx context.Context, resource string) (Resource, error) {
	var out Resource
	err := c.request(ctx, http.MethodGet, "/resources/"+url.PathEscape(requiredControl(resource, "resource")), "", nil, &out)
	return out, err
}

func (c *ControlClient) PutResource(ctx context.Context, resource string, input ResourceRegistration) (Resource, error) {
	var out Resource
	err := c.request(ctx, http.MethodPut, "/resources/"+url.PathEscape(requiredControl(resource, "resource")), "", input, &out)
	return out, err
}

func (c *ControlClient) CreateSystemResource(ctx context.Context, input ResourceRegistration, key string) (DurableOperation, error) {
	var out DurableOperation
	err := c.request(ctx, http.MethodPost, "/resources", key, input, &out)
	return out, err
}

func (c *ControlClient) MoveResource(ctx context.Context, resource, parent string, fence ResourceLifecycleFence, key string) (DurableOperation, error) {
	body := struct {
		Parent string `json:"parent"`
		ResourceLifecycleFence
	}{Parent: parent, ResourceLifecycleFence: fence}
	return c.operationRequest(ctx, http.MethodPost, "/resources/"+url.PathEscape(requiredControl(resource, "resource"))+"/move", key, body)
}

func (c *ControlClient) DisableResource(ctx context.Context, resource string, fence ResourceLifecycleFence, key string) (DurableOperation, error) {
	return c.lifecycle(ctx, resource, "disable", fence, key)
}

func (c *ControlClient) RestoreResource(ctx context.Context, resource string, fence ResourceLifecycleFence, key string) (DurableOperation, error) {
	return c.lifecycle(ctx, resource, "restore", fence, key)
}

func (c *ControlClient) DeleteResource(ctx context.Context, resource string, fence ResourceLifecycleFence, subtree bool, key string) (DurableOperation, error) {
	body := struct {
		ResourceLifecycleFence
		Subtree bool `json:"subtree"`
	}{fence, subtree}
	return c.operationRequest(ctx, http.MethodDelete, "/resources/"+url.PathEscape(requiredControl(resource, "resource")), key, body)
}

func (c *ControlClient) Operation(ctx context.Context, id string) (DurableOperation, error) {
	return c.operationRequest(ctx, http.MethodGet, "/operations/"+url.PathEscape(requiredControl(id, "operation ID")), "", nil)
}

func (c *ControlClient) WaitForOperation(ctx context.Context, id string, options OperationWaitOptions) (DurableOperation, error) {
	maxAttempts := options.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 120
	}
	interval := options.Interval
	if interval == 0 {
		interval = 500 * time.Millisecond
	}
	if maxAttempts < 1 || maxAttempts > 10000 || interval < 0 || interval > time.Minute {
		return DurableOperation{}, errors.New("invalid operation wait options")
	}
	for attempt := range maxAttempts {
		if err := ctx.Err(); err != nil {
			return DurableOperation{}, err
		}
		operation, err := c.Operation(ctx, id)
		if err != nil {
			return DurableOperation{}, err
		}
		switch operation.Status {
		case "succeeded", "failed", "cancelled":
			return operation, nil
		case "pending", "running":
		default:
			return DurableOperation{}, errors.New("invalid Lotor operation status")
		}
		if attempt+1 < maxAttempts {
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return DurableOperation{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return DurableOperation{}, errors.New("Lotor operation exceeded max attempts")
}

func (c *ControlClient) PutResourceType(ctx context.Context, resourceType string, definition ResourceTypeDefinition) (ResourceTypeDefinition, error) {
	if definition.AllowedParentTypes == nil {
		definition.AllowedParentTypes = []string{}
	}
	if definition.Relations == nil {
		definition.Relations = []string{}
	}
	if definition.Payload.Slots == nil {
		definition.Payload.Slots = []ResourcePayloadSlotPolicy{}
	}
	var out ResourceTypeDefinition
	err := c.request(ctx, http.MethodPut, "/resource-types/"+url.PathEscape(requiredControl(resourceType, "resource type")), "", definition, &out)
	return out, err
}

func (c *ControlClient) CreateCatalog(ctx context.Context, input CatalogCreation, key string) (Catalog, error) {
	var out Catalog
	err := c.request(ctx, http.MethodPost, "/catalogs", key, input, &out)
	return out, err
}

func (c *ControlClient) Catalog(ctx context.Context, id string) (Catalog, error) {
	var out Catalog
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(requiredControl(id, "catalog ID")), "", nil, &out)
	return out, err
}

func (c *ControlClient) Catalogs(ctx context.Context, cursor string, limit int) (CatalogList, error) {
	var out CatalogList
	err := c.request(ctx, http.MethodGet, "/catalogs"+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) ImportOpenAPI(ctx context.Context, catalogID string, input CatalogImportInput, key string) (DurableOperation, error) {
	return c.operationRequest(ctx, http.MethodPost, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/imports", key, input)
}

func (c *ControlClient) ImportDefinitions(ctx context.Context, catalogID string, entries []GenericCatalogDefinition, key string) (DurableOperation, error) {
	source, err := json.Marshal(struct {
		Entries []GenericCatalogDefinition `json:"entries"`
	}{Entries: entries})
	if err != nil {
		return DurableOperation{}, err
	}
	return c.operationRequest(ctx, http.MethodPost, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/imports", key, CatalogImportInput{Format: "definitions_v1", SourceDocument: string(source)})
}

func (c *ControlClient) CatalogSnapshots(ctx context.Context, catalogID, cursor string, limit int) (CatalogSnapshotList, error) {
	var out CatalogSnapshotList
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/snapshots"+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) PublishCatalogSnapshot(ctx context.Context, catalogID, snapshotID, key string) (DurableOperation, error) {
	return c.operationRequest(ctx, http.MethodPost, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/snapshots/"+url.PathEscape(requiredControl(snapshotID, "snapshot ID"))+"/publish", key, nil)
}

func (c *ControlClient) CatalogEntries(ctx context.Context, catalogID, cursor string, limit int) (CatalogEntryList, error) {
	var out CatalogEntryList
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/entries"+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) CatalogEntry(ctx context.Context, catalogID, entryID string) (CatalogEntry, error) {
	var out CatalogEntry
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/entries/"+url.PathEscape(requiredControl(entryID, "entry ID")), "", nil, &out)
	return out, err
}

func (c *ControlClient) BindResourceCatalog(ctx context.Context, resource string, input ResourceCatalogBindingInput, key string) (DurableOperation, error) {
	return c.operationRequest(ctx, http.MethodPut, "/resources/"+url.PathEscape(requiredControl(resource, "resource"))+"/catalog-binding", key, input)
}

func (c *ControlClient) IssueResourceCredential(ctx context.Context, resource string, input ResourceCredentialIssueInput, key string) (IssuedResourceCredential, error) {
	var out IssuedResourceCredential
	err := c.request(ctx, http.MethodPost, resourcePath(resource)+"/credentials", key, input, &out)
	return out, err
}

func (c *ControlClient) ResourceCredentials(ctx context.Context, resource string) ([]ResourceCredentialMetadata, error) {
	var out struct {
		Items []ResourceCredentialMetadata `json:"items"`
	}
	err := c.request(ctx, http.MethodGet, resourcePath(resource)+"/credentials", "", nil, &out)
	return out.Items, err
}

func (c *ControlClient) RotateResourceCredential(ctx context.Context, resource, credentialID string, input ResourceCredentialRotateInput, key string) (IssuedResourceCredential, error) {
	var out IssuedResourceCredential
	err := c.request(ctx, http.MethodPost, resourcePath(resource)+"/credentials/"+url.PathEscape(requiredControl(credentialID, "credential ID"))+"/rotate", key, input, &out)
	return out, err
}

func (c *ControlClient) RevokeResourceCredential(ctx context.Context, resource, credentialID, key string) (ResourceCredentialMetadata, error) {
	var out ResourceCredentialMetadata
	err := c.request(ctx, http.MethodDelete, resourcePath(resource)+"/credentials/"+url.PathEscape(requiredControl(credentialID, "credential ID")), key, nil, &out)
	return out, err
}

func (c *ControlClient) BeginResourcePayloadUpload(ctx context.Context, resource, slot string, input ResourcePayloadUploadInput) (ResourcePayloadUploadIntent, error) {
	var out ResourcePayloadUploadIntent
	headers, err := c.requestHeaders(ctx, http.MethodPost, resourcePayloadPath(resource, slot)+"/uploads", "", nil, input, &out)
	if err != nil {
		return ResourcePayloadUploadIntent{}, err
	}
	out.Token = strings.TrimSpace(headers.Get("Lotor-Payload-Token"))
	if out.Token == "" {
		return ResourcePayloadUploadIntent{}, errors.New("Lotor payload upload omitted its token")
	}
	return out, nil
}

func (c *ControlClient) UploadResourcePayloadObject(ctx context.Context, intent ResourcePayloadUploadIntent, object []byte) error {
	return uploadResourcePayloadObject(ctx, c.httpClient, intent, object)
}

func (c *ControlClient) CommitResourcePayload(ctx context.Context, resource, slot string, intent ResourcePayloadUploadIntent) (ResourcePayloadManifest, error) {
	var out ResourcePayloadManifest
	_, err := c.requestHeaders(ctx, http.MethodPost, resourcePayloadPath(resource, slot)+"/commits", "", http.Header{
		"Lotor-Payload-Token": []string{requiredControl(intent.Token, "payload token")},
	}, struct {
		ExpectedPayloadVersion int64 `json:"expected_payload_version"`
	}{intent.ExpectedPayloadVersion}, &out)
	return out, err
}

// ResourcePayloadRewrapInput preserves key and lifecycle fences. Browser custody
// supplies the optional attestation fields; box custody leaves them empty.
type ResourcePayloadRewrapInput struct {
	KeyBindingRef        string `json:"key_binding_ref"`
	WrappedPayloadKey    string `json:"wrapped_payload_key,omitempty"`
	RewrapperSubject     string `json:"rewrapper_subject,omitempty"`
	RewrapperKeyID       string `json:"rewrapper_key_id,omitempty"`
	RewrapReceipt        string `json:"rewrap_receipt,omitempty"`
	PayloadVersion       int64  `json:"payload_version"`
	ExpectedWrapRevision int64  `json:"expected_wrap_revision"`
	PreviousKeyVersion   int64  `json:"previous_key_version"`
	KeyVersion           int64  `json:"key_version"`
	ResourceRevision     int64  `json:"resource_revision"`
	LifecycleGeneration  int64  `json:"lifecycle_generation"`
}

type ResourcePayloadRewrapResult struct {
	Resource            string `json:"resource"`
	Slot                string `json:"slot"`
	KeyBindingRef       string `json:"key_binding_ref"`
	WrappedPayloadKey   string `json:"wrapped_payload_key"`
	AADHash             string `json:"aad_hash"`
	RewrapperSubject    string `json:"rewrapper_subject"`
	RewrapperKeyID      string `json:"rewrapper_key_id"`
	PayloadVersion      int64  `json:"payload_version"`
	WrapRevision        int64  `json:"wrap_revision"`
	PreviousKeyVersion  int64  `json:"previous_key_version"`
	KeyVersion          int64  `json:"key_version"`
	ResourceRevision    int64  `json:"resource_revision"`
	LifecycleGeneration int64  `json:"lifecycle_generation"`
}

// RewrapResourcePayload changes the wrapped payload key through the configured
// custody service without downloading or re-encrypting the stored object.
func (c *ControlClient) RewrapResourcePayload(ctx context.Context, resource, slot string, input ResourcePayloadRewrapInput) (ResourcePayloadRewrapResult, error) {
	var out ResourcePayloadRewrapResult
	err := c.request(ctx, http.MethodPost, resourcePayloadPath(resource, slot)+"/rewraps", "", input, &out)
	return out, err
}

func (c *ControlClient) DeleteResourcePayload(ctx context.Context, resource, slot, key string) (ResourcePayloadMutation, error) {
	var out ResourcePayloadMutation
	err := c.request(ctx, http.MethodDelete, resourcePayloadPath(resource, slot), key, nil, &out)
	return out, err
}

func (c *ControlClient) lifecycle(ctx context.Context, resource, action string, fence ResourceLifecycleFence, key string) (DurableOperation, error) {
	return c.operationRequest(ctx, http.MethodPost, "/resources/"+url.PathEscape(requiredControl(resource, "resource"))+"/"+action, key, fence)
}

func (c *ControlClient) operationRequest(ctx context.Context, method, path, key string, body any) (DurableOperation, error) {
	var out DurableOperation
	err := c.request(ctx, method, path, key, body, &out)
	return out, err
}

func (c *ControlClient) request(ctx context.Context, method, path, key string, body, out any) error {
	_, err := c.requestHeaders(ctx, method, path, key, nil, body, out)
	return err
}

func (c *ControlClient) requestHeaders(ctx context.Context, method, path, key string, extra http.Header, body, out any) (http.Header, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/v1/public/applications/"+url.PathEscape(c.clientID)+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Lotor-Secret-Key", c.secretKey)
	if c.userToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.userToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", requiredControl(key, "idempotency key"))
	}
	for name, values := range extra {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 4<<20 {
		return nil, errors.New("Lotor response exceeds limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem struct{ Code, Error string }
		_ = json.Unmarshal(raw, &problem)
		if problem.Code == "" {
			problem.Code = "request_failed"
		}
		if problem.Error == "" {
			problem.Error = fmt.Sprintf("Lotor request failed with status %d", response.StatusCode)
		}
		return nil, &ControlError{Status: response.StatusCode, Code: problem.Code, Message: problem.Error}
	}
	if out == nil || response.StatusCode == http.StatusNoContent {
		return response.Header.Clone(), nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return nil, errors.New("invalid Lotor response")
	}
	return response.Header.Clone(), nil
}

func requiredControl(value, name string) string {
	value = strings.TrimSpace(value)
	// Required-field policy is canonical in Control and its problem response.
	_ = name
	return value
}

func pagination(cursor string, limit int) string {
	query := url.Values{}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	if limit > 0 {
		query.Set("limit", strconv.Itoa(limit))
	}
	if len(query) == 0 {
		return ""
	}
	return "?" + query.Encode()
}
