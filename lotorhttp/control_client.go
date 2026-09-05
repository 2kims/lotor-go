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
)

// ControlClient calls the public Control API as an application adapter. Its
// secret key must only be used from trusted server or CLI processes.
type ControlClient struct {
	httpClient *http.Client
	baseURL    string
	clientID   string
	secretKey  string
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
	ResourceType string `json:"resource_type"`
	DisplayName  string `json:"display_name,omitempty"`
	Parent       string `json:"parent,omitempty"`
	KeyScope     string `json:"key_scope,omitempty"`
}

type Resource struct {
	ID                  string          `json:"id"`
	Resource            string          `json:"resource"`
	ResourceType        string          `json:"resource_type"`
	DisplayName         string          `json:"display_name"`
	Parent              string          `json:"parent,omitempty"`
	Status              string          `json:"status"`
	Encryption          json.RawMessage `json:"encryption"`
	CatalogBinding      json.RawMessage `json:"catalog_binding,omitempty"`
	Revision            int64           `json:"revision"`
	LifecycleGeneration int64           `json:"lifecycle_generation"`
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

func (c *ControlClient) PutResourceType(ctx context.Context, resourceType string, definition any) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, http.MethodPut, "/resource-types/"+url.PathEscape(requiredControl(resourceType, "resource type")), "", definition, &out)
	return out, err
}

func (c *ControlClient) CreateCatalog(ctx context.Context, input any, key string) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, http.MethodPost, "/catalogs", key, input, &out)
	return out, err
}

func (c *ControlClient) Catalog(ctx context.Context, id string) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(requiredControl(id, "catalog ID")), "", nil, &out)
	return out, err
}

func (c *ControlClient) Catalogs(ctx context.Context, cursor string, limit int) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, http.MethodGet, "/catalogs"+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) ImportOpenAPI(ctx context.Context, catalogID string, input any, key string) (DurableOperation, error) {
	return c.operationRequest(ctx, http.MethodPost, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/imports", key, input)
}

func (c *ControlClient) CatalogSnapshots(ctx context.Context, catalogID, cursor string, limit int) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/snapshots"+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) PublishCatalogSnapshot(ctx context.Context, catalogID, snapshotID, key string) (DurableOperation, error) {
	return c.operationRequest(ctx, http.MethodPost, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/snapshots/"+url.PathEscape(requiredControl(snapshotID, "snapshot ID"))+"/publish", key, nil)
}

func (c *ControlClient) CatalogEntries(ctx context.Context, catalogID, cursor string, limit int) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/entries"+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) CatalogEntry(ctx context.Context, catalogID, entryID string) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/entries/"+url.PathEscape(requiredControl(entryID, "entry ID")), "", nil, &out)
	return out, err
}

func (c *ControlClient) BindResourceCatalog(ctx context.Context, resource string, input any, key string) (DurableOperation, error) {
	return c.operationRequest(ctx, http.MethodPut, "/resources/"+url.PathEscape(requiredControl(resource, "resource"))+"/catalog-binding", key, input)
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
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/v1/public/applications/"+url.PathEscape(c.clientID)+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Lotor-Secret-Key", c.secretKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", requiredControl(key, "idempotency key"))
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > 4<<20 {
		return errors.New("Lotor response exceeds limit")
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
		return &ControlError{Status: response.StatusCode, Code: problem.Code, Message: problem.Error}
	}
	if out == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return errors.New("invalid Lotor response")
	}
	return nil
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
