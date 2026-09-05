package lotorhttp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ResourceClient authenticates one workload principal with a Lotor-issued
// resource credential and the application's publishable key. It cannot use or
// accept an application secret.
type ResourceClient struct {
	httpClient         *http.Client
	baseURL            string
	clientID           string
	publishableKey     string
	resourceCredential string
}

type ResourceClientOptions struct {
	HTTPClient         *http.Client
	BaseURL            string
	ClientID           string
	PublishableKey     string
	ResourceCredential string
}

func NewResourceClient(options ResourceClientOptions) (*ResourceClient, error) {
	base, err := validatedControlURL(options.BaseURL)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(options.ClientID)
	publishableKey := strings.TrimSpace(options.PublishableKey)
	credential := strings.TrimSpace(options.ResourceCredential)
	if clientID == "" || publishableKey == "" || credential == "" {
		return nil, errors.New("client ID, publishable key, and resource credential are required")
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	isolatedClient := *httpClient
	isolatedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &ResourceClient{httpClient: &isolatedClient, baseURL: base, clientID: clientID, publishableKey: publishableKey, resourceCredential: credential}, nil
}

type ResourceExecutionRequest struct {
	Method            string `json:"method"`
	Path              string `json:"path"`
	ContentType       string `json:"content_type"`
	RequestBodyDigest string `json:"request_body_digest"`
	RequestBodySize   int64  `json:"request_body_size"`
}

type ResourceCredentialExchangeInput struct {
	Audience             string `json:"audience"`
	Method               string `json:"method"`
	Path                 string `json:"path"`
	BodySHA256           string `json:"body_sha256"`
	QuerySHA256          string `json:"query_sha256"`
	IdempotencyKeySHA256 string `json:"idempotency_key_sha256,omitempty"`
	ExpiresIn            int64  `json:"expires_in,omitempty"`
}

type ResourceCredentialExchange struct {
	Assertion         string `json:"assertion"`
	TokenType         string `json:"token_type"`
	Subject           string `json:"subject"`
	APIKeyResource    string `json:"api_key_resource"`
	ClientID          string `json:"client_id"`
	ApplicationID     string `json:"application_id"`
	EnvironmentID     string `json:"environment_id"`
	EnvironmentMode   string `json:"environment_mode"`
	ExpiresAt         int64  `json:"expires_at"`
	CredentialVersion int64  `json:"credential_version"`
}

func (c *ResourceClient) ExchangeCredential(ctx context.Context, input ResourceCredentialExchangeInput) (ResourceCredentialExchange, error) {
	var out ResourceCredentialExchange
	_, err := c.request(ctx, http.MethodPost, "/credential-exchanges", nil, input, &out)
	return out, err
}

type ResourceExecutionPreflight struct {
	PolicyRevision        string `json:"policy_revision"`
	Resource              string `json:"resource"`
	Path                  string `json:"path"`
	ContentType           string `json:"content_type"`
	RequestBodyDigest     string `json:"request_body_digest"`
	Token                 string `json:"-"`
	CatalogEntryRevision  string `json:"catalog_entry_revision"`
	RequestAAD            string `json:"request_aad,omitempty"`
	ResponsePolicyRef     string `json:"response_policy_ref,omitempty"`
	CatalogSnapshotID     string `json:"catalog_snapshot_id"`
	Method                string `json:"method"`
	CatalogEntryID        string `json:"catalog_entry_id"`
	KeyResource           string `json:"key_resource,omitempty"`
	PayloadSlot           string `json:"payload_slot"`
	ExecutionMode         string `json:"execution_mode"`
	PayloadRepresentation string `json:"payload_representation"`
	RequestFingerprint    string `json:"request_fingerprint"`
	PayloadVersion        int64  `json:"payload_version"`
	CredentialVersion     int64  `json:"credential_version"`
	KeyVersion            int64  `json:"key_version,omitempty"`
	LifecycleGeneration   int64  `json:"lifecycle_generation"`
	ResourceRevision      int64  `json:"resource_revision"`
	ExpiresAt             int64  `json:"expires_at"`
	RequestBodySize       int64  `json:"request_body_size"`
}

type ResourceExecutionAuthorization struct {
	Status                string `json:"status"`
	RequestFingerprint    string `json:"request_fingerprint"`
	Resource              string `json:"resource"`
	CatalogEntryID        string `json:"catalog_entry_id"`
	PayloadSlot           string `json:"payload_slot"`
	PayloadRepresentation string `json:"payload_representation"`
	ExecutionMode         string `json:"execution_mode"`
	ProtectedResponse     string `json:"protected_response,omitempty"`
	PayloadVersion        int64  `json:"payload_version"`
	ProviderStatus        int    `json:"provider_status,omitempty"`
	ExpiresAt             int64  `json:"expires_at"`
}

type ResourceExecutionCommitInput struct {
	ProtectedRequest  string `json:"protected_request,omitempty"`
	ResponsePolicyRef string `json:"response_policy_ref,omitempty"`
}

func (c *ResourceClient) PreflightExecution(ctx context.Context, resource string, input ResourceExecutionRequest) (ResourceExecutionPreflight, error) {
	var out ResourceExecutionPreflight
	headers, err := c.request(ctx, http.MethodPost, resourcePath(resource)+"/executions/preflight", nil, input, &out)
	if err != nil {
		return ResourceExecutionPreflight{}, err
	}
	out.Token = strings.TrimSpace(headers.Get("Lotor-Execution-Token"))
	if out.Token == "" {
		return ResourceExecutionPreflight{}, errors.New("Lotor execution preflight omitted its token")
	}
	return out, nil
}

func (c *ResourceClient) CommitExecution(ctx context.Context, resource string, preflight ResourceExecutionPreflight, input ResourceExecutionCommitInput) (ResourceExecutionAuthorization, error) {
	var out ResourceExecutionAuthorization
	_, err := c.request(ctx, http.MethodPost, resourcePath(resource)+"/executions/commit", http.Header{
		"Lotor-Execution-Token": []string{requiredControl(preflight.Token, "execution token")},
	}, struct {
		RequestFingerprint string `json:"request_fingerprint"`
		ProtectedRequest   string `json:"protected_request,omitempty"`
		ResponsePolicyRef  string `json:"response_policy_ref,omitempty"`
	}{preflight.RequestFingerprint, input.ProtectedRequest, input.ResponsePolicyRef}, &out)
	return out, err
}

type ProviderPlainRequest struct {
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

type ProviderProtectedResponse struct {
	Headers map[string]string
	Body    []byte
	Status  int
}

// ProtectProviderRequest encrypts a provider request using the exact AAD and
// effective resource key selected by preflight. The resource key remains in
// the caller's custody and is never sent to Lotor.
func ProtectProviderRequest(resourceKey []byte, preflight ResourceExecutionPreflight, input ProviderPlainRequest) (string, error) {
	if len(input.Body) > 1<<20 {
		return "", errors.New("provider request body exceeds 1 MiB")
	}
	if preflight.PayloadRepresentation != "encrypted-envelope-v1" || preflight.ResponsePolicyRef != "encrypt_all" || preflight.RequestAAD == "" {
		return "", errors.New("execution preflight is not encrypted")
	}
	aad, err := base64.RawURLEncoding.DecodeString(preflight.RequestAAD)
	if err != nil || len(aad) == 0 {
		return "", errors.New("invalid execution request AAD")
	}
	bodyDigest := sha256.Sum256(input.Body)
	if int64(len(input.Body)) != preflight.RequestBodySize || hex.EncodeToString(bodyDigest[:]) != preflight.RequestBodyDigest {
		return "", errors.New("provider request body does not match execution preflight")
	}
	headers := make(map[string]string, len(input.Headers)+1)
	for name, value := range input.Headers {
		if len(value) > 8192 || strings.ContainsAny(value, "\r\n") {
			return "", errors.New("provider request contains invalid header value")
		}
		if !strings.EqualFold(name, "Accept") && !strings.EqualFold(name, "Content-Type") {
			return "", errors.New("provider request contains unsupported header")
		}
		if strings.EqualFold(name, "Accept") {
			headers["Accept"] = value
		}
	}
	headers["Content-Type"] = preflight.ContentType
	body, err := json.Marshal(struct {
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}{headers, base64.RawURLEncoding.EncodeToString(input.Body)})
	if err != nil {
		return "", err
	}
	return sealExecutionPayload(resourceKey, body, aad)
}

// OpenProviderResponse decrypts the complete provider response returned by an
// encrypted execution commit and verifies its command-bound response AAD.
func OpenProviderResponse(resourceKey []byte, preflight ResourceExecutionPreflight, authorization ResourceExecutionAuthorization) (ProviderProtectedResponse, error) {
	if authorization.Status != "completed" || authorization.ProviderStatus < 100 || authorization.ProviderStatus > 599 || authorization.ProtectedResponse == "" {
		return ProviderProtectedResponse{}, errors.New("execution did not return a protected provider response")
	}
	if authorization.RequestFingerprint != preflight.RequestFingerprint || authorization.Resource != preflight.Resource ||
		authorization.CatalogEntryID != preflight.CatalogEntryID || authorization.PayloadSlot != preflight.PayloadSlot ||
		authorization.PayloadVersion != preflight.PayloadVersion || authorization.PayloadRepresentation != preflight.PayloadRepresentation ||
		authorization.ExecutionMode != preflight.ExecutionMode || authorization.ExpiresAt != preflight.ExpiresAt {
		return ProviderProtectedResponse{}, errors.New("execution response does not match preflight")
	}
	requestAAD, err := base64.RawURLEncoding.DecodeString(preflight.RequestAAD)
	if err != nil || len(requestAAD) == 0 {
		return ProviderProtectedResponse{}, errors.New("invalid execution request AAD")
	}
	requestHash := sha256.Sum256(requestAAD)
	responseAAD := []byte(fmt.Sprintf("lotor-provider-response-v1\x00%x\x00%d", requestHash, authorization.ProviderStatus))
	plaintext, err := openExecutionPayload(resourceKey, authorization.ProtectedResponse, responseAAD)
	if err != nil {
		return ProviderProtectedResponse{}, err
	}
	var decoded struct {
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
		Status  int               `json:"status"`
	}
	if json.Unmarshal(plaintext, &decoded) != nil || decoded.Status != authorization.ProviderStatus {
		return ProviderProtectedResponse{}, errors.New("invalid protected provider response")
	}
	responseBody, err := base64.RawURLEncoding.DecodeString(decoded.Body)
	if err != nil || len(responseBody) > 1<<20 {
		return ProviderProtectedResponse{}, errors.New("invalid protected provider response body")
	}
	return ProviderProtectedResponse{Status: decoded.Status, Headers: decoded.Headers, Body: responseBody}, nil
}

type executionEnvelope struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	AADHash    string `json:"aad_hash"`
}

func sealExecutionPayload(key, plaintext, aad []byte) (string, error) {
	aead, err := executionAEAD(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	digest := sha256.Sum256(aad)
	wire, err := json.Marshal(executionEnvelope{Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext), AADHash: hex.EncodeToString(digest[:])})
	if err != nil {
		return "", err
	}
	if base64.RawURLEncoding.EncodedLen(len(wire)) > 3<<20 {
		return "", errors.New("protected provider payload exceeds 3 MiB")
	}
	return base64.RawURLEncoding.EncodeToString(wire), nil
}

func openExecutionPayload(key []byte, encoded string, aad []byte) ([]byte, error) {
	if len(encoded) > 3<<20 {
		return nil, errors.New("protected provider payload exceeds 3 MiB")
	}
	wire, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid protected provider response")
	}
	var envelope executionEnvelope
	if json.Unmarshal(wire, &envelope) != nil {
		return nil, errors.New("invalid protected provider response")
	}
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	ciphertext, ciphertextErr := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	digest := sha256.Sum256(aad)
	if nonceErr != nil || ciphertextErr != nil || len(nonce) != 12 || envelope.AADHash != hex.EncodeToString(digest[:]) {
		return nil, errors.New("invalid protected provider response")
	}
	aead, err := executionAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("protected provider response authentication failed")
	}
	return plaintext, nil
}

func executionAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("resource key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

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

type ResourcePayloadUploadInput struct {
	KeyBindingRef          string `json:"key_binding_ref,omitempty"`
	EncryptorKeyID         string `json:"encryptor_key_id,omitempty"`
	EncryptionReceipt      string `json:"encryption_receipt,omitempty"`
	ObjectDigest           string `json:"object_digest"`
	WrappedPayloadKey      string `json:"wrapped_payload_key,omitempty"`
	EncryptionSuite        string `json:"encryption_suite,omitempty"`
	Representation         string `json:"representation"`
	EncryptorSubject       string `json:"encryptor_subject,omitempty"`
	SchemaID               string `json:"schema_id"`
	AADHash                string `json:"aad_hash,omitempty"`
	ObjectSize             int64  `json:"object_size"`
	KeyVersion             int64  `json:"key_version,omitempty"`
	ExpectedPayloadVersion int64  `json:"expected_payload_version"`
	ResourceRevision       int64  `json:"resource_revision"`
	LifecycleGeneration    int64  `json:"lifecycle_generation"`
}

type ResourcePayloadUploadIntent struct {
	RequiredHeaders        map[string]string `json:"required_headers"`
	Resource               string            `json:"resource"`
	Slot                   string            `json:"slot"`
	UploadURL              string            `json:"upload_url"`
	UploadMethod           string            `json:"upload_method"`
	Token                  string            `json:"-"`
	PayloadVersion         int64             `json:"payload_version"`
	ExpectedPayloadVersion int64             `json:"expected_payload_version"`
	ExpiresAt              int64             `json:"expires_at"`
}

type ResourcePayloadMutation struct {
	Resource       string `json:"resource"`
	Slot           string `json:"slot"`
	State          string `json:"state"`
	PayloadVersion int64  `json:"payload_version"`
	Idempotent     bool   `json:"idempotent"`
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

func (c *ResourceClient) ResourcePayload(ctx context.Context, resource, slot string) (ResourcePayloadManifest, error) {
	var out ResourcePayloadManifest
	_, err := c.request(ctx, http.MethodGet, resourcePayloadPath(resource, slot), nil, nil, &out)
	return out, err
}

func (c *ResourceClient) AccessResourcePayload(ctx context.Context, resource, slot string, payloadVersion int64) (ResourcePayloadAccessLease, error) {
	var out ResourcePayloadAccessLease
	body := struct {
		PayloadVersion int64 `json:"payload_version,omitempty"`
	}{payloadVersion}
	_, err := c.request(ctx, http.MethodPost, resourcePayloadPath(resource, slot)+"/access", nil, body, &out)
	return out, err
}

func (c *ResourceClient) DownloadResourcePayload(ctx context.Context, lease ResourcePayloadAccessLease) ([]byte, error) {
	parsed, err := validatedObjectURL(lease.DownloadURL)
	if err != nil || lease.DownloadMethod != http.MethodGet {
		return nil, errors.New("invalid resource payload access lease")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return nil, fmt.Errorf("resource payload download failed with status %d", response.StatusCode)
	}
	limit := lease.ObjectSize
	if limit < 0 || limit > 64<<20 {
		return nil, errors.New("invalid resource payload object size")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(raw)) != limit {
		return nil, errors.New("resource payload download size does not match lease")
	}
	digest := sha256.Sum256(raw)
	if fmt.Sprintf("%x", digest[:]) != strings.ToLower(strings.TrimSpace(lease.ObjectDigest)) {
		return nil, errors.New("resource payload download digest does not match lease")
	}
	return raw, nil
}

func uploadResourcePayloadObject(ctx context.Context, client *http.Client, intent ResourcePayloadUploadIntent, object []byte) error {
	parsed, err := validatedObjectURL(intent.UploadURL)
	if err != nil || intent.UploadMethod != http.MethodPut || int64(len(object)) < 1 {
		return errors.New("invalid resource payload upload intent")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, parsed.String(), bytes.NewReader(object))
	if err != nil {
		return err
	}
	for name, value := range intent.RequiredHeaders {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "X-Lotor-Secret-Key") || strings.EqualFold(name, "X-Lotor-Publishable-Key") {
			return errors.New("unsafe resource payload upload header")
		}
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("resource payload upload failed with status %d", response.StatusCode)
	}
	return nil
}

func (c *ResourceClient) request(ctx context.Context, method, path string, headers http.Header, body, out any) (http.Header, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/v1/public/applications/"+url.PathEscape(c.clientID)+path, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.resourceCredential)
	request.Header.Set("X-Lotor-Publishable-Key", c.publishableKey)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := c.httpClient.Do(request)
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
		return nil, decodeControlError(response.StatusCode, raw)
	}
	if out != nil && response.StatusCode != http.StatusNoContent {
		if json.Unmarshal(raw, out) != nil {
			return nil, errors.New("invalid Lotor response")
		}
	}
	return response.Header.Clone(), nil
}

func decodeControlError(status int, raw []byte) error {
	var problem struct{ Code, Error string }
	_ = json.Unmarshal(raw, &problem)
	if problem.Code == "" {
		problem.Code = "request_failed"
	}
	if problem.Error == "" {
		problem.Error = "Lotor request failed with status " + strconv.Itoa(status)
	}
	return &ControlError{Status: status, Code: problem.Code, Message: problem.Error}
}

func resourcePath(resource string) string {
	return "/resources/" + url.PathEscape(requiredControl(resource, "resource"))
}

func resourcePayloadPath(resource, slot string) string {
	return resourcePath(resource) + "/payloads/" + url.PathEscape(requiredControl(slot, "payload slot"))
}

func validatedObjectURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback(parsed.Hostname()))) {
		return nil, errors.New("invalid object URL")
	}
	return parsed, nil
}
