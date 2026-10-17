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

// WorkloadContext is the original Control-authenticated identity at the instant
// of validation. It is not a bearer credential, cacheable authorization lease,
// permission to read the authority resource, or an expansion of Resources.
type WorkloadContext struct {
	InvocationID      string `json:"invocation_id"`
	BindingID         string `json:"binding_id"`
	Scope             Scope  `json:"scope"`
	Principal         string `json:"principal"`
	AuthorityKind     string `json:"authority_kind"`
	AuthorityResource string `json:"authority_resource,omitempty"`
}

// WorkloadContext is available only inside a verified function handler. Every
// call revalidates with Control using this runtime's proof of the original grant;
// no user/API credential is forwarded and no response is cached.
func (client *ResourceClient) WorkloadContext(ctx context.Context) (WorkloadContext, error) {
	grant, original, ok := InvocationFromContext(ctx)
	if !ok || grant.Kind != "invocation" {
		return WorkloadContext{}, ErrUnauthorized
	}
	proof, err := SignValidation(ValidationRequest{Authorization: original}, client.validator.keyID, client.validator.key)
	if err != nil {
		return WorkloadContext{}, ErrInvalid
	}
	body, err := json.Marshal(proof)
	if err != nil {
		return WorkloadContext{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.validator.baseURL+"/v1/function-bindings/"+url.PathEscape(grant.BindingID)+"/authorizations/context", bytes.NewReader(body))
	if err != nil {
		return WorkloadContext{}, ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.validator.client.Do(request)
	if err != nil {
		return WorkloadContext{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusUnauthorized {
		return WorkloadContext{}, ErrUnauthorized
	}
	if response.StatusCode != http.StatusOK {
		return WorkloadContext{}, ErrUnavailable
	}
	// Identity metadata is small even when the original grant contains a large
	// protected request. Do not accept arbitrary payloads from a dependency.
	raw, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	if err != nil || len(raw) > 16<<10 {
		return WorkloadContext{}, ErrUnavailable
	}
	// Check exact names and duplicates before Go's case-insensitive struct
	// decoder can merge aliases or retain a value preceding a duplicate null.
	fields, err := workloadObjectFields(raw, "invocation_id", "binding_id", "scope", "principal", "authority_kind", "authority_resource")
	if err != nil {
		return WorkloadContext{}, ErrUnavailable
	}
	if _, err = workloadObjectFields(fields["scope"], "tenant_id", "application_id", "environment_id", "owner_resource"); err != nil {
		return WorkloadContext{}, ErrUnavailable
	}
	var result WorkloadContext
	if strictJSON(raw, &result) != nil {
		return WorkloadContext{}, ErrUnavailable
	}
	_, hasAuthorityResource := fields["authority_resource"]
	if result.InvocationID != grant.ID || result.BindingID != grant.BindingID || result.Scope != grant.Scope || result.Principal != grant.Principal ||
		!validScope(result.Scope) || !identifier(result.Principal, 256) ||
		!(result.AuthorityKind == "subject" && !hasAuthorityResource || result.AuthorityKind == "resource_credential" && identifier(result.AuthorityResource, 256)) {
		return WorkloadContext{}, ErrUnavailable
	}
	return result, nil
}

// workloadObjectFields is deliberately local to workload-context decoding; it
// does not change decoding of other SDK protocols or signed payload bytes.
func workloadObjectFields(raw []byte, names ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalid
	}
	fields := make(map[string]json.RawMessage, len(names))
	for decoder.More() {
		token, err = decoder.Token()
		name, ok := token.(string)
		_, duplicate := fields[name]
		if err != nil || !ok || duplicate || !slices.Contains(names, name) {
			return nil, ErrInvalid
		}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return nil, ErrInvalid
		}
		fields[name] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrInvalid
	}
	return fields, nil
}
