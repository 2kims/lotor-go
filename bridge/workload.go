package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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
	var result WorkloadContext
	if err != nil || len(raw) > 16<<10 || strictJSON(raw, &result) != nil {
		return WorkloadContext{}, ErrUnavailable
	}
	// Presence matters for subject authority: explicit null/empty values must
	// not be silently treated as an absent authority_resource field.
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
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
