package lotorhttp

import (
	"context"
	"errors"
	"net/http"
)

type OrganizationE2EEPolicyInput struct {
	RequiredAccountCustody string `json:"required_account_custody"`
	ResourceKeyExecutor    string `json:"resource_key_executor"`
	AutomationExecutor     string `json:"automation_executor"`
	FunctionBindingID      string `json:"function_binding_id,omitempty"`
	ResourceKeyPolicy      string `json:"resource_key_policy"`
}

type OrganizationE2EEPolicy struct {
	Organization string `json:"organization"`
	OrganizationE2EEPolicyInput
	Status   string `json:"status"`
	Revision int64  `json:"revision"`
}

type ResourceGuestPolicyOverride struct {
	Allowed        *bool    `json:"allowed,omitempty"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
}

type ResourceCollaborationPolicyOverride struct {
	Guests ResourceGuestPolicyOverride `json:"guests"`
}

type ResourceCollaborationPolicyMutation struct {
	Resource string `json:"resource"`
	Revision int64  `json:"revision"`
}

func (c *ControlClient) OrganizationE2EEPolicy(ctx context.Context, organization string) (OrganizationE2EEPolicy, error) {
	var out OrganizationE2EEPolicy
	if err := c.requireResourceGraphUser(); err != nil {
		return out, err
	}
	organization, err := graphString(organization, "organization", 512)
	if err != nil {
		return out, err
	}
	err = c.strictRequest(ctx, http.MethodGet, graphResourcePath(organization)+"/e2ee", "", nil, nil, &out)
	if err == nil {
		err = validateOrganizationE2EEPolicy(out, organization)
	}
	return out, err
}

func (c *ControlClient) ConfigureOrganizationE2EE(ctx context.Context, organization string, input OrganizationE2EEPolicyInput) (OrganizationE2EEPolicy, error) {
	var out OrganizationE2EEPolicy
	if err := c.requireResourceGraphUser(); err != nil {
		return out, err
	}
	organization, err := graphString(organization, "organization", 512)
	if err != nil {
		return out, err
	}
	if err = validateOrganizationE2EEPolicyInput(input); err != nil {
		return out, err
	}
	err = c.strictRequest(ctx, http.MethodPut, graphResourcePath(organization)+"/e2ee", "", nil, input, &out)
	if err == nil {
		err = validateOrganizationE2EEPolicy(out, organization)
	}
	return out, err
}

func (c *ControlClient) SetResourceCollaborationPolicy(ctx context.Context, resource string, input ResourceCollaborationPolicyOverride) (ResourceCollaborationPolicyMutation, error) {
	var out ResourceCollaborationPolicyMutation
	if err := c.requireResourceGraphUser(); err != nil {
		return out, err
	}
	resource, err := graphString(resource, "resource", 512)
	if err != nil {
		return out, err
	}
	if err = validateResourceCollaborationPolicy(input); err != nil {
		return out, err
	}
	err = c.strictRequest(ctx, http.MethodPut, graphResourcePath(resource)+"/collaboration-policy", "", nil, input, &out)
	if err == nil && (out.Resource != resource || out.Revision < 1) {
		err = errors.New("invalid resource collaboration policy response")
	}
	return out, err
}

func validateOrganizationE2EEPolicyInput(input OrganizationE2EEPolicyInput) error {
	if !oneOf(input.RequiredAccountCustody, "browser_passphrase", "temporary_box_then_browser", "enterprise_box") ||
		!oneOf(input.ResourceKeyExecutor, "managed", "customer_box", "browser") ||
		!oneOf(input.AutomationExecutor, "managed", "customer_box", "none") ||
		!oneOf(input.ResourceKeyPolicy, "organization_only", "organization_default", "resource_only") {
		return errors.New("invalid organization E2EE policy")
	}
	if input.FunctionBindingID != "" {
		if _, err := graphString(input.FunctionBindingID, "function binding ID", 256); err != nil {
			return err
		}
	}
	return nil
}

func validateOrganizationE2EEPolicy(policy OrganizationE2EEPolicy, organization string) error {
	if policy.Organization != organization || policy.Revision < 1 || !oneOf(policy.Status, "pending", "ready", "unavailable") {
		return errors.New("invalid organization E2EE policy response")
	}
	return validateOrganizationE2EEPolicyInput(policy.OrganizationE2EEPolicyInput)
}

func validateResourceCollaborationPolicy(input ResourceCollaborationPolicyOverride) error {
	guests := input.Guests
	if guests.Allowed == nil && guests.AllowedDomains == nil {
		return errors.New("guest policy must contain a restriction")
	}
	if guests.AllowedDomains != nil && (len(guests.AllowedDomains) < 1 || len(guests.AllowedDomains) > 100) {
		return errors.New("guest policy must contain between 1 and 100 domains")
	}
	seen := map[string]bool{}
	for _, domain := range guests.AllowedDomains {
		value, err := graphString(domain, "allowed domain", 253)
		if err != nil || len(value) < 3 || seen[value] {
			return errors.New("invalid guest allowed domain")
		}
		seen[value] = true
	}
	return nil
}
