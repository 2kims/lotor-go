package lotorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var organizationBindingIDPattern = regexp.MustCompile(`^efb_[A-Za-z0-9_-]+$`)

type OrganizationFunctionBindingBootstrap struct {
	BindingID      string `json:"binding_id"`
	Status         string `json:"status"`
	BootstrapToken string `json:"bootstrap_token"`
}

// OrganizationFunctionBindingStatus never contains connector or bootstrap secrets.
// Timestamps use Unix microseconds; registration does not assert box readiness.
type OrganizationFunctionBindingStatus struct {
	BindingID          string                                     `json:"binding_id"`
	Status             string                                     `json:"status"`
	BoxSubject         string                                     `json:"box_subject,omitempty"`
	SigningKeyID       string                                     `json:"signing_key_id,omitempty"`
	Challenge          OrganizationFunctionBindingChallengeStatus `json:"challenge"`
	BootstrapExpiresAt int64                                      `json:"bootstrap_expires_at,omitempty"`
	LastSeenAt         int64                                      `json:"last_seen_at,omitempty"`
}

// ExpiresAt is the pending challenge completion deadline, not a ready-key lease.
// Both timestamps are Unix microseconds.
type OrganizationFunctionBindingChallengeStatus struct {
	Status       string `json:"status"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	ChallengedAt int64  `json:"challenged_at,omitempty"`
}

func (c *ControlClient) StartOrganizationFunctionBindingChallenge(ctx context.Context, organization, bindingID string) (OrganizationFunctionBindingChallengeStatus, error) {
	if !organizationBindingIDPattern.MatchString(bindingID) {
		return OrganizationFunctionBindingChallengeStatus{}, errors.New("invalid binding ID")
	}
	path, err := c.organizationBindingPath(organization, bindingID)
	if err != nil {
		return OrganizationFunctionBindingChallengeStatus{}, err
	}
	var raw json.RawMessage
	if err = c.request(ctx, http.MethodPost, path+"/challenge", "", nil, &raw); err != nil {
		return OrganizationFunctionBindingChallengeStatus{}, err
	}
	return decodeOrganizationBindingChallenge(raw)
}

func decodeOrganizationBindingChallenge(raw json.RawMessage) (OrganizationFunctionBindingChallengeStatus, error) {
	var fields map[string]json.RawMessage
	var out OrganizationFunctionBindingChallengeStatus
	invalid := errors.New("invalid organization box challenge response")
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(raw, &out) != nil {
		return out, invalid
	}
	for field := range fields {
		if field != "status" && field != "expires_at" && field != "challenged_at" {
			return OrganizationFunctionBindingChallengeStatus{}, invalid
		}
	}
	if out.ExpiresAt < 0 || out.ChallengedAt < 0 {
		return OrganizationFunctionBindingChallengeStatus{}, invalid
	}
	switch out.Status {
	case "not_started", "failed", "unavailable":
	case "pending", "expired":
		if out.ExpiresAt == 0 {
			return OrganizationFunctionBindingChallengeStatus{}, invalid
		}
	case "ready":
		if out.ChallengedAt == 0 {
			return OrganizationFunctionBindingChallengeStatus{}, invalid
		}
	default:
		return OrganizationFunctionBindingChallengeStatus{}, invalid
	}
	return out, nil
}

func (c *ControlClient) organizationBindingPath(organization, bindingID string) (string, error) {
	if c.userToken == "" {
		return "", errors.New("organization box operations require ForUser delegation")
	}
	if strings.TrimSpace(organization) == "" || len(organization) > 512 || len(bindingID) > 256 {
		return "", errors.New("invalid organization binding input")
	}
	path := "/resources/" + url.PathEscape(organization) + "/e2ee/function-bindings"
	if bindingID != "" {
		path += "/" + url.PathEscape(bindingID)
	}
	return path, nil
}

func (c *ControlClient) CreateOrganizationFunctionBinding(ctx context.Context, organization string) (OrganizationFunctionBindingBootstrap, error) {
	var out OrganizationFunctionBindingBootstrap
	path, err := c.organizationBindingPath(organization, "")
	if err != nil {
		return out, err
	}
	if err = c.request(ctx, http.MethodPost, path, "", nil, &out); err != nil {
		return OrganizationFunctionBindingBootstrap{}, err
	}
	if out.Status != "pending" || !organizationBindingIDPattern.MatchString(out.BindingID) || !strings.HasPrefix(out.BootstrapToken, "e2ee_bootstrap_") || len(out.BootstrapToken) <= len("e2ee_bootstrap_") {
		return OrganizationFunctionBindingBootstrap{}, errors.New("invalid organization box bootstrap response")
	}
	return out, nil
}

func (c *ControlClient) ListOrganizationFunctionBindings(ctx context.Context, organization string) ([]OrganizationFunctionBindingStatus, error) {
	path, err := c.organizationBindingPath(organization, "")
	if err != nil {
		return nil, err
	}
	var raw []json.RawMessage
	if err = c.request(ctx, http.MethodGet, path, "", nil, &raw); err != nil {
		return nil, err
	}
	if raw == nil || len(raw) > 1 {
		return nil, errors.New("invalid current organization bindings response")
	}
	out := make([]OrganizationFunctionBindingStatus, 0, len(raw))
	for _, value := range raw {
		binding, decodeErr := decodeOrganizationBinding(value)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if binding.Status == "revoked" {
			return nil, errors.New("invalid current organization binding state")
		}
		out = append(out, binding)
	}
	return out, nil
}

func (c *ControlClient) GetOrganizationFunctionBinding(ctx context.Context, organization, bindingID string) (OrganizationFunctionBindingStatus, error) {
	if strings.TrimSpace(bindingID) == "" {
		return OrganizationFunctionBindingStatus{}, errors.New("binding ID is required")
	}
	path, err := c.organizationBindingPath(organization, bindingID)
	if err != nil {
		return OrganizationFunctionBindingStatus{}, err
	}
	var raw json.RawMessage
	if err = c.request(ctx, http.MethodGet, path, "", nil, &raw); err != nil {
		return OrganizationFunctionBindingStatus{}, err
	}
	out, err := decodeOrganizationBinding(raw)
	if err != nil {
		return OrganizationFunctionBindingStatus{}, err
	}
	if out.BindingID != bindingID {
		return OrganizationFunctionBindingStatus{}, errors.New("Lotor returned a different organization binding")
	}
	return out, nil
}

func (c *ControlClient) RevokeOrganizationFunctionBinding(ctx context.Context, organization, bindingID string) error {
	if strings.TrimSpace(bindingID) == "" {
		return errors.New("binding ID is required")
	}
	path, err := c.organizationBindingPath(organization, bindingID)
	if err != nil {
		return err
	}
	return c.request(ctx, http.MethodDelete, path, "", nil, nil)
}

func decodeOrganizationBinding(raw json.RawMessage) (OrganizationFunctionBindingStatus, error) {
	var fields map[string]json.RawMessage
	var out OrganizationFunctionBindingStatus
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(raw, &out) != nil {
		return out, errors.New("invalid organization box status response")
	}
	for _, field := range []string{"bootstrap_token", "connector_token", "bootstrap_token_hash", "connector_token_hash"} {
		if _, exists := fields[field]; exists {
			return OrganizationFunctionBindingStatus{}, errors.New("organization box status contains credentials")
		}
	}
	if !organizationBindingIDPattern.MatchString(out.BindingID) || out.BootstrapExpiresAt < 0 || out.LastSeenAt < 0 {
		return OrganizationFunctionBindingStatus{}, errors.New("invalid organization box status response")
	}
	challenge, err := decodeOrganizationBindingChallenge(fields["challenge"])
	if err != nil {
		return OrganizationFunctionBindingStatus{}, err
	}
	out.Challenge = challenge
	switch out.Status {
	case "pending", "expired", "active", "revoked":
		return out, nil
	default:
		return OrganizationFunctionBindingStatus{}, errors.New("invalid organization box status response")
	}
}
