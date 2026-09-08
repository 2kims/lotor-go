package lotorhttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type PortalSessionInput struct {
	OrganizationID string `json:"organization_id"`
	ReturnURL      string `json:"return_url"`
}

type PortalSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// CreatePortalSession uses delegated user authority. The user must manage the
// organization; an application secret alone is not sufficient.
func (c *ControlClient) CreatePortalSession(ctx context.Context, input PortalSessionInput) (PortalSession, error) {
	var out PortalSession
	parsed, err := url.ParseRequestURI(input.ReturnURL)
	if strings.TrimSpace(input.OrganizationID) == "" || len(input.OrganizationID) > 256 || err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback(parsed.Hostname()))) {
		return out, errors.New("invalid portal session input")
	}
	if err = c.request(ctx, http.MethodPost, "/billing/portal-sessions", "", input, &out); err != nil {
		return PortalSession{}, err
	}
	parsed, err = url.Parse(out.URL)
	if err != nil || out.ID == "" || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return PortalSession{}, errors.New("invalid portal session response")
	}
	return out, nil
}
