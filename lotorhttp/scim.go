package lotorhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type SCIMDirectory struct {
	ID                 string `json:"id"`
	Resource           string `json:"resource"`
	Organization       string `json:"organization"`
	CredentialResource string `json:"credential_resource"`
	Status             string `json:"status"`
	BaseURL            string `json:"base_url"`
	Revision           int64  `json:"revision"`
}

type SCIMDirectoryCreateInput struct {
	DirectoryResource           string `json:"directory_resource"`
	CredentialResource          string `json:"credential_resource"`
	ExpectedResourceRevision    int64  `json:"expected_resource_revision"`
	ExpectedLifecycleGeneration int64  `json:"expected_lifecycle_generation"`
}

type SCIMDirectoryUpdateInput struct {
	Enabled          bool  `json:"enabled"`
	ExpectedRevision int64 `json:"expected_revision"`
}

type SCIMDirectoryList struct {
	NextCursor  *string         `json:"next_cursor"`
	Directories []SCIMDirectory `json:"directories"`
}

func (c *ControlClient) scimPath(organization string) (string, error) {
	if c.userToken == "" {
		return "", errors.New("SCIM directory setup requires ForUser delegation")
	}
	if !scimString(organization, 256) {
		return "", errors.New("invalid SCIM organization")
	}
	return "/resources/" + url.PathEscape(organization) + "/scim-directories", nil
}

func scimString(value string, maximum int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func decodeSCIMDirectory(raw json.RawMessage) (SCIMDirectory, error) {
	var out SCIMDirectory
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	invalid := errors.New("invalid SCIM directory response")
	if decoder.Decode(&out) != nil || out.Revision < 1 || (out.Status != "disabled" && out.Status != "active") {
		return SCIMDirectory{}, invalid
	}
	for _, value := range []string{out.ID, out.Resource, out.Organization, out.CredentialResource} {
		if !scimString(value, 256) {
			return SCIMDirectory{}, invalid
		}
	}
	u, err := url.Parse(out.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return SCIMDirectory{}, invalid
	}
	return out, nil
}

func (c *ControlClient) CreateSCIMDirectory(ctx context.Context, organization string, input SCIMDirectoryCreateInput, idempotencyKey string) (SCIMDirectory, error) {
	path, err := c.scimPath(organization)
	if err != nil {
		return SCIMDirectory{}, err
	}
	if !scimString(input.DirectoryResource, 256) || !scimString(input.CredentialResource, 256) || !scimString(idempotencyKey, 256) || input.ExpectedResourceRevision < 1 || input.ExpectedLifecycleGeneration < 1 {
		return SCIMDirectory{}, errors.New("invalid SCIM directory creation input")
	}
	var raw json.RawMessage
	if err = c.request(ctx, http.MethodPost, path, idempotencyKey, input, &raw); err != nil {
		return SCIMDirectory{}, err
	}
	return decodeSCIMDirectory(raw)
}

func (c *ControlClient) SCIMDirectory(ctx context.Context, organization, directoryID string) (SCIMDirectory, error) {
	path, err := c.scimPath(organization)
	if err != nil {
		return SCIMDirectory{}, err
	}
	if !scimString(directoryID, 256) || directoryID == "." || directoryID == ".." || strings.ContainsAny(directoryID, "/\\") {
		return SCIMDirectory{}, errors.New("invalid SCIM directory ID")
	}
	var raw json.RawMessage
	if err = c.request(ctx, http.MethodGet, path+"/"+url.PathEscape(directoryID), "", nil, &raw); err != nil {
		return SCIMDirectory{}, err
	}
	out, err := decodeSCIMDirectory(raw)
	if err == nil && out.ID != directoryID {
		return SCIMDirectory{}, errors.New("SCIM directory response ID mismatch")
	}
	return out, err
}

func (c *ControlClient) UpdateSCIMDirectory(ctx context.Context, organization, directoryID string, input SCIMDirectoryUpdateInput, idempotencyKey string) (SCIMDirectory, error) {
	path, err := c.scimPath(organization)
	if err != nil {
		return SCIMDirectory{}, err
	}
	if !scimString(directoryID, 256) || directoryID == "." || directoryID == ".." || strings.ContainsAny(directoryID, "/\\") ||
		!scimString(idempotencyKey, 256) || input.ExpectedRevision < 1 {
		return SCIMDirectory{}, errors.New("invalid SCIM directory update input")
	}
	var raw json.RawMessage
	if err = c.request(ctx, http.MethodPut, path+"/"+url.PathEscape(directoryID), idempotencyKey, input, &raw); err != nil {
		return SCIMDirectory{}, err
	}
	out, err := decodeSCIMDirectory(raw)
	if err == nil && out.ID != directoryID {
		return SCIMDirectory{}, errors.New("SCIM directory response ID mismatch")
	}
	return out, err
}

func (c *ControlClient) SCIMDirectories(ctx context.Context, organization, cursor string, limit int) (SCIMDirectoryList, error) {
	path, err := c.scimPath(organization)
	if err != nil {
		return SCIMDirectoryList{}, err
	}
	if limit < 1 || limit > 100 || len(cursor) > 4096 {
		return SCIMDirectoryList{}, errors.New("invalid SCIM page options")
	}
	query := url.Values{"limit": {strconv.Itoa(limit)}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	var raw json.RawMessage
	if err = c.request(ctx, http.MethodGet, path+"?"+query.Encode(), "", nil, &raw); err != nil {
		return SCIMDirectoryList{}, err
	}
	var page struct {
		NextCursor  *string           `json:"next_cursor"`
		Directories []json.RawMessage `json:"directories"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields["next_cursor"] == nil {
		return SCIMDirectoryList{}, errors.New("invalid SCIM directory list response")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&page) != nil || page.Directories == nil || len(page.Directories) > 100 || (page.NextCursor != nil && !scimString(*page.NextCursor, 4096)) {
		return SCIMDirectoryList{}, errors.New("invalid SCIM directory list response")
	}
	result := SCIMDirectoryList{NextCursor: page.NextCursor, Directories: make([]SCIMDirectory, 0, len(page.Directories))}
	for _, item := range page.Directories {
		directory, decodeErr := decodeSCIMDirectory(item)
		if decodeErr != nil {
			return SCIMDirectoryList{}, decodeErr
		}
		result.Directories = append(result.Directories, directory)
	}
	return result, nil
}
