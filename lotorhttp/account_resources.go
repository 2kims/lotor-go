package lotorhttp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

type AccountResourceReference struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Type     string `json:"type"`
	Name     string `json:"name"`
}

type AccountResourcePathStep struct {
	AccountResourceReference
	SubjectRelation string `json:"subject_relation"`
}

type AccountResourceAccessPath struct {
	Type     string                    `json:"type"`
	Relation string                    `json:"relation"`
	Via      []AccountResourcePathStep `json:"via"`
}

type AccountResourceAccess struct {
	Paths  []AccountResourceAccessPath `json:"paths"`
	Direct bool                        `json:"direct"`
}

type AccountResource struct {
	AccountResourceReference
	Parent      *AccountResourceReference `json:"parent,omitempty"`
	Relations   []string                  `json:"relations"`
	AccessState string                    `json:"access_state"`
	Access      AccountResourceAccess     `json:"access"`
}

type AccountResourceList struct {
	NextCursor *string           `json:"next_cursor"`
	Resources  []AccountResource `json:"resources"`
}

// AccountResourceListOptions filters a member directory, not management search.
// Limit zero uses the server default. Cursor is opaque and bound to the filters.
type AccountResourceListOptions struct {
	Parent       string
	Cursor       string
	Types        []string
	AccessStates []string
	Limit        int
}

// AccountResources lists resources visible to the delegated user. Use ForUser;
// this method never substitutes application authority for a denied user request.
func (c *ControlClient) AccountResources(ctx context.Context, options AccountResourceListOptions) (AccountResourceList, error) {
	var out AccountResourceList
	if options.Limit < 0 || options.Limit > 100 || len(options.Parent) > 512 || len(options.Cursor) > 2048 {
		return out, errors.New("invalid account resource directory options")
	}
	query := url.Values{}
	if options.Parent != "" {
		query.Set("parent", options.Parent)
	}
	if options.Cursor != "" {
		query.Set("cursor", options.Cursor)
	}
	if options.Limit != 0 {
		query.Set("limit", strconv.Itoa(options.Limit))
	}
	for _, kind := range options.Types {
		if len(kind) == 0 || len(kind) > 128 {
			return out, errors.New("invalid resource type")
		}
		query.Add("type", kind)
	}
	for _, state := range options.AccessStates {
		if state != "active" && state != "pending_encryption" {
			return out, errors.New("invalid resource access state")
		}
		query.Add("access_state", state)
	}
	path := "/me/resources"
	if len(query) != 0 {
		path += "?" + query.Encode()
	}
	err := c.request(ctx, http.MethodGet, path, "", nil, &out)
	return out, err
}
