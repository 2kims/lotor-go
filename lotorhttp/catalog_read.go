package lotorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

type CatalogEntry struct {
	ID             string          `json:"id"`
	CatalogID      string          `json:"catalog_id"`
	SemanticKey    string          `json:"semantic_key"`
	EntryKind      string          `json:"entry_kind"`
	RevisionID     string          `json:"revision_id"`
	RevisionDigest string          `json:"revision_digest"`
	Definition     json.RawMessage `json:"definition"`
}

type CatalogEntryList struct {
	NextCursor *string        `json:"next_cursor"`
	Items      []CatalogEntry `json:"items"`
}

// ResourceCatalogEntries reads the exact published binding using this client's
// principal. Use ForUser for requests on behalf of a signed-in user.
func (c *ControlClient) ResourceCatalogEntries(ctx context.Context, resource, catalogID, cursor string, limit int) (CatalogEntryList, error) {
	var out CatalogEntryList
	if resource == "" || catalogID == "" || limit < 1 || limit > 100 {
		return out, errors.New("resource, catalog ID and limit between 1 and 100 are required")
	}
	query := url.Values{"resource": {resource}, "limit": {strconv.Itoa(limit)}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(catalogID)+"/entries?"+query.Encode(), "", nil, &out)
	return out, err
}

func (c *ControlClient) ResourceCatalogEntry(ctx context.Context, resource, catalogID, entryID string) (CatalogEntry, error) {
	var out CatalogEntry
	if resource == "" || catalogID == "" || entryID == "" {
		return out, errors.New("resource, catalog ID and entry ID are required")
	}
	query := url.Values{"resource": {resource}}
	err := c.request(ctx, http.MethodGet, "/catalogs/"+url.PathEscape(catalogID)+"/entries/"+url.PathEscape(entryID)+"?"+query.Encode(), "", nil, &out)
	return out, err
}
