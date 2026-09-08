package lotorhttp

import (
	"context"
	"net/http"
	"net/url"
)

// AvailableCatalogs uses the current client's delegated user authority.
func (c *ControlClient) AvailableCatalogs(ctx context.Context, cursor string, limit int) (CatalogList, error) {
	var out CatalogList
	err := c.request(ctx, http.MethodGet, "/me/catalogs"+pagination(cursor, limit), "", nil, &out)
	return out, err
}

func (c *ControlClient) AvailableCatalogEntries(ctx context.Context, catalogID, cursor string, limit int) (PublishedCatalogEntryList, error) {
	var out PublishedCatalogEntryList
	err := c.request(ctx, http.MethodGet, "/me/catalogs/"+url.PathEscape(requiredControl(catalogID, "catalog ID"))+"/entries"+pagination(cursor, limit), "", nil, &out)
	return out, err
}
