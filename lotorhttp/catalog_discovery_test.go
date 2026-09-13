package lotorhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDelegatedCatalogDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer user" {
			t.Error("missing delegated authority")
		}
		if !strings.HasSuffix(r.URL.Path, "/document") && (r.URL.Query().Get("cursor") != "opaque+cursor" || r.URL.Query().Get("limit") != "10") {
			t.Error("pagination changed")
		}
		if strings.HasSuffix(r.URL.Path, "/entries") {
			_, _ = w.Write([]byte(`{"items":[],"next_cursor":null,"snapshot_id":"snap"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/document") {
			_, _ = w.Write([]byte(`{"catalog_id":"cat","snapshot_id":"snap","document_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","document":{"openapi":"3.1.0","paths":{}}}`))
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/me/catalogs") {
			t.Error("wrong discovery path")
		}
		_, _ = w.Write([]byte(`{"items":[{"id":"cat","discoverable":true,"catalog_type":"generic","published_snapshot_id":"snap"}],"next_cursor":null}`))
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := client.ForUser("user")
	if err != nil {
		t.Fatal(err)
	}
	page, err := user.AvailableCatalogs(t.Context(), "opaque+cursor", 10)
	if err != nil || len(page.Items) != 1 || !page.Items[0].Discoverable {
		t.Fatalf("catalog discovery: %v", err)
	}
	entries, err := user.AvailableCatalogEntries(t.Context(), "cat", "opaque+cursor", 10)
	if err != nil || entries.SnapshotID != "snap" || entries.Items == nil {
		t.Fatalf("published discovery: %v", err)
	}
	document, err := user.AvailableCatalogSnapshotDocument(t.Context(), "cat", "snap")
	if err != nil || document.CatalogID != "cat" || !strings.Contains(string(document.Document), `"openapi":"3.1.0"`) {
		t.Fatalf("published document: %+v %v", document, err)
	}
}
