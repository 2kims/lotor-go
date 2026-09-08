package lotorhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResourceCatalogReadsPreserveUserAndBinding(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer user-session" || r.URL.Query().Get("resource") != "vault:one" {
			t.Error("lost delegated authority or resource binding")
		}
		entry := `{"id":"entry_1","catalog_id":"cat_1","semantic_key":"send","entry_kind":"api.operation","revision_id":"rev_1","revision_digest":"digest","definition":{"method":"POST"}}`
		if strings.HasSuffix(r.URL.Path, "/entries/entry_1") {
			_, _ = w.Write([]byte(entry))
		} else {
			if r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("cursor") != "opaque+cursor" {
				t.Error("lost pagination")
			}
			_, _ = w.Write([]byte(`{"items":[` + entry + `],"next_cursor":"next"}`))
		}
	}))
	defer server.Close()
	application, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := application.ForUser("user-session")
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ResourceCatalogEntries(t.Context(), "vault:one", "cat_1", "opaque+cursor", 2)
	if err != nil || len(page.Items) != 1 || page.Items[0].RevisionID != "rev_1" || page.NextCursor == nil || *page.NextCursor != "next" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	entry, err := client.ResourceCatalogEntry(t.Context(), "vault:one", "cat_1", "entry_1")
	if err != nil || entry.SemanticKey != "send" {
		t.Fatalf("entry=%+v err=%v", entry, err)
	}
	if _, err = client.ResourceCatalogEntries(t.Context(), "vault:one", "cat_1", "", 101); err == nil {
		t.Fatal("invalid limit accepted")
	}
	if _, err = client.ResourceCatalogEntry(t.Context(), "", "cat_1", "entry_1"); err == nil {
		t.Fatal("missing binding accepted")
	}
	if requests != 2 {
		t.Fatalf("unexpected request count=%d", requests)
	}
}
