package lotorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTypedCatalogAdministration(t *testing.T) {
	const catalog = `{"id":"cat","namespace":"slack","catalog_type":"api","visibility":"application_private","organization":null,"published_snapshot_id":null,"status":"active","created_at":1}`
	var bodies []map[string]any
	const entry = `{"id":"entry","catalog_id":"cat","semantic_key":"send","entry_kind":"api.operation","revision_id":"rev","revision_digest":"digest","definition":{"method":"POST"}}`
	var keys []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Lotor-Secret-Key") != "secret" || r.Header.Get("Authorization") != "" {
			t.Error("incorrect application authority")
		}
		if r.Method != http.MethodGet {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			bodies = append(bodies, body)
			keys = append(keys, r.Header.Get("Idempotency-Key"))
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/entries/entry"):
			_, _ = w.Write([]byte(entry))
		case strings.HasSuffix(r.URL.Path, "/entries"):
			_, _ = w.Write([]byte(`{"items":[` + entry + `],"next_cursor":null}`))
		case strings.HasSuffix(r.URL.Path, "/imports"), strings.HasSuffix(r.URL.Path, "/catalog-binding"):
			_, _ = w.Write([]byte(`{"id":"op","status":"pending"}`))
		case strings.HasSuffix(r.URL.Path, "/snapshots"):
			_, _ = w.Write([]byte(`{"items":[{"id":"snap","catalog_id":"cat","source_digest":"digest","importer_version":"v1","digest":"digest","status":"candidate","entry_count":2,"published_at":null,"created_at":1}],"next_cursor":null}`))
		case strings.HasSuffix(r.URL.Path, "/catalogs") && r.Method == http.MethodGet:
			if r.URL.Query().Get("cursor") != "opaque+cursor" || r.URL.Query().Get("limit") != "2" {
				t.Error("lost cursor/limit")
			}
			_, _ = w.Write([]byte(`{"items":[` + catalog + `],"next_cursor":"next"}`))
		default:
			_, _ = w.Write([]byte(catalog))
		}
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateCatalog(t.Context(), CatalogCreation{Namespace: "slack", CatalogType: "api", Visibility: "application_private"}, "create")
	if err != nil || created.ID != "cat" || created.Organization != nil || created.PublishedSnapshotID != nil {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	listed, err := client.Catalogs(t.Context(), "opaque+cursor", 2)
	if err != nil || len(listed.Items) != 1 || listed.NextCursor == nil || *listed.NextCursor != "next" {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	detail, err := client.Catalog(t.Context(), "cat")
	if err != nil || detail.Namespace != "slack" {
		t.Fatalf("catalog=%+v err=%v", detail, err)
	}
	entries, err := client.CatalogEntries(t.Context(), "cat", "", 2)
	if err != nil || len(entries.Items) != 1 || entries.Items[0].SemanticKey != "send" || entries.NextCursor != nil {
		t.Fatalf("entries=%+v err=%v", entries, err)
	}
	entryDetail, err := client.CatalogEntry(t.Context(), "cat", "entry")
	if err != nil || entryDetail.RevisionID != "rev" || string(entryDetail.Definition) != `{"method":"POST"}` {
		t.Fatalf("entry=%+v err=%v", entryDetail, err)
	}
	operation, err := client.ImportOpenAPI(t.Context(), "cat", CatalogImportInput{Format: "openapi_3_1", SourceDocument: "inline-document"}, "import")
	if err != nil || operation.Status != "pending" {
		t.Fatalf("import=%+v err=%v", operation, err)
	}
	snapshots, err := client.CatalogSnapshots(t.Context(), "cat", "", 2)
	if err != nil || len(snapshots.Items) != 1 || snapshots.Items[0].EntryCount != 2 || snapshots.Items[0].PublishedAt != nil || snapshots.NextCursor != nil {
		t.Fatalf("snapshots=%+v err=%v", snapshots, err)
	}
	_, err = client.BindResourceCatalog(t.Context(), "vault:one", ResourceCatalogBindingInput{CatalogID: "cat", SnapshotID: "snap", EntryKinds: []string{"api.operation"}, ExpectedResourceRevision: 3, ExpectedLifecycleGeneration: 4}, "bind")
	if err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 3 || len(keys) != 3 {
		t.Fatalf("requests=%v keys=%v", bodies, keys)
	}
	if bodies[0]["namespace"] != "slack" || bodies[1]["source_document"] != "inline-document" || bodies[2]["expected_resource_revision"] != float64(3) || bodies[2]["expected_lifecycle_generation"] != float64(4) || keys[0] != "create" || keys[1] != "import" || keys[2] != "bind" {
		t.Fatalf("wire contract=%v keys=%v", bodies, keys)
	}
}

func TestGenericCatalogImportWire(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/catalogs/cat/imports") || r.Header.Get("Idempotency-Key") != "generic-import" {
			t.Error("wrong generic import request")
		}
		var input CatalogImportInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
			return
		}
		if input.Format != "definitions_v1" || input.SourceDocument != `{"entries":[{"semantic_key":"rule","entry_kind":"policy.rule","definition":{"large":9007199254740993}}]}` {
			t.Errorf("invalid generic document: %s", input.SourceDocument)
		}
		_, _ = w.Write([]byte(`{"id":"op","kind":"catalog_import","status":"pending"}`))
	}))
	defer server.Close()
	client, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	op, err := client.ImportDefinitions(t.Context(), "cat", []GenericCatalogDefinition{{SemanticKey: "rule", EntryKind: "policy.rule", Definition: json.RawMessage(`{"large":9007199254740993}`)}}, "generic-import")
	if err != nil || op.Kind != "catalog_import" {
		t.Fatalf("operation=%+v err=%v", op, err)
	}
}
