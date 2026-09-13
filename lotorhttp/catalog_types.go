package lotorhttp

import "encoding/json"

type GenericCatalogDefinition struct {
	SemanticKey string          `json:"semantic_key"`
	EntryKind   string          `json:"entry_kind"`
	Definition  json.RawMessage `json:"definition"`
}

// CatalogCreation configures application-owned catalog metadata, not its entries.
type CatalogCreation struct {
	Namespace    string `json:"namespace"`
	CatalogType  string `json:"catalog_type"`
	Visibility   string `json:"visibility"`
	Organization string `json:"organization,omitempty"`
	Discoverable bool   `json:"discoverable"`
}

type Catalog struct {
	Organization        *string `json:"organization"`
	PublishedSnapshotID *string `json:"published_snapshot_id"`
	ID                  string  `json:"id"`
	Namespace           string  `json:"namespace"`
	CatalogType         string  `json:"catalog_type"`
	Visibility          string  `json:"visibility"`
	Status              string  `json:"status"`
	CreatedAt           int64   `json:"created_at"`
	Discoverable        bool    `json:"discoverable"`
}

type CatalogList struct {
	NextCursor *string   `json:"next_cursor"`
	Items      []Catalog `json:"items"`
}

type PublishedCatalogEntryList struct {
	SnapshotID string `json:"snapshot_id"`
	CatalogEntryList
}

type CatalogSnapshotDocument struct {
	CatalogID      string          `json:"catalog_id"`
	SnapshotID     string          `json:"snapshot_id"`
	DocumentDigest string          `json:"document_digest"`
	Document       json.RawMessage `json:"document"`
}

type CatalogImportInput struct {
	Format         string `json:"format"`
	SourceDocument string `json:"source_document"`
}

type CatalogSnapshot struct {
	PublishedAt     *int64 `json:"published_at"`
	ID              string `json:"id"`
	CatalogID       string `json:"catalog_id"`
	SourceDigest    string `json:"source_digest"`
	ImporterVersion string `json:"importer_version"`
	Digest          string `json:"digest"`
	Status          string `json:"status"`
	EntryCount      int64  `json:"entry_count"`
	CreatedAt       int64  `json:"created_at"`
}

type CatalogSnapshotList struct {
	NextCursor *string           `json:"next_cursor"`
	Items      []CatalogSnapshot `json:"items"`
}

type ResourceCatalogBindingInput struct {
	CatalogID                   string   `json:"catalog_id"`
	SnapshotID                  string   `json:"snapshot_id"`
	EntryKinds                  []string `json:"entry_kinds"`
	ExpectedResourceRevision    int64    `json:"expected_resource_revision"`
	ExpectedLifecycleGeneration int64    `json:"expected_lifecycle_generation"`
}
