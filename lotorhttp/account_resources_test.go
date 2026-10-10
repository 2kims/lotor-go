package lotorhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestAccountResourcesDefaultsAndCancellation(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.RawQuery != "" {
			t.Errorf("invented default filters: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"resources":[],"next_cursor":"opaque-next"}`))
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := app.ForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.AccountResources(t.Context(), AccountResourceListOptions{})
	if err != nil || page.Resources == nil || len(page.Resources) != 0 || page.NextCursor == nil || *page.NextCursor != "opaque-next" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = client.AccountResources(ctx, AccountResourceListOptions{}); err == nil {
		t.Fatal("cancellation ignored")
	}
	if requests != 1 {
		t.Fatalf("cancelled request sent: %d", requests)
	}
}

func TestAccountResourcesPreservesMemberDirectoryContract(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/me/resources") || r.Header.Get("Authorization") != "Bearer alice" {
			t.Error("lost user directory authority")
		}
		q := r.URL.Query()
		if q.Get("parent") != "organization:root" || q.Get("cursor") != "opaque+cursor" || q.Get("limit") != "2" || !reflect.DeepEqual(q["type"], []string{"project", "vault"}) || !reflect.DeepEqual(q["access_state"], []string{"active", "pending_encryption"}) {
			t.Errorf("lost filters: %v", q)
		}
		if requests > 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"resources":[{"id":"a/b","resource":"project:a/b","type":"project","name":"Parent","relations":[],"access_state":"active","access":{"direct":false,"paths":[{"type":"ancestor","relation":"member","via":[{"id":"one","resource":"vault:one","type":"vault","name":"One","subject_relation":"member"}]}]}}],"next_cursor":null}`))
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := app.ForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	options := AccountResourceListOptions{Parent: "organization:root", Cursor: "opaque+cursor", Limit: 2, Types: []string{"project", "vault"}, AccessStates: []string{"active", "pending_encryption"}}
	page, err := client.AccountResources(t.Context(), options)
	if err != nil || len(page.Resources) != 1 || page.NextCursor != nil {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	resource := page.Resources[0]
	if resource.Resource != "project:a/b" || resource.AccessState != "active" || resource.Access.Direct || len(resource.Access.Paths) != 1 || resource.Access.Paths[0].Type != "ancestor" || len(resource.Access.Paths[0].Via) != 1 || resource.Access.Paths[0].Via[0].Resource != "vault:one" || resource.Access.Paths[0].Via[0].SubjectRelation != "member" {
		t.Fatalf("lost resource projection: %+v", resource)
	}
	if _, err = client.AccountResources(t.Context(), options); err == nil {
		t.Fatal("denial ignored")
	}
	for _, invalid := range []AccountResourceListOptions{{Limit: -1}, {Limit: 101}, {Types: []string{""}}, {AccessStates: []string{"disabled"}}, {Parent: strings.Repeat("x", 513)}, {Cursor: strings.Repeat("x", 2049)}} {
		if _, err = client.AccountResources(t.Context(), invalid); err == nil {
			t.Fatalf("accepted invalid options: %+v", invalid)
		}
	}
	if requests != 2 {
		t.Fatalf("invalid input or denial retried: %d", requests)
	}
}
