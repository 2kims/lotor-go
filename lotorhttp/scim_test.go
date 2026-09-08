package lotorhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSCIMDirectoryDelegation(t *testing.T) {
	const directory = `{"id":"res_directory","resource":"directory:acme","organization":"organization:acme","credential_resource":"api_key:scim","status":"disabled","revision":1,"base_url":"https://api.example.test/scim/v2/directories/res_directory"}`
	body, status, calls := directory, http.StatusOK, 0
	input := SCIMDirectoryCreateInput{DirectoryResource: "directory:acme", CredentialResource: "api_key:scim", ExpectedResourceRevision: 1, ExpectedLifecycleGeneration: 2}
	update := SCIMDirectoryUpdateInput{Enabled: true, ExpectedRevision: 1}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer alice" || r.Header.Get("X-Lotor-Secret-Key") != "secret" || !strings.HasPrefix(r.URL.Path, "/v1/public/applications/app/resources/organization:acme/scim-directories") {
			t.Error("lost user delegation or route")
		}
		if r.Method == http.MethodPost {
			var got SCIMDirectoryCreateInput
			if json.NewDecoder(r.Body).Decode(&got) != nil || got != input || r.Header.Get("Idempotency-Key") != "setup-once" {
				t.Error("changed creation input or retry key")
			}
		}
		if r.Method == http.MethodPut {
			var got SCIMDirectoryUpdateInput
			if json.NewDecoder(r.Body).Decode(&got) != nil || got != update || r.Header.Get("Idempotency-Key") != "enable-once" {
				t.Error("changed update input or retry key")
			}
		}
		if r.URL.RawQuery != "" && (r.URL.Query().Get("cursor") != "one+two" || r.URL.Query().Get("limit") != "1") {
			t.Error("changed page options")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = app.CreateSCIMDirectory(ctx, "organization:acme", input, "setup-once"); err == nil {
		t.Fatal("application-only creation accepted")
	}
	if _, err = app.SCIMDirectory(ctx, "organization:acme", "res_directory"); err == nil {
		t.Fatal("application-only read accepted")
	}
	if _, err = app.UpdateSCIMDirectory(ctx, "organization:acme", "res_directory", update, "enable-once"); err == nil {
		t.Fatal("application-only update accepted")
	}
	if _, err = app.SCIMDirectories(ctx, "organization:acme", "", 1); err == nil || calls != 0 {
		t.Fatal("application-only listing sent a request")
	}
	user, err := app.ForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	created, err := user.CreateSCIMDirectory(ctx, "organization:acme", input, "setup-once")
	if err != nil || created.Status != "disabled" || created.ID != "res_directory" {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	if read, readErr := user.SCIMDirectory(ctx, "organization:acme", "res_directory"); readErr != nil || read != created {
		t.Fatalf("read=%+v err=%v", read, readErr)
	}
	body = strings.Replace(directory, `"status":"disabled","revision":1`, `"status":"active","revision":2`, 1)
	if updated, updateErr := user.UpdateSCIMDirectory(ctx, "organization:acme", "res_directory", update, "enable-once"); updateErr != nil || updated.Status != "active" || updated.Revision != 2 {
		t.Fatalf("updated=%+v err=%v", updated, updateErr)
	}
	body = `{"directories":[` + directory + `],"next_cursor":"next"}`
	page, err := user.SCIMDirectories(ctx, "organization:acme", "one+two", 1)
	if err != nil || len(page.Directories) != 1 || page.NextCursor == nil || *page.NextCursor != "next" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	body = `{"directories":[]}`
	if _, err = user.SCIMDirectories(ctx, "organization:acme", "one+two", 1); err == nil {
		t.Fatal("missing next_cursor accepted")
	}
	if _, err = user.UpdateSCIMDirectory(ctx, "organization:acme", "res_directory", SCIMDirectoryUpdateInput{Enabled: true}, "enable-once"); err == nil {
		t.Fatal("invalid update sent a request")
	}
	for _, invalid := range []string{strings.Replace(directory, `"revision":1`, `"revision":0`, 1), strings.Replace(directory, `"id":"res_directory"`, `"id":"other"`, 1), strings.Replace(directory, `"status":"disabled"`, `"status":"unknown"`, 1), strings.Replace(directory, `"revision":1`, `"revision":1,"secret":"private"`, 1)} {
		body = invalid
		if _, err = user.SCIMDirectory(ctx, "organization:acme", "res_directory"); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
	status = http.StatusForbidden
	before := calls
	if _, err = user.SCIMDirectory(ctx, "organization:acme", "res_directory"); err == nil || calls != before+1 {
		t.Fatal("denial was accepted or retried")
	}
}
