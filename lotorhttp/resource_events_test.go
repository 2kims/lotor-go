package lotorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResourceEventProducerUsesOnlyItsNativeResourceCredential(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/resources/logs:one/event-streams/requests/events") || r.Header.Get("Authorization") != "Bearer producer-key" || r.Header.Get("X-Lotor-Publishable-Key") != "pk_fixture" || r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("producer authority or route changed")
		}
		var event ResourceEvent
		if checkErr := json.NewDecoder(r.Body).Decode(&event); checkErr != nil || event.ID != "one" || len(event.Body) != 0 || event.Attributes == nil {
			t.Error("event encoding changed", checkErr)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := NewResourceClient(ResourceClientOptions{BaseURL: server.URL, ClientID: "app", PublishableKey: "pk_fixture", ResourceCredential: "producer-key"})
	if err != nil {
		t.Fatal(err)
	}
	if checkErr := client.AppendResourceEvent(t.Context(), "logs:one", "requests", ResourceEvent{ID: "one", Representation: "raw"}); checkErr != nil || calls != 1 {
		t.Fatal("producer append failed or retried", checkErr, calls)
	}
}

func TestResourceEventSDKPreservesDelegationSnapshotAndOpaqueBodies(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer member-session" || r.Header.Get("X-Lotor-Secret-Key") != "secret" {
			t.Error("delegated authority missing")
		}
		if !strings.Contains(r.URL.EscapedPath(), "/resources/organization:acme/event-streams/audit") {
			t.Error("wrong event stream path", r.URL.EscapedPath())
		}
		switch {
		case r.Method == http.MethodPut || r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/events"):
			w.WriteHeader(204)
		case strings.HasSuffix(r.URL.Path, "/queries"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id":"snapshot","from":"2026-10-16T00:00:00Z","to":"2026-10-16T01:00:00Z","expires_at":"2026-10-16T01:10:00Z"}`))
		case strings.HasSuffix(r.URL.Path, "/histogram"):
			if r.URL.Query().Get("group_by") != "result" || r.URL.Query().Get("interval_seconds") != "60" {
				t.Error("histogram parameters lost")
			}
			_, _ = w.Write([]byte(`[{"start":"2026-10-16T00:00:00Z","end":"2026-10-16T00:01:00Z","counts":{"no_response":2}}]`))
		case strings.HasSuffix(r.URL.Path, "/events"):
			if !strings.Contains(r.URL.Path, "/queries/snapshot/events") || r.URL.Query().Get("cursor") != "opaque+cursor" {
				t.Error("snapshot/cursor lost")
			}
			_, _ = w.Write([]byte(`{"items":[],"next_cursor":null}`))
		default:
			_, _ = w.Write([]byte(`{"id":"event","occurred_at":"2026-10-16T00:00:00Z","attributes":{},"representation":"encrypted","body":"AAE="}`))
		}
	}))
	defer server.Close()
	application, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = application.ResourceEvents(t.Context(), "organization:acme", "audit", "snapshot", "", 10); err == nil || calls != 0 {
		t.Fatal("application-only read attempted")
	}
	client, err := application.ForUser("member-session")
	if err != nil {
		t.Fatal(err)
	}
	if err = client.ConfigureResourceEventStream(t.Context(), "organization:acme", "audit", ResourceEventStreamInput{AttributeKeys: []string{"result"}, RetentionDays: 7}); err != nil {
		t.Fatal(err)
	}
	if err = client.AppendResourceEvent(t.Context(), "organization:acme", "audit", ResourceEvent{ID: "event", Representation: "encrypted", Body: []byte{0, 1}}); err != nil {
		t.Fatal(err)
	}
	query, err := client.CreateResourceEventQuery(t.Context(), "organization:acme", "audit", ResourceEventQueryInput{})
	if err != nil || query.ID != "snapshot" {
		t.Fatal(err)
	}
	if _, err = client.ResourceEvents(t.Context(), "organization:acme", "audit", query.ID, "opaque+cursor", 10); err != nil {
		t.Fatal(err)
	}
	buckets, err := client.ResourceEventHistogram(t.Context(), "organization:acme", "audit", query.ID, "result", time.Minute)
	if err != nil || len(buckets) != 1 || buckets[0].Counts["no_response"] != 2 {
		t.Fatal(err)
	}
	event, err := client.ResourceEvent(t.Context(), "organization:acme", "audit", "event")
	if err != nil || string(event.Body) != string([]byte{0, 1}) {
		t.Fatal("opaque bytes changed", err)
	}
	if calls != 6 {
		t.Fatal("unexpected retries", calls)
	}
}
