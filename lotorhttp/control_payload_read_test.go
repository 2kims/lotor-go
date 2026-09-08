package lotorhttp

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlPayloadReadPreservesDelegationAndIsolatesObjectCredentials(t *testing.T) {
	object := []byte("payload")
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("Lotor credentials leaked to object storage")
		}
		_, _ = w.Write(object)
	}))
	defer storage.Close()
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer member" {
			t.Error("lost delegated authority")
		}
		if calls > 2 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"resource":"vault:one","slot":"config","payload_version":2}`))
			return
		}
		var body struct {
			PayloadVersion int64 `json:"payload_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PayloadVersion != 2 {
			t.Error("lost payload version")
		}
		_ = json.NewEncoder(w).Encode(ResourcePayloadAccessLease{DownloadURL: storage.URL, DownloadMethod: http.MethodGet, ObjectSize: int64(len(object)), ObjectDigest: fmt.Sprintf("%x", sha256.Sum256(object))})
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := app.ForUser("member")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := user.ResourcePayload(t.Context(), "vault:one", "config")
	if err != nil || manifest.PayloadVersion != 2 {
		t.Fatalf("manifest=%+v err=%v", manifest, err)
	}
	lease, err := user.AccessResourcePayload(t.Context(), "vault:one", "config", 2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := user.DownloadResourcePayload(t.Context(), lease)
	if err != nil || string(raw) != string(object) {
		t.Fatalf("download=%q err=%v", raw, err)
	}
	lease.ObjectDigest = "invalid"
	if _, err = user.DownloadResourcePayload(t.Context(), lease); err == nil {
		t.Fatal("accepted incorrect digest")
	}
	if _, err = user.ResourcePayload(t.Context(), "vault:one", "config"); err == nil {
		t.Fatal("ignored denial")
	}
	if calls != 3 {
		t.Fatalf("unexpected retry: %d calls", calls)
	}
}
