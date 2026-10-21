package lotorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEndpointUpdatePreservesDelegationAndExpectedRevision(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "PUT" || r.URL.Path != "/v1/public/applications/app/resources/project:one/function-bindings/existing/endpoint" || r.Header.Get("Authorization") != "Bearer owner" || r.Header.Get("X-Lotor-Secret-Key") != "app-secret" {
			t.Error("endpoint update lost scope or delegation")
		}
		var input struct {
			EndpointURL      string `json:"endpoint_url"`
			ExpectedRevision int64  `json:"expected_revision"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.EndpointURL != "https://new.example" || input.ExpectedRevision != 3 {
			t.Error("endpoint update changed contract")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"existing","revision":4,"status":"pending"}`))
	}))
	defer server.Close()
	app, err := NewControlClient(ControlClientOptions{BaseURL: server.URL, ClientID: "app", SecretKey: "app-secret"})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := app.ForUser("owner")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := owner.UpdateFunctionBindingEndpoint(t.Context(), "project:one", "existing", "https://new.example", 3)
	if err != nil || binding.ID != "existing" || binding.Revision != 4 || calls != 1 {
		t.Fatal("endpoint update failed or retried", err)
	}
}
