package lotorhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlIdentityVerifierUsesBearerAndDecodesCanonicalScope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/me" || r.Header.Get("Authorization") != "Bearer bearer-secret" {
			http.Error(w, "bad request", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subject":"user:one","email":"Member@Example.Test","account":{"tenant_id":"tenant:one","application_id":"app:one","environment_id":"env:staging"}}`))
	}))
	defer server.Close()
	verifier, err := newControlIdentityVerifier(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := verifier.Verify(t.Context(), "bearer-secret")
	if err != nil || identity.Subject != "user:one" || identity.Email != "member@example.test" || identity.TenantID != "tenant:one" || identity.ApplicationID != "app:one" || identity.EnvironmentID != "env:staging" {
		t.Fatalf("identity=%+v err=%v", identity, err)
	}
}

func TestControlIdentityVerifierRejectsInsecureRemoteURL(t *testing.T) {
	if _, err := newControlIdentityVerifier("http://control.example.test"); err == nil {
		t.Fatal("expected insecure remote Control URL rejection")
	}
}
