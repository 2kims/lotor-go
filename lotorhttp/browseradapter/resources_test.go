package browseradapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestItShouldPreserveUserAuthorityForEveryResourceRoute(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{"GET", "/resources/project%3Aone"},
		{"PUT", "/resources/project%3Aone"},
		{"GET", "/resources/org_one"},
		{"GET", "/resources/personal-one"},
		{"GET", "/me/invitations"},
		{"GET", "/me/resources"},
		{"GET", "/catalogs/cat_one/entries"},
		{"GET", "/catalogs/cat_one/entries/entry_one"},
		{"GET", "/resources/api_key%3Aone/credentials"},
		{"POST", "/resources/api_key%3Aone/credentials"},
		{"POST", "/billing/checkout-sessions"},
		{"POST", "/billing/portal-sessions"},
		{"POST", "/resources"},
		{"GET", "/resources/vault%3Aone/payloads/content"},
		{"DELETE", "/resources/vault%3Aone/payloads/content"},
		{"POST", "/resources/vault%3Aone/payloads/content/access"},
		{"POST", "/resources/vault%3Aone/payloads/content/rewraps"},
		{"DELETE", "/resources/api_key%3Aone/credentials/cred_one"},
		{"POST", "/resources/api_key%3Aone/credentials/cred_one/rotate"},
		{"GET", "/resources/org_one/collaborators"},
		{"POST", "/resources/org_one/link-candidates/search"},
		{"POST", "/me/invitations/inv_one/accept"},
		{"POST", "/me/invitations/inv_one/decline"},
		{"GET", "/key-access/subject-keys"},
		{"POST", "/key-access/subject-keys"},
		{"GET", "/key-access/resource-envelope"},
		{"POST", "/key-access/resource-envelope"},
		{"GET", "/me/encryption-actions"},
		{"POST", "/me/encryption-actions/job_one/complete"},
		{"GET", "/resources/org_one/e2ee"},
		{"PUT", "/resources/org_one/e2ee"},
		{"DELETE", "/resources/project%3Aone"},
		{"POST", "/resources/search"},
		{"POST", "/resources/project%3Aone/move"},
		{"POST", "/resources/project%3Aone/disable"},
		{"POST", "/resources/project%3Aone/restore"},
		{"GET", "/operations/op-one"},
	} {
		t.Run(route.method+route.path, func(t *testing.T) {
			a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Lotor-Secret-Key") != "" {
					t.Error("browser escalated to application authority")
				}
				if r.Header.Get("Authorization") != "Bearer user-session" || r.Header.Get("X-Lotor-Publishable-Key") != "pk_fixture" {
					t.Error("missing user credentials")
				}
				if r.Header.Get("X-Lotor-Request") != "lotor-js-v1" {
					t.Error("missing SDK marker")
				}
				_, _ = w.Write([]byte(`{"status":"ready"}`))
			})
			r := request(route.method, route.path)
			r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "user-session"})
			r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
			r.Header.Set("X-Lotor-CSRF", "proof")
			r.Header.Set("X-Lotor-Request", "lotor-js-v1")
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("status %d", w.Code)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("resource deletion affected session cookies")
			}
		})
	}
}

func TestItShouldKeepLinkCapabilityInScopedHTTPOnlyCookie(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/preflight") {
			w.Header().Set("Lotor-Link-Token", "remote-link-capability")
		} else if r.Header.Get("Lotor-Link-Token") != "remote-link-capability" {
			t.Error("commit did not use cookie capability")
		}
		if r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("application authority leaked")
		}
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	var capability *http.Cookie
	for _, action := range []string{"preflight", "commit"} {
		r := request("POST", "/resources/project%3Aone/links/"+action)
		r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "user"})
		r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
		r.Header.Set("X-Lotor-CSRF", "proof")
		r.Header.Set("Lotor-Link-Token", "untrusted-browser-header")
		if capability != nil {
			r.AddCookie(capability)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s status %d", action, w.Code)
		}
		if w.Header().Get("Lotor-Link-Token") != "" {
			t.Fatal("capability exposed to JS")
		}
		if action == "preflight" {
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("missing scoped capability")
			}
			capability = cookies[0]
			if !capability.HttpOnly || capability.SameSite != http.SameSiteStrictMode || capability.MaxAge != 300 || capability.Path != prefix+"/resources/project%3Aone/links" {
				t.Fatal("unsafe capability cookie")
			}
		}
	}
}

func TestItShouldRestrictDirectoryQueryParameters(t *testing.T) {
	for _, tc := range []struct {
		path, query string
		valid       bool
	}{
		{prefix + "/me/invitations", "cursor=opaque&limit=2", true},
		{prefix + "/me/resources", "type=project&type=vault", true},
		{prefix + "/me/resources", "type=vault&parent=project%3Aone", true},
		{prefix + "/me/resources", "parent=project%3Aone&parent=project%3Atwo", false},
		{prefix + "/catalogs/cat_one/entries", "resource=vault%3Aone&cursor=opaque&limit=2", true},
		{prefix + "/me/invitations", "limit=2&limit=3", false},
		{prefix + "/me/invitations", "mode=live", false},
		{prefix + "/me/invitations", "cursor%20limit=2", false},
		{prefix + "/resources/org_one", "cursor=one", false},
		{prefix + "/resources/org_one/collaborators", "relation=member&relation=owner", true},
	} {
		if validResourceQuery("GET", tc.path, tc.query) != tc.valid {
			t.Errorf("unexpected query decision for %s", tc.query)
		}
	}
}

func TestItShouldUseOnlyClaimCookieAndNeverBrowserClaimHeader(t *testing.T) {
	for _, methodPath := range []struct{ method, path string }{
		{"GET", "/key-access/claims/claim_one"},
		{"POST", "/key-access/claims/claim_one/transfer"},
		{"POST", "/key-access/claims/claim_one/complete"},
	} {
		for _, withCookie := range []bool{false, true} {
			calls := 0
			a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Lotor-Key-Claim-Token") != "cookie-claim" || r.Header.Get("X-Lotor-Secret-Key") != "" {
					t.Error("wrong claim authority")
				}
				_, _ = w.Write([]byte(`{"status":"completed"}`))
			})
			r := request(methodPath.method, methodPath.path)
			r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "user"})
			r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
			r.Header.Set("X-Lotor-CSRF", "proof")
			r.Header.Set("Lotor-Key-Claim-Token", "untrusted-header")
			if withCookie {
				r.AddCookie(&http.Cookie{Name: "lotor_key_claim_token", Value: "cookie-claim"})
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if withCookie && (w.Code != 200 || calls != 1) {
				t.Fatal("valid claim not forwarded")
			}
			if !withCookie && (w.Code != 401 || calls != 0) {
				t.Fatal("claim header bypassed cookie")
			}
		}
	}
}

func TestItShouldRejectResourcePathAmbiguityAndMissingSession(t *testing.T) {
	a := fixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("unexpected remote I/O") })
	for _, path := range []string{"/resources/project%253Aone", "/resources/project%3A..%2Fother", "/resources/..", "/catalogs/cat_one/snapshots", "/resource-types/project", "/resources/project%3Aone"} {
		r := request("GET", path)
		if path != "/resources/project%3Aone" {
			r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "valid-session"})
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code < 400 {
			t.Fatal("accepted " + path)
		}
	}
}

func TestItShouldForwardOrganizationCreationAsTheUser(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Lotor-Secret-Key") != "" || r.Header.Get("Authorization") != "Bearer session" || r.Header.Get("Idempotency-Key") != "create-org" {
			t.Error("incorrect organization authority")
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"org-one","name":"Acme","current_role":"owner","member_count":1,"pending_invites":0}`))
	})
	r := request("POST", "/organizations")
	r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "session"})
	r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
	r.Header.Set("X-Lotor-CSRF", "proof")
	r.Header.Set("Idempotency-Key", "create-org")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
}

func TestItShouldRequireCSRFForResourceWritesBeforeRemoteIO(t *testing.T) {
	a := fixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("unexpected remote I/O") })
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		path := "/resources/project%3Aone"
		if method == "POST" {
			path += "/move"
		}
		r := request(method, path)
		r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "session"})
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%s: %d", method, w.Code)
		}
	}
}

func TestItShouldNotSendApplicationSecretWhenResourceSessionIsRejected(t *testing.T) {
	calls := 0
	a := fixture(t, func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(401) })
	r := request("GET", "/resources/project%3Aone")
	r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "expired"})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 401 || calls != 1 || strings.Contains(w.Body.String(), "sk_fixture") {
		t.Fatal("resource authority fallback")
	}
}
