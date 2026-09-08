package browseradapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestItShouldKeepPayloadCapabilityInScopedHTTPOnlyCookie(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/uploads") {
			w.Header().Set("Lotor-Payload-Token", "remote-payload-capability")
		} else if r.Header.Get("Lotor-Payload-Token") != "remote-payload-capability" {
			t.Error("commit did not use cookie capability")
		}
		if r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("application authority leaked")
		}
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	var capability *http.Cookie
	for _, action := range []string{"uploads", "commits"} {
		r := request("POST", "/resources/project%3Aone/payloads/content/"+action)
		r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "user"})
		r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
		r.Header.Set("X-Lotor-CSRF", "proof")
		r.Header.Set("Lotor-Payload-Token", "untrusted-browser-header")
		if capability != nil {
			r.AddCookie(capability)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s status %d", action, w.Code)
		}
		if w.Header().Get("Lotor-Payload-Token") != "" {
			t.Fatal("capability exposed to JS")
		}
		if action == "uploads" {
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("missing scoped capability")
			}
			capability = cookies[0]
			if !capability.HttpOnly || capability.SameSite != http.SameSiteStrictMode || capability.MaxAge != 300 || capability.Path != prefix+"/resources/project%3Aone/payloads/content" {
				t.Fatal("unsafe capability cookie")
			}
		}
	}
}

func TestItShouldRejectMissingOrDuplicatePayloadCookieBeforeRemoteIO(t *testing.T) {
	a := fixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("unexpected remote call") })
	for _, duplicate := range []bool{false, true} {
		r := request("POST", "/resources/vault%3Aone/payloads/content/commits")
		r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "session"})
		r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
		r.Header.Set("X-Lotor-CSRF", "proof")
		r.Header.Set("Lotor-Payload-Token", "untrusted")
		if duplicate {
			r.AddCookie(&http.Cookie{Name: "lotor_payload_token", Value: "one"})
			r.AddCookie(&http.Cookie{Name: "lotor_payload_token", Value: "two"})
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d", w.Code)
		}
	}
}
