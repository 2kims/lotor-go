package browseradapter

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestItShouldKeepExecutionCapabilityInShortLivedScopedHTTPOnlyCookie(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/preflight") {
			w.Header().Set("Lotor-Execution-Token", "remote-execution-capability")
		} else if r.Header.Get("Lotor-Execution-Token") != "remote-execution-capability" {
			t.Error("commit did not use cookie capability")
		}
		if r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("application authority leaked")
		}
		_, _ = w.Write([]byte(`{"status":"completed"}`))
	})
	var capability *http.Cookie
	for _, action := range []string{"preflight", "commit"} {
		r := request("POST", "/resources/integration%3Aslack/executions/"+action)
		r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "user"})
		r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
		r.Header.Set("X-Lotor-CSRF", "proof")
		r.Header.Set("Lotor-Execution-Token", "untrusted-browser-header")
		if capability != nil {
			r.AddCookie(capability)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s status %d", action, w.Code)
		}
		if w.Header().Get("Lotor-Execution-Token") != "" {
			t.Fatal("capability exposed to JavaScript")
		}
		if action == "preflight" {
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("missing scoped execution capability")
			}
			capability = cookies[0]
			if !capability.HttpOnly || capability.SameSite != http.SameSiteStrictMode || capability.MaxAge != 30 || capability.Path != prefix+"/resources/integration%3Aslack/executions" {
				t.Fatalf("unsafe execution capability cookie: %+v", capability)
			}
		}
	}
}

func TestItShouldBoundExecutionCommitSeparatelyFromOrdinaryAdapterBodies(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"completed"}`)) })
	for _, scenario := range []struct{ size, status int }{{bodyLimit + 1, http.StatusOK}, {executionBodyLimit + 1, http.StatusRequestEntityTooLarge}} {
		r := request("POST", "/resources/integration%3Aslack/executions/commit")
		r.Body = io.NopCloser(bytes.NewReader([]byte(`{"protected_request":"` + strings.Repeat("a", scenario.size-24) + `"}`)))
		r.ContentLength = int64(scenario.size)
		r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "session"})
		r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
		r.AddCookie(&http.Cookie{Name: "lotor_execution_token", Value: "execution-capability"})
		r.Header.Set("X-Lotor-CSRF", "proof")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != scenario.status {
			t.Fatalf("size=%d status=%d", scenario.size, w.Code)
		}
	}
}

func TestItShouldRejectMissingOrDuplicateExecutionCookieBeforeRemoteIO(t *testing.T) {
	a := fixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("unexpected remote call") })
	for _, duplicate := range []bool{false, true} {
		r := request("POST", "/resources/integration%3Aslack/executions/commit")
		r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "session"})
		r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
		r.Header.Set("X-Lotor-CSRF", "proof")
		if duplicate {
			r.AddCookie(&http.Cookie{Name: "lotor_execution_token", Value: "one"})
			r.AddCookie(&http.Cookie{Name: "lotor_execution_token", Value: "two"})
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d", w.Code)
		}
	}
}
