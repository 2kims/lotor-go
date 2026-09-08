package browseradapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestItShouldUseSecureCookiesOnAnHTTPSBrowserOrigin(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"token","subject":"alice"}`))
	})
	a.origin.Scheme = "https"
	a.origin.Host = "avault.example.test"
	a.config.BrowserOrigin = "https://avault.example.test"
	a.secure = true
	r := request("POST", "/auth/passwordless/verify")
	r.Host = "avault.example.test"
	r.Header.Set("Origin", a.config.BrowserOrigin)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if !c.Secure || c.Domain != "" {
			t.Fatal("insecure production cookie")
		}
		if strings.HasPrefix(c.Name, "__Host-") && c.Path != "/" {
			t.Fatal("invalid host-prefix cookie")
		}
	}
}

func TestItShouldRejectMissingMutationOriginAndDuplicateCSRFProof(t *testing.T) {
	a := fixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("unexpected upstream call") })
	for _, duplicate := range []bool{false, true} {
		r := request("DELETE", "/session")
		r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
		r.Header.Set("X-Lotor-CSRF", "proof")
		if duplicate {
			r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
		} else {
			r.Header.Del("Origin")
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
}

func TestItShouldRejectOversizedRemoteResponses(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", responseLimit+1)))
	})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, request("GET", "/session"))
	if w.Code != 502 || len(w.Result().Cookies()) != 0 {
		t.Fatal("oversized response accepted")
	}
}

func TestItShouldFailClosedOnNetworkOutage(t *testing.T) {
	a := fixture(t, func(_ http.ResponseWriter, _ *http.Request) {})
	a.config.APIURL = "https://127.0.0.1:1"
	w := httptest.NewRecorder()
	a.ServeHTTP(w, request("GET", "/session"))
	if w.Code != 502 || strings.Contains(w.Body.String(), "127.0.0.1") {
		t.Fatal("unsafe network failure")
	}
}

func fixture(t *testing.T, upstream http.HandlerFunc) *Adapter {
	t.Helper()
	remote := httptest.NewTLSServer(upstream)
	t.Cleanup(remote.Close)
	a, err := New(Config{APIURL: remote.URL, BrowserOrigin: "http://localhost:3000", ClientID: "avault", PublishableKey: "pk_fixture", SecretKey: "sk_fixture"})
	if err != nil {
		t.Fatal(err)
	}
	a.client.Transport = remote.Client().Transport
	return a
}

func request(method, path string) *http.Request {
	r := httptest.NewRequest(method, "http://localhost:3000/.lotor/v1"+path, strings.NewReader(`{"email":"alice@example.test"}`))
	r.Header.Set("Origin", "http://localhost:3000")
	r.Header.Set("X-Lotor-Publishable-Key", "pk_fixture")
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestItShouldRejectInvalidConfiguration(t *testing.T) {
	valid := Config{APIURL: "https://api.example.test", BrowserOrigin: "http://localhost:3000", ClientID: "avault", PublishableKey: "pk_fixture", SecretKey: "sk_fixture"}
	for _, field := range []string{"url", "origin", "client", "publishable", "secret", "httpRemote", "credentials", "path", "query", "remoteLocalCookie"} {
		t.Run(field, func(t *testing.T) {
			c := valid
			switch field {
			case "url":
				c.APIURL = ""
			case "origin":
				c.BrowserOrigin = ""
			case "client":
				c.ClientID = "../other"
			case "publishable":
				c.PublishableKey = ""
			case "secret":
				c.SecretKey = ""
			case "httpRemote":
				c.APIURL = "http://remote.example.test"
			case "credentials":
				c.APIURL = "https://user:secret@remote.example.test"
			case "path":
				c.APIURL += "/api"
			case "query":
				c.APIURL += "?env=prod"
			case "remoteLocalCookie":
				c.BrowserOrigin = "http://public.example.test"
			}
			if _, err := New(c); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func TestItShouldUseOnlyConfiguredRemoteAuthority(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/public/applications/avault/session" {
			t.Error(r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer remote-session" || r.Header.Get("X-Lotor-Secret-Key") != "sk_fixture" || r.Header.Get("X-Lotor-Publishable-Key") != "pk_fixture" {
			t.Error("incorrect credentials")
		}
		for _, h := range []string{"Cookie", "X-Lotor-Tenant-ID", "X-Lotor-Environment", "X-Forwarded-Host"} {
			if r.Header.Get(h) != "" {
				t.Errorf("forwarded %s", h)
			}
		}
		_, _ = w.Write([]byte(`{"authenticated":true,"subject":"alice"}`))
	})
	r := request("GET", "/session")
	r.Header.Set("Authorization", "Bearer attacker")
	r.Header.Set("X-Lotor-Secret-Key", "attacker")
	r.Header.Set("X-Lotor-Tenant-ID", "attacker")
	r.Header.Set("X-Lotor-Environment", "prod")
	r.AddCookie(&http.Cookie{Name: "lotor_dev_session", Value: "remote-session"})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d", w.Code)
	}
}

func TestItShouldRejectUntrustedRequestsBeforeRemoteIO(t *testing.T) {
	a := fixture(t, func(_ http.ResponseWriter, _ *http.Request) { t.Error("unexpected remote I/O") })
	for _, kind := range []string{"origin", "metadata", "publishable", "csrf", "route", "encoded", "query", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			r := request("POST", "/auth/passwordless/start")
			switch kind {
			case "origin":
				r.Header.Set("Origin", "https://evil.example")
			case "metadata":
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			case "publishable":
				r.Header.Del("X-Lotor-Publishable-Key")
			case "csrf":
				r = request("DELETE", "/session")
			case "route":
				r = request("POST", "/admin")
			case "encoded":
				r.URL.RawPath = "/.lotor/v1/auth/passwordless/%73tart"
			case "query":
				r.URL.RawQuery = "environment=prod"
			case "oversize":
				r = request("POST", "/auth/passwordless/start")
				r.Body = http.NoBody
				r.ContentLength = 1 << 20
			}
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code < 400 {
				t.Fatalf("accepted with %d", w.Code)
			}
		})
	}
}

func TestItShouldKeepVerifiedCredentialsOnlyInStrictCookies(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Lotor-Key-Claim-Token", "claim-secret")
		w.Header().Set("Set-Cookie", "untrusted=secret")
		_, _ = w.Write([]byte(`{"access_token":"access-secret","subject":"alice","email":"alice@example.test","e2ee":{"claim_required":true,"claim_id":"claim-id"}}`))
	})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, request("POST", "/auth/passwordless/verify"))
	if w.Code != 200 || strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("invalid sanitized response: %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 3 {
		t.Fatalf("cookies: %d", len(cookies))
	}
	for _, c := range cookies {
		if c.Domain != "" || c.SameSite != http.SameSiteStrictMode {
			t.Fatal("cookie is not host-only strict")
		}
		if c.Name != "lotor_dev_csrf" && !c.HttpOnly {
			t.Fatal("credential readable by JS")
		}
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["authenticated"] != true {
		t.Fatal("invalid browser session")
	}
}

func TestItShouldRejectIncompleteE2EEVerificationWithoutSettingCookies(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"token","subject":"alice","e2ee":{"claim_required":true,"claim_id":"claim-id"}}`))
	})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, request("POST", "/auth/passwordless/verify"))
	if w.Code != 502 || len(w.Result().Cookies()) != 0 {
		t.Fatal("partial authentication accepted")
	}
}

func TestItShouldPropagateDenialsWithoutLeakingRemoteBodies(t *testing.T) {
	for _, status := range []int{401, 403, 404, 409, 429, 503} {
		a := fixture(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("sensitive upstream diagnostic"))
		})
		w := httptest.NewRecorder()
		a.ServeHTTP(w, request("GET", "/session"))
		if w.Code != status || strings.Contains(w.Body.String(), "sensitive") {
			t.Fatalf("status %d", w.Code)
		}
	}
}

func TestItShouldNotFollowUpstreamRedirects(t *testing.T) {
	calls := 0
	a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Redirect(w, r, "https://other.example", http.StatusFound)
	})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, request("GET", "/session"))
	if w.Code != 502 || calls != 1 || w.Header().Get("Location") != "" {
		t.Fatal("redirect escaped boundary")
	}
}

func TestItShouldRevokeRemotelyBeforeClearingSessionCookies(t *testing.T) {
	a := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Error("method")
		}
		w.WriteHeader(204)
	})
	r := request("DELETE", "/session")
	r.AddCookie(&http.Cookie{Name: "lotor_dev_csrf", Value: "proof"})
	r.Header.Set("X-Lotor-CSRF", "proof")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 204 || len(w.Result().Cookies()) != 3 {
		t.Fatalf("status %d", w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge != -1 {
			t.Fatal("cookie not cleared")
		}
	}
}
