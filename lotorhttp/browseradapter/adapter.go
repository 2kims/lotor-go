// Package browseradapter is an HTTP cookie boundary, not an identity authority.
package browseradapter

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Config struct {
	APIURL         string
	BrowserOrigin  string
	ClientID       string
	PublishableKey string
	SecretKey      string
}

type Adapter struct {
	client *http.Client
	origin *url.URL
	config Config
	secure bool
}

const (
	prefix        = "/.lotor/v1"
	bodyLimit     = 64 << 10
	responseLimit = 4 << 20
)

var clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

func New(config Config) (*Adapter, error) {
	remote, err := originURL(config.APIURL)
	if err != nil || remote.Scheme != "https" {
		return nil, errors.New("Lotor API URL must be an HTTPS origin")
	}
	origin, err := originURL(config.BrowserOrigin)
	if err != nil || (origin.Scheme != "https" && !(origin.Scheme == "http" && (origin.Hostname() == "localhost" || origin.Hostname() == "127.0.0.1" || origin.Hostname() == "::1"))) {
		return nil, errors.New("browser origin must use HTTPS except on explicit loopback")
	}
	if !clientIDPattern.MatchString(config.ClientID) || !validValue(config.PublishableKey) || !validValue(config.SecretKey) {
		return nil, errors.New("Lotor application credentials are required")
	}
	config.APIURL = remote.String()
	config.BrowserOrigin = origin.String()
	return &Adapter{config: config, origin: origin, secure: origin.Scheme == "https", client: &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func originURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errors.New("invalid origin")
	}
	return u, nil
}

func validValue(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, c := range value {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func equal(a, b string) bool { return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func (a *Adapter) names() (string, string, string) {
	if a.secure {
		return "__Host-lotor_session", "__Host-lotor_csrf", "__Secure-lotor_key_claim_token"
	}
	return "lotor_dev_session", "lotor_dev_csrf", "lotor_key_claim_token"
}

func cookieValue(r *http.Request, name string) string {
	result := ""
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == name {
			result = c.Value
			count++
		}
	}
	if count != 1 {
		return ""
	}
	return result
}

func (a *Adapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// This boundary never opts into cross-origin credential access, even if an
	// outer application middleware sets permissive CORS headers.
	for name := range w.Header() {
		if strings.HasPrefix(strings.ToLower(name), "access-control-") {
			w.Header().Del(name)
		}
	}
	fail := func(status int) { http.Error(w, "Lotor request rejected", status) }
	if r.Host != a.origin.Host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != a.config.BrowserOrigin) || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		fail(403)
		return
	}
	if !equal(r.Header.Get("X-Lotor-Publishable-Key"), a.config.PublishableKey) {
		fail(401)
		return
	}
	nativeResource := resourceRoute(r.Method, r.URL.EscapedPath())
	if (r.URL.RawPath != "" && !nativeResource) || !validResourceQuery(r.Method, r.URL.Path, r.URL.RawQuery) || r.URL.ForceQuery {
		fail(400)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, prefix)
	allowed := r.URL.Path == prefix+path && ((r.Method == "GET" && (path == "/configuration" || path == "/pricing" || path == "/session")) || (r.Method == "POST" && (path == "/auth/passwordless/start" || path == "/auth/passwordless/verify")) || (r.Method == "DELETE" && path == "/session"))
	if !allowed && !nativeResource {
		fail(404)
		return
	}
	sessionName, csrfName, _ := a.names()
	if r.Method != "GET" && r.Header.Get("Origin") != a.config.BrowserOrigin {
		fail(403)
		return
	}
	if (r.Method == "DELETE" || (nativeResource && r.Method != "GET")) && !equal(cookieValue(r, csrfName), r.Header.Get("X-Lotor-CSRF")) {
		fail(403)
		return
	}
	if nativeResource && cookieValue(r, sessionName) == "" {
		fail(401)
		return
	}
	if r.ContentLength > bodyLimit {
		fail(413)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, bodyLimit))
	if err != nil {
		fail(413)
		return
	}
	bodylessInvitation := nativeResource && strings.HasPrefix(path, "/me/invitations/") && len(body) == 0
	if r.Method == "POST" && !bodylessInvitation && (strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" || !json.Valid(body)) {
		fail(400)
		return
	}
	remote, err := http.NewRequestWithContext(r.Context(), r.Method, a.config.APIURL+"/v1/public/applications/"+a.config.ClientID+strings.TrimPrefix(r.URL.EscapedPath(), prefix), bytes.NewReader(body))
	if err != nil {
		fail(502)
		return
	}
	remote.URL.RawQuery = r.URL.RawQuery
	if nativeResource && strings.HasPrefix(path, "/key-access/claims/") {
		_, _, claimName := a.names()
		token := cookieValue(r, claimName)
		if !validValue(token) {
			fail(401)
			return
		}
		remote.Header.Set("Lotor-Key-Claim-Token", token)
	}
	if nativeResource && strings.HasSuffix(path, "/links/commit") {
		token := cookieValue(r, "lotor_link_token")
		if !validValue(token) {
			fail(401)
			return
		}
		remote.Header.Set("Lotor-Link-Token", token)
	}
	if nativeResource && strings.Contains(path, "/payloads/") && strings.HasSuffix(path, "/commits") {
		token := cookieValue(r, "lotor_payload_token")
		if !validValue(token) {
			fail(401)
			return
		}
		remote.Header.Set("Lotor-Payload-Token", token)
	}
	// Browser resource requests carry only end-user authority. The issued
	// publishable key and session are scope-checked together by remote Lotor.
	if !nativeResource {
		remote.Header.Set("X-Lotor-Secret-Key", a.config.SecretKey)
	}
	remote.Header.Set("X-Lotor-Publishable-Key", a.config.PublishableKey)
	if r.Header.Get("X-Lotor-Request") == "lotor-js-v1" {
		remote.Header.Set("X-Lotor-Request", "lotor-js-v1")
	}
	remote.Header.Set("Content-Type", "application/json")
	remote.Header.Set("Accept", "application/json")
	if idempotency := r.Header.Get("Idempotency-Key"); idempotency != "" {
		if !validValue(idempotency) {
			fail(400)
			return
		}
		remote.Header.Set("Idempotency-Key", idempotency)
	}
	// Login never borrows a previous session or an arbitrary browser bearer.
	if path == "/session" || nativeResource {
		if token := cookieValue(r, sessionName); token != "" {
			remote.Header.Set("Authorization", "Bearer "+token)
		}
	}
	response, err := a.client.Do(remote)
	if err != nil {
		fail(502)
		return
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || len(payload) > responseLimit {
		fail(502)
		return
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		fail(502)
		return
	}
	if response.StatusCode >= 400 {
		if retry := response.Header.Get("Retry-After"); len(retry) < 128 {
			w.Header().Set("Retry-After", retry)
		}
		fail(response.StatusCode)
		return
	}
	if path == "/auth/passwordless/verify" {
		a.finishVerification(w, payload, response.Header.Get("Lotor-Key-Claim-Token"))
		return
	}
	if r.Method == "DELETE" && path == "/session" {
		a.clearCookies(w)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !json.Valid(payload) {
		fail(502)
		return
	}
	if nativeResource && strings.HasSuffix(path, "/links/preflight") {
		token := response.Header.Get("Lotor-Link-Token")
		if !validValue(token) || (&http.Cookie{Name: "lotor_link_token", Value: token}).Valid() != nil {
			fail(502)
			return
		}
		cookie := a.cookie("lotor_link_token", token, strings.TrimSuffix(r.URL.EscapedPath(), "/preflight"), true, false)
		cookie.MaxAge = 300
		cookie.Expires = time.Now().Add(5 * time.Minute)
		http.SetCookie(w, cookie)
	}
	if nativeResource && strings.Contains(path, "/payloads/") && strings.HasSuffix(path, "/uploads") {
		token := response.Header.Get("Lotor-Payload-Token")
		if !validValue(token) || (&http.Cookie{Name: "lotor_payload_token", Value: token}).Valid() != nil {
			fail(502)
			return
		}
		cookie := a.cookie("lotor_payload_token", token, strings.TrimSuffix(r.URL.EscapedPath(), "/uploads"), true, false)
		cookie.MaxAge = 300
		cookie.Expires = time.Now().Add(5 * time.Minute)
		http.SetCookie(w, cookie)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(payload)
}

type encryptionClaim struct {
	ID       string `json:"claim_id,omitempty"`
	Required bool   `json:"claim_required"`
}

func (a *Adapter) finishVerification(w http.ResponseWriter, payload []byte, claimToken string) {
	var verified struct {
		E2EE        *encryptionClaim `json:"e2ee,omitempty"`
		AccessToken string           `json:"access_token"`
		Subject     string           `json:"subject"`
		Email       string           `json:"email"`
	}
	sessionName, csrfName, claimName := a.names()
	if json.Unmarshal(payload, &verified) != nil || verified.Subject == "" || !validValue(verified.AccessToken) || (&http.Cookie{Name: sessionName, Value: verified.AccessToken}).Valid() != nil || (verified.E2EE != nil && verified.E2EE.Required && (verified.E2EE.ID == "" || !validValue(claimToken) || (&http.Cookie{Name: claimName, Value: claimToken}).Valid() != nil)) {
		http.Error(w, "Invalid Lotor verification response", 502)
		return
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		http.Error(w, "Session cookie unavailable", 500)
		return
	}
	// Session cookies do not invent a token lifetime. Remote Lotor checks expiry
	// on every authenticated request; this process never verifies identity itself.
	http.SetCookie(w, a.cookie(sessionName, verified.AccessToken, "/", true, false))
	http.SetCookie(w, a.cookie(csrfName, base64.RawURLEncoding.EncodeToString(random), "/", false, false))
	required := verified.E2EE != nil && verified.E2EE.Required
	if !required {
		claimToken = ""
	}
	http.SetCookie(w, a.cookie(claimName, claimToken, prefix+"/key-access/claims", true, !required))
	result := struct {
		E2EE          *encryptionClaim `json:"e2ee,omitempty"`
		Subject       string           `json:"subject"`
		Email         string           `json:"email"`
		Authenticated bool             `json:"authenticated"`
	}{E2EE: verified.E2EE, Subject: verified.Subject, Email: verified.Email, Authenticated: true}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (a *Adapter) cookie(name, value, path string, httpOnly, expire bool) *http.Cookie {
	c := &http.Cookie{Name: name, Value: value, Path: path, Secure: a.secure, HttpOnly: httpOnly, SameSite: http.SameSiteStrictMode}
	if expire {
		c.MaxAge = -1
		c.Expires = time.Unix(1, 0)
	}
	return c
}

func (a *Adapter) clearCookies(w http.ResponseWriter) {
	session, csrf, claim := a.names()
	http.SetCookie(w, a.cookie(session, "", "/", true, true))
	http.SetCookie(w, a.cookie(csrf, "", "/", false, true))
	http.SetCookie(w, a.cookie(claim, "", prefix+"/key-access/claims", true, true))
}
