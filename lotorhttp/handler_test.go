package lotorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeSessions struct {
	token     string
	deleted   string
	requested string
}

func (s *fakeSessions) Bearer(_ context.Context, id string) (string, error) {
	s.requested = id
	if s.token == "" {
		return "", ErrNoSession
	}
	return s.token, nil
}

func TestAcceptSupportsAnExplicitApplicationBearer(t *testing.T) {
	handler, sessions, _, runtime := fixtureHandler()
	request := commandRequest("/api/lotor/invitations/accept", `{"ticket":"ticket","idempotency_key":"key"}`)
	request.Header.Set("Authorization", "Bearer public-application-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || sessions.requested != "public-application-token" || runtime.call.kind != "accept" {
		t.Fatalf("status=%d session=%q call=%+v", response.Code, sessions.requested, runtime.call)
	}
}
func (s *fakeSessions) Delete(_ context.Context, id string) error { s.deleted = id; return nil }

type fakeIdentity struct {
	identity Identity
	err      error
	token    string
}

func (v *fakeIdentity) Verify(_ context.Context, token string) (Identity, error) {
	v.token = token
	return v.identity, v.err
}

type runtimeCall struct {
	kind, ticket, organization, invitationID, key string
	identity                                      Identity
}

type fakeRuntime struct { //nolint:govet // explicit test recording fields are easier to audit in command order.
	call   runtimeCall
	result lifecycleResult
	err    error
}

func (r *fakeRuntime) Accept(_ context.Context, identity Identity, ticket, key string) (lifecycleResult, error) {
	r.call = runtimeCall{kind: "accept", identity: identity, ticket: ticket, key: key}
	return r.result, r.err
}

func (r *fakeRuntime) Cancel(_ context.Context, identity Identity, organization, invitationID, key string) (lifecycleResult, error) {
	r.call = runtimeCall{kind: "cancel", identity: identity, organization: organization, invitationID: invitationID, key: key}
	return r.result, r.err
}

func fixtureHandler() (*Handler, *fakeSessions, *fakeIdentity, *fakeRuntime) {
	sessions := &fakeSessions{token: "control-bearer-secret"}
	identity := &fakeIdentity{identity: Identity{
		Subject: "user:member", Email: "member@example.test", TenantID: "tenant:one",
		ApplicationID: "app:signalbox", EnvironmentID: "env:staging",
	}}
	runtime := &fakeRuntime{result: lifecycleResult{
		Succeeded: true, Reason: "accepted", InvitationID: "inv_1",
		Active: 2, Reserved: 0, Used: 2, Maximum: 3, Remaining: 1,
	}}
	return newHandler("signalbox_session", sessions, identity, runtime), sessions, identity, runtime
}

func commandRequest(path, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://signalbox.example"+path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Lotor-Request", "browser-sdk-v1")
	request.Header.Set("Origin", "https://signalbox.example")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(&http.Cookie{Name: "signalbox_session", Value: "opaque-session"})
	return request
}

func TestAcceptBindsVerifiedIdentityAndReturnsOnlyPublicLifecycleFields(t *testing.T) {
	handler, _, verifier, runtime := fixtureHandler()
	request := commandRequest("/api/lotor/invitations/accept", `{"ticket":"ticket-secret","idempotency_key":"browser-key"}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if verifier.token != "control-bearer-secret" || runtime.call.kind != "accept" || runtime.call.ticket != "ticket-secret" ||
		runtime.call.identity.Subject != "user:member" || runtime.call.identity.Email != "member@example.test" ||
		runtime.call.key != deriveKey("accept-v1", "user:member", "browser-key") {
		t.Fatalf("verifier=%q call=%+v", verifier.token, runtime.call)
	}
	body := response.Body.String()
	for _, forbidden := range []string{"ticket-secret", "control-bearer-secret", "tenant:one", "app:signalbox", "env:staging", "evidence", "composition", "log_seq"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
	var output struct {
		Reason       string `json:"reason"`
		InvitationID string `json:"invitation_id"`
		Succeeded    bool   `json:"succeeded"`
		Capacity     struct {
			Active, Reserved, Used, Maximum, Remaining int64
		} `json:"capacity"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil || !output.Succeeded || output.InvitationID != "inv_1" || output.Capacity.Used != 2 {
		t.Fatalf("output=%+v err=%v", output, err)
	}
}

func TestCancelUsesPublicOrganizationButSessionDerivedActor(t *testing.T) {
	handler, _, _, runtime := fixtureHandler()
	runtime.result.Reason = "cancelled"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, commandRequest("/api/lotor/invitations/cancel", `{"organization":"workspace-acme","invitation_id":"inv_2","idempotency_key":"cancel-key"}`))
	if response.Code != http.StatusOK || runtime.call.kind != "cancel" || runtime.call.organization != "workspace-acme" ||
		runtime.call.invitationID != "inv_2" || runtime.call.identity.Subject != "user:member" ||
		runtime.call.key != deriveKey("cancel-v1", "user:member", "cancel-key") {
		t.Fatalf("status=%d call=%+v body=%s", response.Code, runtime.call, response.Body.String())
	}
}

func TestLifecycleDenialIsDefinitiveResult(t *testing.T) {
	handler, _, _, runtime := fixtureHandler()
	runtime.result = lifecycleResult{Succeeded: false, Reason: "no_seats", InvitationID: "inv_1", Active: 1, Used: 1, Maximum: 1, Remaining: 0}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, commandRequest("/api/lotor/invitations/accept", `{"ticket":"ticket","idempotency_key":"key"}`))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"succeeded":false`) || !strings.Contains(response.Body.String(), `"no_seats"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestInvalidSessionIsDeletedAndRuntimeIsNotCalled(t *testing.T) {
	handler, sessions, verifier, runtime := fixtureHandler()
	verifier.err = errIdentityRejected
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, commandRequest("/api/lotor/invitations/accept", `{"ticket":"ticket","idempotency_key":"key"}`))
	if response.Code != http.StatusUnauthorized || sessions.deleted != "opaque-session" || runtime.call.kind != "" {
		t.Fatalf("status=%d deleted=%q call=%+v", response.Code, sessions.deleted, runtime.call)
	}
}

func TestTransientIdentityFailureDoesNotDestroySession(t *testing.T) {
	handler, sessions, verifier, runtime := fixtureHandler()
	verifier.err = errors.New("Control temporarily unavailable")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, commandRequest("/api/lotor/invitations/accept", `{"ticket":"ticket","idempotency_key":"key"}`))
	if response.Code != http.StatusServiceUnavailable || sessions.deleted != "" || runtime.call.kind != "" {
		t.Fatalf("status=%d deleted=%q call=%+v", response.Code, sessions.deleted, runtime.call)
	}
}

func TestRuntimeScopeMismatchDeletesApplicationSession(t *testing.T) {
	handler, sessions, _, runtime := fixtureHandler()
	runtime.err = errScopeMismatch
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, commandRequest("/api/lotor/invitations/accept", `{"ticket":"ticket","idempotency_key":"key"}`))
	if response.Code != http.StatusUnauthorized || sessions.deleted != "opaque-session" {
		t.Fatalf("status=%d deleted=%q", response.Code, sessions.deleted)
	}
}

func TestBrowserMutationSecurityAndInputValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
		body   string
		status int
	}{
		{name: "missing marker", mutate: func(r *http.Request) { r.Header.Del("X-Lotor-Request") }, body: `{"ticket":"ticket","idempotency_key":"key"}`, status: http.StatusForbidden},
		{name: "cross site", mutate: func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, body: `{"ticket":"ticket","idempotency_key":"key"}`, status: http.StatusForbidden},
		{name: "cross origin", mutate: func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, body: `{"ticket":"ticket","idempotency_key":"key"}`, status: http.StatusForbidden},
		{name: "unknown field", mutate: func(*http.Request) {}, body: `{"ticket":"ticket","idempotency_key":"key","scope":"org:other"}`, status: http.StatusBadRequest},
		{name: "typed organization", mutate: func(*http.Request) {}, body: `{"organization":"org:personal-test","ticket":"ticket","idempotency_key":"key"}`, status: http.StatusBadRequest},
		{name: "unrecognized organization", mutate: func(*http.Request) {}, body: `{"organization":"plain-id","ticket":"ticket","idempotency_key":"key"}`, status: http.StatusBadRequest},
		{name: "empty key", mutate: func(*http.Request) {}, body: `{"ticket":"ticket","idempotency_key":""}`, status: http.StatusBadRequest},
		{name: "oversized body", mutate: func(*http.Request) {}, body: `{"ticket":"` + strings.Repeat("x", maxRequestBody) + `","idempotency_key":"key"}`, status: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, _, _, runtime := fixtureHandler()
			request := commandRequest("/api/lotor/invitations/accept", test.body)
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || runtime.call.kind != "" {
				t.Fatalf("status=%d call=%+v body=%s", response.Code, runtime.call, response.Body.String())
			}
		})
	}
}

func TestRuntimeErrorsAreSafelyMapped(t *testing.T) {
	for _, test := range []struct {
		err    error
		code   string
		status int
	}{
		{err: errIdempotencyConflict, code: "idempotency_conflict", status: http.StatusConflict},
		{err: errScopeMismatch, code: "unauthenticated", status: http.StatusUnauthorized},
		{err: errors.New("upstream secret detail"), code: "runtime_unavailable", status: http.StatusServiceUnavailable},
	} {
		handler, _, _, runtime := fixtureHandler()
		runtime.err = test.err
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, commandRequest("/api/lotor/invitations/accept", `{"ticket":"ticket","idempotency_key":"key"}`))
		if response.Code != test.status || !strings.Contains(response.Body.String(), test.code) || strings.Contains(response.Body.String(), "secret detail") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestCommandIdempotencyNamespacesAndUsersDoNotCollide(t *testing.T) {
	accept := deriveKey("accept-v1", "user:one", "same-key")
	if accept == deriveKey("cancel-v1", "user:one", "same-key") || accept == deriveKey("accept-v1", "user:two", "same-key") ||
		accept != deriveKey("accept-v1", "user:one", "same-key") {
		t.Fatal("idempotency derivation did not isolate command and user")
	}
}
