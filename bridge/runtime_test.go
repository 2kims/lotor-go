package bridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Explicit test fixture, not a production durable-store implementation.
type testStore struct {
	hashes       map[string]string
	results      map[string]Result
	mu           sync.Mutex
	failReserve  bool
	failComplete bool
}

func (s *testStore) Reserve(_ context.Context, id, digest string) (*Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failReserve {
		return nil, ErrUnavailable
	}
	if previous, ok := s.hashes[id]; ok {
		if previous != digest {
			return nil, ErrConflict
		}
		if result, ok := s.results[id]; ok {
			return &result, nil
		}
		return nil, ErrInProgress
	}
	s.hashes[id] = digest
	return nil, nil
}

func (s *testStore) Complete(_ context.Context, id, digest string, result Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failComplete {
		return ErrUnavailable
	}
	if s.hashes[id] != digest {
		return ErrConflict
	}
	s.results[id] = result
	return nil
}

type fixture struct {
	runtime *Runtime
	store   *testStore
	issuer  ed25519.PrivateKey
	config  Config
	auth    Authorization
	calls   int
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pub, issuer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{issuer: issuer, store: &testStore{hashes: map[string]string{}, results: map[string]Result{}}}
	fn := Function{Name: "customer.echo", Version: "1", InputSchemaDigest: Digest([]byte("input")), OutputSchemaDigest: Digest([]byte("output"))}
	now := time.Now().Truncate(time.Second)
	f.config = Config{
		Issuer: "lotor", Audience: "customer-runtime", BindingID: "binding-1", BindingRevision: 1,
		Scope:        Scope{TenantID: "tenant", ApplicationID: "application", EnvironmentID: "sandbox", OwnerResource: "organization:customer"},
		SigningKeyID: "box-key", SigningKey: signing, TrustedKeys: map[string]ed25519.PublicKey{"issuer-key": pub},
		Functions: []Registration{{Function: fn, Handler: func(_ context.Context, a Authorization) (json.RawMessage, error) { f.calls++; return a.Input, nil }}},
		Store:     f.store, Authorize: func(context.Context, Authorization, SignedMessage) error { return nil }, Now: func() time.Time { return now },
	}
	f.runtime, err = NewRuntime(f.config)
	if err != nil {
		t.Fatal(err)
	}
	input := json.RawMessage(`{"value":"hello"}`)
	f.auth = Authorization{
		ProtocolVersion: 1, Kind: "invocation", ID: "invocation-1", Issuer: f.config.Issuer, Audience: f.config.Audience,
		BindingID: f.config.BindingID, BindingRevision: 1, Scope: f.config.Scope, ManifestDigest: f.runtime.manifestDigest,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Function: &fn, Principal: "user:one",
		Resources: []string{"resource:one"}, Capabilities: []string{"payload.read"}, Input: input, InputDigest: Digest(input), PolicyDigest: Digest([]byte("policy")),
	}
	return f
}

func (f *fixture) call(t *testing.T, auth Authorization, path string) (*httptest.ResponseRecorder, Result) {
	t.Helper()
	signed, err := sign(auth, authorizationPurpose, "issuer-key", f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.runtime.ServeHTTP(w, req)
	var result Result
	if w.Code == 200 {
		var message SignedMessage
		if err := json.Unmarshal(w.Body.Bytes(), &message); err != nil {
			t.Fatal(err)
		}
		_, raw, err := VerifyAuthorization(signed, f.issuer.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		result, err = VerifyResult(message, f.config.SigningKey.Public().(ed25519.PublicKey), auth, raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	return w, result
}

func TestChallengeNeverExecutesFunction(t *testing.T) {
	f := setup(t)
	a := f.auth
	a.Kind, a.Nonce = "challenge", "one-use-nonce"
	a.Function, a.Principal, a.Input, a.InputDigest, a.PolicyDigest = nil, "", nil, "", ""
	a.Resources, a.Capabilities = nil, nil
	w, result := f.call(t, a, "/v1/functions/challenge")
	if w.Code != 200 || result.Nonce != a.Nonce || f.calls != 0 || len(f.store.hashes) != 0 {
		t.Fatal("challenge caused execution")
	}
	w, _ = f.call(t, a, "/v1/functions/invoke")
	if w.Code != 401 || f.calls != 0 {
		t.Fatal("challenge used for invocation")
	}
}

func TestInvocationRejectsInvalidAuthorization(t *testing.T) {
	for _, test := range []struct {
		change func(*Authorization)
		name   string
	}{
		{name: "expired", change: func(a *Authorization) { a.ExpiresAt = a.IssuedAt }},
		{name: "future", change: func(a *Authorization) { a.IssuedAt++ }},
		{name: "overlong", change: func(a *Authorization) { a.ExpiresAt = a.IssuedAt + 301 }},
		{name: "negative issue time", change: func(a *Authorization) { a.IssuedAt = -9223372036854775808 }},
		{name: "issuer", change: func(a *Authorization) { a.Issuer = "other" }},
		{name: "audience", change: func(a *Authorization) { a.Audience = "other" }},
		{name: "tenant", change: func(a *Authorization) { a.Scope.TenantID = "other" }},
		{name: "application", change: func(a *Authorization) { a.Scope.ApplicationID = "other" }},
		{name: "environment", change: func(a *Authorization) { a.Scope.EnvironmentID = "other" }},
		{name: "owner", change: func(a *Authorization) { a.Scope.OwnerResource = "other" }},
		{name: "binding", change: func(a *Authorization) { a.BindingID = "other" }},
		{name: "revision", change: func(a *Authorization) { a.BindingRevision++ }},
		{name: "manifest", change: func(a *Authorization) { a.ManifestDigest = Digest([]byte("other")) }},
		{name: "input", change: func(a *Authorization) { a.Input = json.RawMessage(`{"changed":true}`) }},
		{name: "policy", change: func(a *Authorization) { a.PolicyDigest = "invalid" }},
		{name: "function", change: func(a *Authorization) {
			changed := *a.Function
			changed.Name = "crypto.provision"
			a.Function = &changed
		}},
		{name: "version", change: func(a *Authorization) { changed := *a.Function; changed.Version = "2"; a.Function = &changed }},
		{name: "principal", change: func(a *Authorization) { a.Principal = "" }},
		{name: "nonce", change: func(a *Authorization) { a.Nonce = "nonce" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := setup(t)
			a := f.auth
			test.change(&a)
			w, _ := f.call(t, a, "/v1/functions/invoke")
			if w.Code != 401 || f.calls != 0 || len(f.store.hashes) != 0 {
				t.Fatalf("invalid authorization accepted: %d", w.Code)
			}
		})
	}
}

func TestExecutionReplaysAfterRestartWithoutRepeatingEffects(t *testing.T) {
	f := setup(t)
	w, result := f.call(t, f.auth, "/v1/functions/invoke")
	if w.Code != 200 || string(result.Output) != string(f.auth.Input) || f.calls != 1 {
		t.Fatalf("execution status=%d", w.Code)
	}
	var err error
	f.runtime, err = NewRuntime(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.auth.IssuedAt-- // renewed authorization, same semantic operation
	w, replay := f.call(t, f.auth, "/v1/functions/invoke")
	if w.Code != 200 || f.calls != 1 || string(replay.Output) != string(result.Output) {
		t.Fatal("restart repeated effects")
	}
	f.auth.Input = json.RawMessage(`{"changed":true}`)
	f.auth.InputDigest = Digest(f.auth.Input)
	w, _ = f.call(t, f.auth, "/v1/functions/invoke")
	if w.Code != 409 || f.calls != 1 {
		t.Fatal("conflicting operation repeated effects")
	}
}

func TestFailureDoesNotLeakOrRepeatEffects(t *testing.T) {
	for _, failure := range []string{"error", "panic", "storage", "output"} {
		t.Run(failure, func(t *testing.T) {
			f := setup(t)
			f.config.Functions[0].Handler = func(context.Context, Authorization) (json.RawMessage, error) {
				f.calls++
				switch failure {
				case "error":
					return nil, errors.New("SECRET-CREDENTIAL")
				case "panic":
					panic("SECRET-CREDENTIAL")
				case "output":
					return json.RawMessage("SECRET-CREDENTIAL"), nil
				}
				return json.RawMessage(`{"ok":true}`), nil
			}
			f.store.failComplete = failure == "storage"
			var err error
			f.runtime, err = NewRuntime(f.config)
			if err != nil {
				t.Fatal(err)
			}
			w, result := f.call(t, f.auth, "/v1/functions/invoke")
			if strings.Contains(w.Body.String(), "SECRET-CREDENTIAL") || failure != "storage" && (w.Code != 200 || result.ErrorCode != "outcome_unknown") || failure == "storage" && w.Code != 503 {
				t.Fatalf("unsafe failure: %d", w.Code)
			}
			w, _ = f.call(t, f.auth, "/v1/functions/invoke")
			if f.calls != 1 || failure == "storage" && w.Code != 409 {
				t.Fatal("ambiguous outcome repeated effects")
			}
		})
	}
}

func TestDependenciesFailClosed(t *testing.T) {
	for _, failure := range []string{"authorization", "unavailable", "store"} {
		t.Run(failure, func(t *testing.T) {
			f := setup(t)
			expected := 503
			if failure == "store" {
				f.store.failReserve = true
			} else {
				f.config.Authorize = func(context.Context, Authorization, SignedMessage) error {
					if failure == "authorization" {
						return ErrUnauthorized
					}
					return ErrUnavailable
				}
				if failure == "authorization" {
					expected = 401
				}
				var err error
				f.runtime, err = NewRuntime(f.config)
				if err != nil {
					t.Fatal(err)
				}
			}
			w, _ := f.call(t, f.auth, "/v1/functions/invoke")
			if w.Code != expected || f.calls != 0 {
				t.Fatal("dependency failure executed function")
			}
		})
	}
}

func TestMalformedAndUntrustedRequests(t *testing.T) {
	f := setup(t)
	signed, err := SignAuthorization(f.auth, "issuer-key", f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	valid, _ := json.Marshal(signed)
	for _, test := range []struct {
		name, body string
		status     int
	}{
		{"malformed", "{", 400},
		{"trailing", string(valid) + " {}", 400},
		{"oversized", strings.Repeat("x", MaximumBodyBytes+1), 400},
		{"unknown field", `{"key_id":"x","payload":"x","signature":"x","extra":true}`, 400},
		{"unknown key", `{"key_id":"other","payload":"x","signature":"x"}`, 401},
		{"bad signature", `{"key_id":"issuer-key","payload":"x","signature":"x"}`, 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/functions/invoke", strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			f.runtime.ServeHTTP(w, req)
			if w.Code != test.status || f.calls != 0 {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
}

func TestConfigRequiresStorageAndAuthorization(t *testing.T) {
	f := setup(t)
	config := f.config
	config.Store = nil
	if _, err := NewRuntime(config); err == nil {
		t.Fatal("missing store accepted")
	}
	config = f.config
	config.Authorize = nil
	if _, err := NewRuntime(config); err == nil {
		t.Fatal("missing authorization accepted")
	}
}

func TestSigningPreservesInputDigestForFormattedJSON(t *testing.T) {
	f := setup(t)
	f.auth.Input = json.RawMessage("{\n  \"value\": \"hello <>&\"\n}")
	f.auth.InputDigest = Digest(f.auth.Input)
	message, err := SignAuthorization(f.auth, "issuer-key", f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _, err := VerifyAuthorization(message, f.issuer.Public().(ed25519.PublicKey))
	if err != nil || decoded.InputDigest != Digest(decoded.Input) {
		t.Fatal("JSON encoding invalidated the signed input digest")
	}
}

func TestInFlightInvocationDoesNotRunTwice(t *testing.T) {
	f := setup(t)
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.config.Functions[0].Handler = func(context.Context, Authorization) (json.RawMessage, error) {
		close(entered)
		<-release
		return json.RawMessage(`{"ok":true}`), nil
	}
	var err error
	f.runtime, err = NewRuntime(f.config)
	if err != nil {
		t.Fatal(err)
	}
	message, err := SignAuthorization(f.auth, "issuer-key", f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(message)
	go func() {
		defer close(finished)
		req := httptest.NewRequest("POST", "/v1/functions/invoke", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		f.runtime.ServeHTTP(httptest.NewRecorder(), req)
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first execution did not start")
	}
	w, _ := f.call(t, f.auth, "/v1/functions/invoke")
	close(release)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("first execution did not complete")
	}
	if w.Code != 409 {
		t.Fatal("in-flight invocation ran twice")
	}
}

type reserveHookStore struct {
	*testStore
	hook func(context.Context)
}

func TestAlreadyCancelledExecutionNeverEntersHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	_, err := execute(ctx, func(context.Context, Authorization) (json.RawMessage, error) {
		called = true
		return json.RawMessage(`{}`), nil
	}, Authorization{})
	if called || !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled execution entered handler")
	}
}

func (s reserveHookStore) Reserve(ctx context.Context, id, digest string) (*Result, error) {
	s.hook(ctx)
	return s.testStore.Reserve(ctx, id, digest)
}

func TestGrantDeadlineBoundsAuthorizationAndReservation(t *testing.T) {
	f := setup(t)
	check := func(ctx context.Context) {
		t.Helper()
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(time.Unix(f.auth.ExpiresAt, 0)) {
			t.Fatal("dependency did not receive the grant deadline")
		}
	}
	f.config.Authorize = func(ctx context.Context, _ Authorization, _ SignedMessage) error { check(ctx); return nil }
	f.config.Store = reserveHookStore{testStore: f.store, hook: check}
	var err error
	f.runtime, err = NewRuntime(f.config)
	if err != nil {
		t.Fatal(err)
	}
	response, result := f.call(t, f.auth, "/v1/functions/invoke")
	if response.Code != 200 || result.ErrorCode != "" || f.calls != 1 {
		t.Fatal("valid grant failed")
	}
}

func TestExpiryDuringDependenciesPreventsHandlerAndCachedReplay(t *testing.T) {
	for _, stage := range []string{"authorization", "reservation", "cached replay"} {
		t.Run(stage, func(t *testing.T) {
			f := setup(t)
			clock := f.config.Now()
			f.config.Now = func() time.Time { return clock }
			if stage == "cached replay" {
				response, _ := f.call(t, f.auth, "/v1/functions/invoke")
				if response.Code != 200 {
					t.Fatal("initial invocation failed")
				}
			}
			previous := f.calls
			expire := func() { clock = time.Unix(f.auth.ExpiresAt, 0) }
			if stage == "authorization" {
				f.config.Authorize = func(context.Context, Authorization, SignedMessage) error { expire(); return nil }
			} else {
				f.config.Store = reserveHookStore{testStore: f.store, hook: func(context.Context) { expire() }}
			}
			var err error
			f.runtime, err = NewRuntime(f.config)
			if err != nil {
				t.Fatal(err)
			}
			response, _ := f.call(t, f.auth, "/v1/functions/invoke")
			if response.Code != 401 || f.calls != previous {
				t.Fatal("expired grant executed or replayed a result")
			}
			if stage == "authorization" && len(f.store.hashes) != 0 {
				t.Fatal("expired authorization reached reservation")
			}
			if stage == "reservation" {
				if _, err := f.store.Reserve(t.Context(), f.auth.BindingID+":"+f.auth.ID, f.store.hashes[f.auth.BindingID+":"+f.auth.ID]); !errors.Is(err, ErrInProgress) {
					t.Fatal("ambiguous reservation was released or completed")
				}
			}
		})
	}
}
