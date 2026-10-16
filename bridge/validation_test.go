package bridge

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestControlValidatorUsesRuntimeProofWithoutApplicationCredentials(t *testing.T) {
	f := setup(t)
	message, err := SignAuthorization(f.auth, "issuer-key", f.issuer)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/function-bindings/binding-1/authorizations/validate" || r.Method != "POST" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("validation leaked or changed authority")
		}
		var proof SignedMessage
		if decodeErr := json.NewDecoder(r.Body).Decode(&proof); decodeErr != nil {
			t.Error(decodeErr)
			w.WriteHeader(400)
			return
		}
		value, verifyErr := VerifyValidation(proof, f.config.SigningKey.Public().(ed25519.PublicKey))
		if verifyErr != nil || value.Authorization != message {
			t.Error("validation lost exact signed grant")
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	validator, err := NewControlValidator(ControlValidatorOptions{BaseURL: server.URL, HTTPClient: server.Client(), SigningKeyID: f.config.SigningKeyID, SigningKey: f.config.SigningKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Authorize(context.Background(), f.auth, message); err != nil || calls != 1 {
		t.Fatalf("validation calls=%d err=%v", calls, err)
	}
	challenge := f.auth
	challenge.Kind = "challenge"
	if err := validator.Authorize(context.Background(), challenge, message); err != nil || calls != 1 {
		t.Fatal("challenge contacted execution authorization")
	}
	wrongPurpose, _ := SignAuthorization(f.auth, f.config.SigningKeyID, f.config.SigningKey)
	if _, err := VerifyValidation(wrongPurpose, f.config.SigningKey.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("validation signature purpose was not isolated")
	}
}

func TestControlValidatorFailsClosedWithoutFollowingRedirects(t *testing.T) {
	f := setup(t)
	message, _ := SignAuthorization(f.auth, "issuer-key", f.issuer)
	var redirects atomic.Int32
	var status atomic.Int32
	status.Store(http.StatusForbidden)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirects.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Location", "/redirected")
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte("private runtime diagnostic must not escape"))
	}))
	defer server.Close()
	options := ControlValidatorOptions{BaseURL: server.URL, HTTPClient: server.Client(), SigningKeyID: f.config.SigningKeyID, SigningKey: f.config.SigningKey}
	validator, err := NewControlValidator(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int32{http.StatusForbidden, http.StatusServiceUnavailable, http.StatusTemporaryRedirect} {
		status.Store(code)
		err := validator.Authorize(context.Background(), f.auth, message)
		want := ErrUnavailable
		if code == http.StatusForbidden {
			want = ErrUnauthorized
		}
		if !errors.Is(err, want) {
			t.Fatalf("status=%d err=%v", code, err)
		}
	}
	if redirects.Load() != 0 {
		t.Fatal("signed validation was redirected")
	}
	for _, endpoint := range []string{"http://control.example", "https://user:secret@control.example", "https://control.example?query=1", "https://control.example#fragment"} {
		options.BaseURL = endpoint
		if _, err := NewControlValidator(options); err == nil {
			t.Fatal("invalid Control endpoint accepted")
		}
	}
}
