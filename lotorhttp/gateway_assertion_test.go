package lotorhttp

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type gatewayGolden struct {
	PublicKey string `json:"public_key_raw_base64url"`
	Assertion string `json:"assertion"`
	Request   struct {
		Method         string `json:"method"`
		Path           string `json:"path"`
		RawQuery       string `json:"raw_query"`
		Body           string `json:"body_base64url"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"request"`
	Claims GatewayAssertionClaims `json:"claims"`
	Now    int64                  `json:"now"`
}

func TestGatewayAssertionGoldenVector(t *testing.T) {
	t.Parallel()
	fixture := loadGatewayGolden(t)
	verifier := goldenVerifier(t, fixture, nil)
	claims, err := verifier.Verify(context.Background(), fixture.Assertion, goldenRequest(t, fixture))
	if err != nil {
		t.Fatalf("verify golden assertion: %v", err)
	}
	if claims.RequestID != fixture.Claims.RequestID || claims.Subject != "user:kim" {
		t.Fatalf("unexpected claims: %#v", claims)
	}

	wrongRequest := goldenRequest(t, fixture)
	wrongRequest.Body = []byte("tampered")
	if _, err = verifier.Verify(context.Background(), fixture.Assertion, wrongRequest); !errors.Is(err, ErrGatewayAssertionRejected) {
		t.Fatalf("tampered body error = %v", err)
	}

	checks := map[string]func(*GatewayAssertionAuthority){
		"audience":    func(value *GatewayAssertionAuthority) { value.Audience = "https://other.example" },
		"environment": func(value *GatewayAssertionAuthority) { value.EnvironmentID = "env-other" },
		"placement":   func(value *GatewayAssertionAuthority) { value.RuntimePlacementID = "runtime-other" },
		"epoch":       func(value *GatewayAssertionAuthority) { value.RuntimeOwnershipEpoch++ },
		"route":       func(value *GatewayAssertionAuthority) { value.RouteID = "other" },
		"config pin":  func(value *GatewayAssertionAuthority) { value.ConfigurationVersion++ },
	}
	for name, change := range checks {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wrongAuthority := goldenAuthority(fixture.Claims)
			change(&wrongAuthority)
			wrongVerifier := verifierForGolden(t, fixture, wrongAuthority, fixture.Now, nil)
			_, verifyErr := wrongVerifier.Verify(context.Background(), fixture.Assertion, goldenRequest(t, fixture))
			if !errors.Is(verifyErr, ErrGatewayAssertionRejected) {
				t.Fatalf("wrong authority error = %v", verifyErr)
			}
		})
	}
	expired := verifierForGolden(t, fixture, goldenAuthority(fixture.Claims), fixture.Claims.ExpiresAt+1, nil)
	if _, err = expired.Verify(context.Background(), fixture.Assertion, goldenRequest(t, fixture)); !errors.Is(err, ErrGatewayAssertionRejected) {
		t.Fatalf("expired assertion error = %v", err)
	}
	parts := strings.Split(fixture.Assertion, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 0xff
	forged := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	if _, err = verifier.Verify(context.Background(), forged, goldenRequest(t, fixture)); !errors.Is(err, ErrGatewayAssertionRejected) {
		t.Fatalf("forged assertion error = %v", err)
	}
}

func TestGatewayAssertionMiddlewareRequiresIndependentOriginAuthentication(t *testing.T) {
	t.Parallel()
	fixture := loadGatewayGolden(t)
	verifier := goldenVerifier(t, fixture, nil)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Header.Get("X-Lotor-Assertion") != "" {
			t.Fatal("raw assertion was forwarded")
		}
		claims, ok := GatewayAssertionFromContext(r.Context())
		if !ok || claims.RequestID != fixture.Claims.RequestID {
			t.Fatal("verified claims missing from context")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "opaque-encrypted-payload" {
			t.Fatalf("body = %q", body)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	middleware, err := GatewayAssertionMiddleware(GatewayAssertionMiddlewareOptions{
		Verifier: verifier, MaxBodyBytes: 1024,
		AuthenticateOrigin: func(r *http.Request) bool { return r.Header.Get("X-Private-Origin") == "verified" },
	}, next)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, fixture.Request.Path+"?"+fixture.Request.RawQuery,
		strings.NewReader("opaque-encrypted-payload"))
	request.Header.Set("X-Lotor-Assertion", fixture.Assertion)
	request.Header.Set("Idempotency-Key", fixture.Request.IdempotencyKey)
	response := httptest.NewRecorder()
	middleware.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("direct request status=%d called=%v", response.Code, called)
	}

	request = httptest.NewRequest(http.MethodPost, fixture.Request.Path+"?"+fixture.Request.RawQuery,
		strings.NewReader("opaque-encrypted-payload"))
	request.Header.Set("X-Private-Origin", "verified")
	request.Header.Set("X-Lotor-Assertion", fixture.Assertion)
	request.Header.Set("Idempotency-Key", fixture.Request.IdempotencyKey)
	response = httptest.NewRecorder()
	middleware.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("gateway request status=%d called=%v body=%s", response.Code, called, response.Body.String())
	}
}

func TestGatewayAssertionReplayIneligibleFailsClosed(t *testing.T) {
	t.Parallel()
	fixture := loadGatewayGolden(t)
	claims := fixture.Claims
	claims.ReplayEligible = false
	claims.IdempotencyKeySHA256 = ""
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	body, _ := json.Marshal(claims)
	assertion := "v1." + base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body))
	request := goldenRequest(t, fixture)
	request.IdempotencyKey = ""
	store := &testReplayStore{}
	verifier := goldenVerifier(t, fixture, store)
	if _, err := verifier.Verify(context.Background(), assertion, request); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), assertion, request); !errors.Is(err, ErrGatewayAssertionRejected) {
		t.Fatalf("replay error = %v", err)
	}
	verifier = goldenVerifier(t, fixture, nil)
	if _, err := verifier.Verify(context.Background(), assertion, request); !errors.Is(err, ErrGatewayReplayUnavailable) {
		t.Fatalf("missing replay store error = %v", err)
	}
}

type testReplayStore struct{ consumed bool }

func (store *testReplayStore) Consume(context.Context, string, time.Time) (bool, error) {
	if store.consumed {
		return false, nil
	}
	store.consumed = true
	return true, nil
}

func loadGatewayGolden(t *testing.T) gatewayGolden {
	t.Helper()
	contents, err := os.ReadFile("testdata/gateway_assertion_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture gatewayGolden
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func goldenVerifier(t *testing.T, fixture gatewayGolden, replay GatewayAssertionReplayStore) *GatewayAssertionVerifier {
	t.Helper()
	return verifierForGolden(t, fixture, goldenAuthority(fixture.Claims), fixture.Now, replay)
}

func verifierForGolden(
	t *testing.T,
	fixture gatewayGolden,
	authority GatewayAssertionAuthority,
	now int64,
	replay GatewayAssertionReplayStore,
) *GatewayAssertionVerifier {
	t.Helper()
	verifier, err := NewGatewayAssertionVerifier(GatewayAssertionVerifierOptions{
		Keys:      map[string]ed25519.PublicKey{fixture.Claims.KeyID: decodeGatewayPublicKey(t, fixture.PublicKey)},
		Authority: authority, Replay: replay,
		Now: func() time.Time { return time.Unix(now, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func goldenAuthority(claims GatewayAssertionClaims) GatewayAssertionAuthority {
	return GatewayAssertionAuthority{
		Issuer: claims.Issuer, Audience: claims.Audience, TenantID: claims.TenantID,
		ApplicationID: claims.ApplicationID, EnvironmentID: claims.EnvironmentID, BindingID: claims.BindingID,
		RouteID: claims.RouteID, RoutePin: claims.RoutePin, GatewayPlacementID: claims.GatewayPlacementID,
		RuntimePlacementID: claims.RuntimePlacementID, Operation: claims.Operation,
		GatewayOwnershipEpoch: claims.GatewayOwnershipEpoch, RuntimeOwnershipEpoch: claims.RuntimeOwnershipEpoch,
		ConfigurationVersion: claims.ConfigurationVersion, BindingActivationEpoch: claims.BindingActivationEpoch,
	}
}

func goldenRequest(t *testing.T, fixture gatewayGolden) GatewayAssertionRequest {
	t.Helper()
	body, err := base64.RawURLEncoding.DecodeString(fixture.Request.Body)
	if err != nil {
		t.Fatal(err)
	}
	return GatewayAssertionRequest{
		Method: fixture.Request.Method, Path: fixture.Request.Path, RawQuery: fixture.Request.RawQuery,
		IdempotencyKey: fixture.Request.IdempotencyKey, Body: body,
	}
}

func decodeGatewayPublicKey(t *testing.T, encoded string) ed25519.PublicKey {
	t.Helper()
	publicKey, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(publicKey)
}
