package bridge

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverControlKeysUsesConfiguredHTTPSAuthority(t *testing.T) {
	f := setup(t)
	public := f.issuer.Public().(ed25519.PublicKey)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/.well-known/lotor-function-keys.json" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Lotor-Secret-Key") != "" {
			t.Error("incorrect key discovery authority")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "lotor", "keys": []map[string]string{{"key_id": "issuer-key", "algorithm": "Ed25519", "public_key": base64.RawURLEncoding.EncodeToString(public)}}})
	}))
	defer server.Close()
	keys, err := DiscoverControlKeys(t.Context(), ControlDiscoveryOptions{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil || keys.Issuer != "lotor" || len(keys.Keys) != 1 || !keys.Keys["issuer-key"].Equal(public) {
		t.Fatalf("discovery failed: %v", err)
	}
}

func TestDiscoverControlKeysRejectsInvalidTrustMetadata(t *testing.T) {
	for name, body := range map[string]string{
		"empty issuer":       `{"issuer":"","keys":[]}`,
		"empty keys":         `{"issuer":"lotor","keys":[]}`,
		"wrong algorithm":    `{"issuer":"lotor","keys":[{"key_id":"one","algorithm":"none","public_key":"AA"}]}`,
		"duplicate keys":     `{"issuer":"lotor","keys":[{"key_id":"one","algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},{"key_id":"one","algorithm":"Ed25519","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`,
		"invalid public key": `{"issuer":"lotor","keys":[{"key_id":"one","algorithm":"Ed25519","public_key":"bad"}]}`,
		"trailing data":      `{"issuer":"lotor","keys":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			if _, err := DiscoverControlKeys(t.Context(), ControlDiscoveryOptions{BaseURL: server.URL, HTTPClient: server.Client()}); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("invalid metadata accepted: %v", err)
			}
		})
	}
}
