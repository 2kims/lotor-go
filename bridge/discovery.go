package bridge

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ControlDiscoveryOptions struct {
	HTTPClient *http.Client
	BaseURL    string
}

type ControlKeys struct {
	Keys   map[string]ed25519.PublicKey
	Issuer string
}

// DiscoverControlKeys bootstraps trust from the explicitly configured HTTPS
// Control origin, not a function URL or an unverified grant's issuer field.
// The caller chooses when to refresh keys; there is no alternate-origin fallback.
func DiscoverControlKeys(ctx context.Context, options ControlDiscoveryOptions) (ControlKeys, error) {
	base, err := controlBaseURL(options.BaseURL)
	if err != nil {
		return ControlKeys{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/lotor-function-keys.json", nil)
	if err != nil {
		return ControlKeys{}, ErrInvalid
	}
	request.Header.Set("Accept", "application/json")
	response, err := isolatedControlClient(options.HTTPClient).Do(request)
	if err != nil {
		return ControlKeys{}, ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ControlKeys{}, ErrUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		return ControlKeys{}, ErrUnavailable
	}
	var document struct {
		Issuer string `json:"issuer"`
		Keys   []struct {
			KeyID     string `json:"key_id"`
			Algorithm string `json:"algorithm"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if strictJSON(body, &document) != nil || !identifier(document.Issuer, 256) || len(document.Keys) < 1 || len(document.Keys) > 8 {
		return ControlKeys{}, ErrUnavailable
	}
	keys := make(map[string]ed25519.PublicKey, len(document.Keys))
	for _, value := range document.Keys {
		if !identifier(value.KeyID, 256) || value.Algorithm != "Ed25519" || keys[value.KeyID] != nil {
			return ControlKeys{}, ErrUnavailable
		}
		public, err := base64.RawURLEncoding.Strict().DecodeString(value.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return ControlKeys{}, ErrUnavailable
		}
		keys[value.KeyID] = ed25519.PublicKey(public)
	}
	return ControlKeys{Issuer: document.Issuer, Keys: keys}, nil
}

func controlBaseURL(raw string) (string, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || strings.Contains(raw, "#") {
		return "", ErrInvalid
	}
	return strings.TrimRight(endpoint.String(), "/"), nil
}

func isolatedControlClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	isolated := *client
	isolated.Jar = nil
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &isolated
}
