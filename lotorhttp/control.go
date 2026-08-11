package lotorhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

type controlIdentityVerifier struct {
	client  *http.Client
	baseURL string
}

var errIdentityRejected = errors.New("application session rejected")

type controlSession struct {
	Subject string          `json:"subject"`
	Email   string          `json:"email"`
	Account json.RawMessage `json:"account"`
}

type controlScope struct {
	TenantID      string `json:"tenant_id"`
	ApplicationID string `json:"application_id"`
	EnvironmentID string `json:"environment_id"`
}

func newControlIdentityVerifier(rawURL string) (*controlIdentityVerifier, error) {
	baseURL, err := validatedControlURL(rawURL)
	if err != nil {
		return nil, err
	}
	return &controlIdentityVerifier{baseURL: baseURL, client: &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (v *controlIdentityVerifier) Verify(ctx context.Context, bearer string) (Identity, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.baseURL+"/v1/me", nil)
	if err != nil {
		return Identity{}, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+bearer)
	response, err := v.client.Do(request)
	if err != nil {
		return Identity{}, fmt.Errorf("verify application session: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return Identity{}, errIdentityRejected
		}
		return Identity{}, errors.New("application session verification unavailable")
	}
	var session controlSession
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if readErr != nil || len(raw) > 64<<10 || json.Unmarshal(raw, &session) != nil {
		return Identity{}, errors.New("invalid application session")
	}
	var scope controlScope
	if err = json.Unmarshal(session.Account, &scope); err != nil {
		return Identity{}, errors.New("invalid application session scope")
	}
	email := strings.ToLower(strings.TrimSpace(session.Email))
	parsed, emailErr := mail.ParseAddress(email)
	identity := Identity{
		Subject: strings.TrimSpace(session.Subject), Email: email,
		TenantID: strings.TrimSpace(scope.TenantID), ApplicationID: strings.TrimSpace(scope.ApplicationID),
		EnvironmentID: strings.TrimSpace(scope.EnvironmentID),
	}
	if !bounded(identity.Subject, 256) || emailErr != nil || parsed.Address != email ||
		identity.TenantID == "" || identity.ApplicationID == "" || identity.EnvironmentID == "" {
		return Identity{}, errors.New("invalid application session")
	}
	return identity, nil
}

func validatedControlURL(rawURL string) (string, error) {
	rawURL = strings.TrimRight(strings.TrimSpace(rawURL), "/")
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", errors.New("invalid Control URL")
	}
	if parsed.Scheme == "http" && !loopback(parsed.Hostname()) {
		return "", errors.New("Control URL must use HTTPS outside local development")
	}
	return rawURL, nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
