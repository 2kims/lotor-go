// Package lotorhttp exposes browser-safe, same-origin HTTP adapters for Lotor-owned commands.
// It keeps Control application bearers and runtime credentials outside browser JavaScript.
package lotorhttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const maxRequestBody = 16 << 10

// ErrNoSession indicates that an opaque application session is absent or expired.
var ErrNoSession = errors.New("application session not found")

// SessionStore resolves the opaque application cookie to the Control bearer held by the BFF.
type SessionStore interface {
	Bearer(context.Context, string) (string, error)
	Delete(context.Context, string) error
}

// Identity is verified from Control for every lifecycle command.
type Identity struct {
	Subject       string
	Email         string
	TenantID      string
	ApplicationID string
	EnvironmentID string
}

type identityVerifier interface {
	Verify(context.Context, string) (Identity, error)
}

type lifecycleRuntime interface {
	Accept(context.Context, Identity, string, string) (lifecycleResult, error)
	Cancel(context.Context, Identity, string, string, string) (lifecycleResult, error)
}

type lifecycleResult struct {
	Reason       string
	InvitationID string
	Active       int64
	Reserved     int64
	Used         int64
	Maximum      int64
	Remaining    int64
	Succeeded    bool
}

// Options configures the reusable browser command gateway.
type Options struct {
	TLSConfig  *tls.Config
	Sessions   SessionStore
	ControlURL string
	APIKey     string
	CookieName string
}

type Handler struct {
	sessions   SessionStore
	identity   identityVerifier
	runtime    lifecycleRuntime
	cookieName string
}

// New constructs a production gateway backed by Control identity verification and owned LWP.
func New(options Options) (*Handler, error) {
	if strings.TrimSpace(options.CookieName) == "" || options.Sessions == nil {
		return nil, errors.New("cookie name and session store are required")
	}
	identity, err := newControlIdentityVerifier(options.ControlURL)
	if err != nil {
		return nil, err
	}
	runtime, err := newOwnedRuntime(options.ControlURL, options.APIKey, options.TLSConfig)
	if err != nil {
		return nil, err
	}
	return newHandler(options.CookieName, options.Sessions, identity, runtime), nil
}

func newHandler(cookieName string, sessions SessionStore, identity identityVerifier, runtime lifecycleRuntime) *Handler {
	return &Handler{cookieName: cookieName, sessions: sessions, identity: identity, runtime: runtime}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !browserMutation(r) {
		writeError(w, http.StatusForbidden, "request_rejected")
		return
	}
	switch r.URL.Path {
	case "/api/lotor/invitations/accept":
		h.accept(w, r)
	case "/api/lotor/invitations/cancel":
		h.cancel(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found")
	}
}

func (h *Handler) accept(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Organization   string `json:"organization"`
		Ticket         string `json:"ticket"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if (input.Organization != "" && !organization(input.Organization)) || !bounded(input.Ticket, 512) || !bounded(input.IdempotencyKey, 256) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	identity, sessionID, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	result, err := h.runtime.Accept(r.Context(), identity, strings.TrimSpace(input.Ticket), deriveKey("accept-v1", identity.Subject, input.IdempotencyKey))
	h.respondLifecycle(w, r, sessionID, result, err)
}

func (h *Handler) cancel(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Organization   string `json:"organization"`
		InvitationID   string `json:"invitation_id"`
		IdempotencyKey string `json:"idempotency_key"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !organization(input.Organization) || !bounded(input.InvitationID, 256) || !bounded(input.IdempotencyKey, 256) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	identity, sessionID, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	result, err := h.runtime.Cancel(r.Context(), identity, strings.TrimSpace(input.Organization), strings.TrimSpace(input.InvitationID), deriveKey("cancel-v1", identity.Subject, input.IdempotencyKey))
	h.respondLifecycle(w, r, sessionID, result, err)
}

func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request) (Identity, string, bool) {
	sessionID := ""
	if authorization := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(authorization, "Bearer ") {
		sessionID = strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	} else if cookie, err := r.Cookie(h.cookieName); err == nil {
		sessionID = cookie.Value
	}
	if !bounded(sessionID, 512) {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return Identity{}, "", false
	}
	token, err := h.sessions.Bearer(r.Context(), sessionID)
	if err != nil || strings.TrimSpace(token) == "" {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return Identity{}, "", false
	}
	identity, err := h.identity.Verify(r.Context(), token)
	if err != nil {
		if errors.Is(err, errIdentityRejected) {
			_ = h.sessions.Delete(r.Context(), sessionID)
			writeError(w, http.StatusUnauthorized, "unauthenticated")
		} else {
			writeError(w, http.StatusServiceUnavailable, "identity_unavailable")
		}
		return Identity{}, "", false
	}
	return identity, sessionID, true
}

func (h *Handler) respondLifecycle(w http.ResponseWriter, r *http.Request, sessionID string, result lifecycleResult, err error) {
	if err != nil {
		if errors.Is(err, errIdempotencyConflict) {
			writeError(w, http.StatusConflict, "idempotency_conflict")
			return
		}
		if errors.Is(err, errScopeMismatch) {
			_ = h.sessions.Delete(r.Context(), sessionID)
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		writeError(w, http.StatusServiceUnavailable, "runtime_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"succeeded":     result.Succeeded,
		"reason":        result.Reason,
		"invitation_id": result.InvitationID,
		"capacity": map[string]int64{
			"active": result.Active, "reserved": result.Reserved, "used": result.Used,
			"maximum": result.Maximum, "remaining": result.Remaining,
		},
	})
}

func browserMutation(r *http.Request) bool {
	if r.Header.Get("X-Lotor-Request") != "browser-sdk-v1" {
		return false
	}
	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site != "" && site != "same-origin" {
		return false
	}
	if rawOrigin := strings.TrimSpace(r.Header.Get("Origin")); rawOrigin != "" {
		origin, err := url.Parse(rawOrigin)
		if err != nil || origin.User != nil || !strings.EqualFold(origin.Host, r.Host) {
			return false
		}
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func bounded(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= maximum
}

func organization(value string) bool {
	value = strings.TrimSpace(value)
	if !bounded(value, 256) {
		return false
	}
	for _, prefix := range []string{"personal-", "workspace-", "org_"} {
		if suffix, found := strings.CutPrefix(value, prefix); found {
			return organizationSuffix(suffix)
		}
	}
	return organizationUUID(value)
}

func organizationSuffix(value string) bool {
	if value == "" || len(value) > 240 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func organizationUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F') ||
			(character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}
