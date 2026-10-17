package bridge

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"
)

type Handler func(context.Context, Authorization) (json.RawMessage, error)

type (
	invocationContextKey struct{}
	invocationState      struct {
		signed        SignedMessage
		authorization Authorization
	}
)

// InvocationFromContext returns the verified invocation associated with this
// authorization callback or handler call, after signature/static scope checks.
// Fresh Control validation is still required. It is never populated for
// ownership challenges. Do not log the signed grant.
func InvocationFromContext(ctx context.Context) (Authorization, SignedMessage, bool) {
	state, ok := ctx.Value(invocationContextKey{}).(invocationState)
	return state.authorization, state.signed, ok
}

type Registration struct {
	Handler  Handler
	Function Function
}

// ExecutionStore is a durable, atomic deployment dependency. Reserve must bind
// an ID to exactly one digest and return ErrConflict for changed input. For an
// existing incomplete reservation return ErrInProgress, never permission to run
// again. Complete must persist the result atomically for restart-safe replay.
// A nil result and nil error from Reserve means this caller owns a new reservation.
type ExecutionStore interface {
	Reserve(context.Context, string, string) (*Result, error)
	Complete(context.Context, string, string, Result) error
}

type Config struct {
	Store       ExecutionStore
	Now         func() time.Time
	TrustedKeys map[string]ed25519.PublicKey
	// Authorize checks current binding/revocation and deployment policy. It is
	// mandatory even though signatures and static scope are checked by the SDK.
	Authorize        func(context.Context, Authorization, SignedMessage) error
	Scope            Scope
	Audience         string
	BindingID        string
	SigningKeyID     string
	Issuer           string
	SigningKey       ed25519.PrivateKey
	Functions        []Registration
	BindingRevision  int64
	ExecutionTimeout time.Duration
}

type Runtime struct {
	functions      map[Function]Handler
	manifestDigest string
	config         Config
}

func NewRuntime(config Config) (*Runtime, error) {
	if !identifier(config.Issuer, 256) || !identifier(config.Audience, 256) || !identifier(config.BindingID, 256) || config.BindingRevision < 1 || !validScope(config.Scope) || !identifier(config.SigningKeyID, 256) || len(config.SigningKey) != ed25519.PrivateKeySize || len(config.TrustedKeys) == 0 || config.Store == nil || config.Authorize == nil {
		return nil, ErrInvalid
	}
	config.SigningKey = append(ed25519.PrivateKey(nil), config.SigningKey...)
	keys := make(map[string]ed25519.PublicKey, len(config.TrustedKeys))
	for id, key := range config.TrustedKeys {
		if !identifier(id, 256) || len(key) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	config.TrustedKeys = keys
	manifest := Manifest{ProtocolVersion: ProtocolVersion}
	functions := make(map[Function]Handler)
	for _, registration := range config.Functions {
		if registration.Handler == nil {
			return nil, ErrInvalid
		}
		manifest.Functions = append(manifest.Functions, registration.Function)
		functions[registration.Function] = registration.Handler
	}
	digest, err := ManifestDigest(manifest)
	if err != nil {
		return nil, err
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.ExecutionTimeout == 0 {
		config.ExecutionTimeout = 30 * time.Second
	}
	if config.ExecutionTimeout < 0 || config.ExecutionTimeout > 5*time.Minute {
		return nil, ErrInvalid
	}
	return &Runtime{config: config, manifestDigest: digest, functions: functions}, nil
}

// ServeHTTP is the canonical adapter; Lambda uses the same handler. TLS/mTLS
// listener configuration belongs to the deployment, not request headers.
func (runtime *Runtime) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if request.URL.Path != "/v1/functions/challenge" && request.URL.Path != "/v1/functions/invoke" {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || request.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	limit := int64(MaximumBodyBytes)
	if request.URL.Path == "/v1/functions/challenge" {
		limit = 64 << 10
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, limit))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	var message SignedMessage
	if strictJSON(body, &message) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	key, ok := runtime.config.TrustedKeys[message.KeyID]
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	authorization, raw, err := VerifyAuthorization(message, key)
	if err != nil || !runtime.validAuthorization(authorization, request.URL.Path) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	grantContext, stopGrant := context.WithDeadline(request.Context(), time.Unix(authorization.ExpiresAt, 0))
	defer stopGrant()
	if authorization.Kind == "invocation" {
		// Custody/policy checks must resolve original workload identity before
		// either reserving an execution or returning a cached result. Resource
		// methods independently revalidate the original grant with Control.
		grantContext = context.WithValue(grantContext, invocationContextKey{}, invocationState{authorization: authorization, signed: message})
	}
	if err = runtime.config.Authorize(grantContext, authorization, message); err != nil {
		if errors.Is(err, ErrUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "authorization_unavailable")
		} else {
			writeError(w, http.StatusUnauthorized, "unauthorized")
		}
		return
	}
	if !runtime.grantActive(grantContext, authorization) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	result := Result{ProtocolVersion: ProtocolVersion, ID: authorization.ID, Kind: authorization.Kind, BindingID: authorization.BindingID, BindingRevision: authorization.BindingRevision, ManifestDigest: authorization.ManifestDigest, AuthorizationDigest: Digest(raw), CompletedAt: runtime.config.Now().Unix()}
	if authorization.Kind == "challenge" {
		result.Nonce = authorization.Nonce
	} else {
		semantic := authorization
		semantic.IssuedAt, semantic.ExpiresAt = 0, 0
		semanticJSON, marshalErr := json.Marshal(semantic)
		if marshalErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		identity := runtime.config.BindingID + ":" + authorization.ID
		digest := Digest(semanticJSON)
		stored, reserveErr := runtime.config.Store.Reserve(grantContext, identity, digest)
		// Dependencies can finish after their deadline, even when they honor
		// cancellation. Never enter application code or replay a cached result
		// with expired authority. An ambiguous reservation remains non-reexecutable.
		if !runtime.grantActive(grantContext, authorization) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if errors.Is(reserveErr, ErrInProgress) || errors.Is(reserveErr, ErrConflict) {
			writeError(w, http.StatusConflict, "operation_conflict")
			return
		}
		if reserveErr != nil {
			writeError(w, http.StatusServiceUnavailable, "storage_unavailable")
			return
		}
		if stored != nil {
			result = *stored
			result.AuthorizationDigest = Digest(raw)
		} else {
			deadline := time.Unix(authorization.ExpiresAt, 0)
			if bound := runtime.config.Now().Add(runtime.config.ExecutionTimeout); bound.Before(deadline) {
				deadline = bound
			}
			ctx, cancel := context.WithDeadline(grantContext, deadline)
			output, executionErr := execute(ctx, runtime.functions[*authorization.Function], authorization)
			cancel()
			canonical, marshalErr := json.Marshal(output)
			if executionErr != nil || marshalErr != nil || !json.Valid(output) || len(output) > MaximumInputBytes || len(canonical) > MaximumInputBytes {
				result.ErrorCode = "outcome_unknown"
			} else {
				result.Output = canonical
			}
			result.CompletedAt = runtime.config.Now().Unix()
			// Attempt durable completion even when the client disconnected. A failed
			// completion leaves the reservation non-reexecutable, never abandoned.
			persist, stop := context.WithTimeout(context.WithoutCancel(request.Context()), 5*time.Second)
			err = runtime.config.Store.Complete(persist, identity, digest, result)
			stop()
			if err != nil {
				writeError(w, http.StatusServiceUnavailable, "outcome_unknown")
				return
			}
		}
	}
	signed, err := SignResult(result, runtime.config.SigningKeyID, runtime.config.SigningKey)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "result_unavailable")
		return
	}
	_ = json.NewEncoder(w).Encode(signed)
}

func (runtime *Runtime) grantActive(ctx context.Context, authorization Authorization) bool {
	return ctx.Err() == nil && runtime.config.Now().Unix() < authorization.ExpiresAt
}

func (runtime *Runtime) validAuthorization(value Authorization, path string) bool {
	now := runtime.config.Now().Unix()
	if value.ProtocolVersion != ProtocolVersion || !identifier(value.ID, 256) || value.Issuer != runtime.config.Issuer || value.Audience != runtime.config.Audience || value.BindingID != runtime.config.BindingID || value.BindingRevision != runtime.config.BindingRevision || value.ManifestDigest != runtime.manifestDigest || value.Scope != runtime.config.Scope || value.IssuedAt <= 0 || value.IssuedAt > now || value.ExpiresAt <= now || value.ExpiresAt <= value.IssuedAt || value.ExpiresAt-value.IssuedAt > 300 {
		return false
	}
	if path == "/v1/functions/challenge" {
		return value.Kind == "challenge" && identifier(value.Nonce, 256) && value.Function == nil && value.Principal == "" && len(value.Input) == 0 && value.InputDigest == "" && value.PolicyDigest == "" && len(value.Resources) == 0 && len(value.Capabilities) == 0
	}
	if value.Kind != "invocation" || value.Nonce != "" || value.Function == nil || !identifier(value.Principal, 256) || len(value.Input) == 0 || len(value.Input) > MaximumInputBytes || !json.Valid(value.Input) || value.InputDigest != Digest(value.Input) || value.PolicyDigest != "" && !isDigest(value.PolicyDigest) {
		return false
	}
	if _, ok := runtime.functions[*value.Function]; !ok {
		return false
	}
	if len(value.Resources) > 128 || len(value.Capabilities) > 64 {
		return false
	}
	for _, resource := range value.Resources {
		if !identifier(resource, 256) {
			return false
		}
	}
	for _, capability := range value.Capabilities {
		if !identifier(capability, 256) {
			return false
		}
	}
	return true
}

func validScope(scope Scope) bool {
	return identifier(scope.TenantID, 256) && identifier(scope.ApplicationID, 256) && identifier(scope.EnvironmentID, 256) && identifier(scope.OwnerResource, 256)
}

func execute(ctx context.Context, handler Handler, authorization Authorization) (output json.RawMessage, err error) {
	defer func() {
		if recover() != nil {
			output, err = nil, ErrUnavailable
		}
	}()
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	output, err = handler(ctx, authorization)
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return output, err
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code string `json:"code"`
	}{code})
}
