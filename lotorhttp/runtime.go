package lotorhttp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/2kims/lotor-go/lotor"
)

var (
	errIdempotencyConflict = errors.New("idempotency conflict")
	errScopeMismatch       = errors.New("application session scope mismatch")
)

type ownedRuntime struct {
	resolver *lotor.OwnershipResolver
	tls      *tls.Config
}

func newOwnedRuntime(controlURL, apiKey string, tlsConfig *tls.Config) (*ownedRuntime, error) {
	resolver, err := lotor.NewOwnershipResolver(lotor.DiscoveryOptions{ControlURL: controlURL, APIKey: apiKey})
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		tlsConfig = tlsConfig.Clone()
	}
	return &ownedRuntime{resolver: resolver, tls: tlsConfig}, nil
}

func (r *ownedRuntime) Accept(ctx context.Context, identity Identity, ticket, key string) (lifecycleResult, error) {
	if err := r.verifyScope(ctx, identity); err != nil {
		return lifecycleResult{}, err
	}
	result, err := lotor.WithOwnerRetry(ctx, r.resolver, r.tls, func(client *lotor.Client) (lotor.LifecycleResult, error) {
		return client.InvitationAccept(ticket, emailAddress(identity.Email), identity.Subject, key)
	})
	return publicLifecycle(result, err)
}

func (r *ownedRuntime) Cancel(ctx context.Context, identity Identity, organization, invitationID, key string) (lifecycleResult, error) {
	if err := r.verifyScope(ctx, identity); err != nil {
		return lifecycleResult{}, err
	}
	result, err := lotor.WithOwnerRetry(ctx, r.resolver, r.tls, func(client *lotor.Client) (lotor.LifecycleResult, error) {
		return client.InvitationCancel(organization, identity.Subject, invitationID, key)
	})
	return publicLifecycle(result, err)
}

func (r *ownedRuntime) verifyScope(ctx context.Context, identity Identity) error {
	owner, err := r.resolver.Resolve(ctx)
	if err != nil {
		return err
	}
	if owner.TenantID != identity.TenantID || owner.ApplicationID != identity.ApplicationID || owner.EnvironmentID != identity.EnvironmentID {
		return errScopeMismatch
	}
	return nil
}

func publicLifecycle(result lotor.LifecycleResult, err error) (lifecycleResult, error) {
	if err != nil {
		if lotor.IsLWPError(err, lotor.ErrorCodeIdempotencyConflict) {
			return lifecycleResult{}, errIdempotencyConflict
		}
		return lifecycleResult{}, err
	}
	return lifecycleResult{
		Succeeded: result.Accepted, Reason: result.Reason, InvitationID: result.InvitationID,
		Active: result.Active, Reserved: result.Reserved, Used: result.Used,
		Maximum: result.Maximum, Remaining: result.Remaining,
	}, nil
}

func deriveKey(command, subject, callerKey string) string {
	sum := sha256.Sum256([]byte("lotor-browser:" + command + "\x00" + subject + "\x00" + strings.TrimSpace(callerKey)))
	return "lotor-browser-v1:" + hex.EncodeToString(sum[:])
}

func emailAddress(email string) string {
	return "email:" + base64.RawURLEncoding.EncodeToString([]byte(strings.ToLower(strings.TrimSpace(email))))
}
