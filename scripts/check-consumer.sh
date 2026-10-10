#!/usr/bin/env bash
set -euo pipefail

version="${1:-local}"
module="github.com/2kims/lotor-go"
sdk_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
consumer="$(mktemp -d)"
trap 'rm -rf "$consumer"' EXIT

cd "$consumer"
go mod init example.test/lotor-go-consumer >/dev/null
if [[ "$version" == "local" ]]; then
  go mod edit -require="$module@v0.0.0"
  go mod edit -replace="$module=$sdk_root"
else
  if [[ ! "$version" =~ ^v0\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$ ]]; then
    echo "version must be local or an exact v0 SemVer" >&2
    exit 1
  fi
  go get "$module@$version"
fi

mkdir -p consumer
cat > consumer/consumer.go <<'EOF'
package consumer

import (
	"context"
	"crypto/ed25519"
	"net/http"

	"github.com/2kims/lotor-go/lotor"
	"github.com/2kims/lotor-go/lotorhttp"
	"github.com/2kims/lotor-go/lotorhttp/browseradapter"
)

// Compile the complete Avault-facing Control surface, not only the legacy LWP client.
type ControlGraph interface {
	ForUser(string) (*lotorhttp.ControlClient, error)
	Resource(context.Context, string) (lotorhttp.Resource, error)
	PutResource(context.Context, string, lotorhttp.ResourceRegistration) (lotorhttp.Resource, error)
	CreateSystemResource(context.Context, lotorhttp.ResourceRegistration, string) (lotorhttp.DurableOperation, error)
	MoveResource(context.Context, string, string, lotorhttp.ResourceLifecycleFence, string) (lotorhttp.DurableOperation, error)
	DisableResource(context.Context, string, lotorhttp.ResourceLifecycleFence, string) (lotorhttp.DurableOperation, error)
	RestoreResource(context.Context, string, lotorhttp.ResourceLifecycleFence, string) (lotorhttp.DurableOperation, error)
	DeleteResource(context.Context, string, lotorhttp.ResourceLifecycleFence, bool, string) (lotorhttp.DurableOperation, error)
	Operation(context.Context, string) (lotorhttp.DurableOperation, error)
	WaitForOperation(context.Context, string, lotorhttp.OperationWaitOptions) (lotorhttp.DurableOperation, error)
	AccountResources(context.Context, lotorhttp.AccountResourceListOptions) (lotorhttp.AccountResourceList, error)
	AccountInvitations(context.Context, string, int) (lotorhttp.AccountInvitationList, error)
	AcceptAccountInvitation(context.Context, string) (lotorhttp.AccountInvitationMutation, error)
	DeclineAccountInvitation(context.Context, string) (lotorhttp.AccountInvitationMutation, error)
	CreatePortalSession(context.Context, lotorhttp.PortalSessionInput) (lotorhttp.PortalSession, error)
	CreateSCIMDirectory(context.Context, string, lotorhttp.SCIMDirectoryCreateInput, string) (lotorhttp.SCIMDirectory, error)
	SCIMDirectory(context.Context, string, string) (lotorhttp.SCIMDirectory, error)
	SCIMDirectories(context.Context, string, string, int) (lotorhttp.SCIMDirectoryList, error)
	UpdateSCIMDirectory(context.Context, string, string, lotorhttp.SCIMDirectoryUpdateInput, string) (lotorhttp.SCIMDirectory, error)
	CreateOrganizationFunctionBinding(context.Context, string) (lotorhttp.OrganizationFunctionBindingBootstrap, error)
	ListOrganizationFunctionBindings(context.Context, string) ([]lotorhttp.OrganizationFunctionBindingStatus, error)
	GetOrganizationFunctionBinding(context.Context, string, string) (lotorhttp.OrganizationFunctionBindingStatus, error)
	StartOrganizationFunctionBindingChallenge(context.Context, string, string) (lotorhttp.OrganizationFunctionBindingChallengeStatus, error)
	RevokeOrganizationFunctionBinding(context.Context, string, string) error
	ResourcePayload(context.Context, string, string) (lotorhttp.ResourcePayloadManifest, error)
	AccessResourcePayload(context.Context, string, string, int64) (lotorhttp.ResourcePayloadAccessLease, error)
	DownloadResourcePayload(context.Context, lotorhttp.ResourcePayloadAccessLease) ([]byte, error)
	BeginResourcePayloadUpload(context.Context, string, string, lotorhttp.ResourcePayloadUploadInput) (lotorhttp.ResourcePayloadUploadIntent, error)
	UploadResourcePayloadObject(context.Context, lotorhttp.ResourcePayloadUploadIntent, []byte) error
	CommitResourcePayload(context.Context, string, string, lotorhttp.ResourcePayloadUploadIntent) (lotorhttp.ResourcePayloadManifest, error)
	RewrapResourcePayload(context.Context, string, string, lotorhttp.ResourcePayloadRewrapInput) (lotorhttp.ResourcePayloadRewrapResult, error)
	DeleteResourcePayload(context.Context, string, string, string) (lotorhttp.ResourcePayloadMutation, error)
	IssueResourceCredential(context.Context, string, lotorhttp.ResourceCredentialIssueInput, string) (lotorhttp.IssuedResourceCredential, error)
	ResourceCredentials(context.Context, string) ([]lotorhttp.ResourceCredentialMetadata, error)
	RotateResourceCredential(context.Context, string, string, lotorhttp.ResourceCredentialRotateInput, string) (lotorhttp.IssuedResourceCredential, error)
	RevokeResourceCredential(context.Context, string, string, string) (lotorhttp.ResourceCredentialMetadata, error)
	SearchResourceLinkCandidates(context.Context, string, lotorhttp.ResourceLinkCandidateSearchInput) (lotorhttp.ResourceLinkCandidateSearchResult, error)
	PreflightResourceLinks(context.Context, string, []lotorhttp.ResourceLinkChange) (lotorhttp.ResourceLinkPreflight, error)
	CommitResourceLinks(context.Context, string, lotorhttp.ResourceLinkPreflight, []lotorhttp.ResourceLinkEnvelopeSubmission) (lotorhttp.ResourceLinkResult, error)
	SendResourceLinks(context.Context, string, lotorhttp.ResourceLinkSendInput) (lotorhttp.ResourceLinkSendResult, error)
	UnlinkResource(context.Context, string, string, string) (lotorhttp.UnlinkResult, error)
	ResourceCollaborators(context.Context, string, lotorhttp.ResourceCollaboratorListOptions) (lotorhttp.ResourceCollaboratorList, error)
	CheckResourceSubjectAccess(context.Context, string, string) (lotorhttp.ResourceSubjectAccessCheck, error)
	SearchResources(context.Context, lotorhttp.ResourceSearchInput) (lotorhttp.ResourceSearchList, error)
	OrganizationE2EEPolicy(context.Context, string) (lotorhttp.OrganizationE2EEPolicy, error)
	ConfigureOrganizationE2EE(context.Context, string, lotorhttp.OrganizationE2EEPolicyInput) (lotorhttp.OrganizationE2EEPolicy, error)
	SetResourceCollaborationPolicy(context.Context, string, lotorhttp.ResourceCollaborationPolicyOverride) (lotorhttp.ResourceCollaborationPolicyMutation, error)
	PutResourceType(context.Context, string, lotorhttp.ResourceTypeDefinition) (lotorhttp.ResourceTypeDefinition, error)
	CreateCatalog(context.Context, lotorhttp.CatalogCreation, string) (lotorhttp.Catalog, error)
	Catalog(context.Context, string) (lotorhttp.Catalog, error)
	Catalogs(context.Context, string, int) (lotorhttp.CatalogList, error)
	ImportOpenAPI(context.Context, string, lotorhttp.CatalogImportInput, string) (lotorhttp.DurableOperation, error)
	ImportDefinitions(context.Context, string, []lotorhttp.GenericCatalogDefinition, string) (lotorhttp.DurableOperation, error)
	CatalogSnapshots(context.Context, string, string, int) (lotorhttp.CatalogSnapshotList, error)
	PublishCatalogSnapshot(context.Context, string, string, string) (lotorhttp.DurableOperation, error)
	CatalogEntries(context.Context, string, string, int) (lotorhttp.CatalogEntryList, error)
	CatalogEntry(context.Context, string, string) (lotorhttp.CatalogEntry, error)
	AvailableCatalogs(context.Context, string, int) (lotorhttp.CatalogList, error)
	AvailableCatalogEntries(context.Context, string, string, int) (lotorhttp.PublishedCatalogEntryList, error)
	BindResourceCatalog(context.Context, string, lotorhttp.ResourceCatalogBindingInput, string) (lotorhttp.DurableOperation, error)
	ResourceCatalogEntries(context.Context, string, string, string, int) (lotorhttp.CatalogEntryList, error)
	ResourceCatalogEntry(context.Context, string, string, string) (lotorhttp.CatalogEntry, error)
}

var _ ControlGraph = (*lotorhttp.ControlClient)(nil)

func BrowserAdapter(config browseradapter.Config) (http.Handler, error) {
	return browseradapter.New(config)
}

type sessions struct{}

func (sessions) Bearer(context.Context, string) (string, error) { return "opaque", nil }
func (sessions) Delete(context.Context, string) error           { return nil }

func Surface(ctx context.Context, resolver *lotor.OwnershipResolver) error {
	_, err := lotor.WithOwnerRetry(ctx, resolver, nil, func(client *lotor.Client) (lotor.Decision, error) {
		return client.AccessCheck("user:1", "view", "document:1")
	})
	return err
}

func Gateway() (http.Handler, error) {
	return lotorhttp.New(lotorhttp.Options{
		ControlURL: "https://control.example.test",
		APIKey: "test_api_key",
		CookieName: "application_session",
		Sessions: sessions{},
	})
}

func ResourceState(resource lotorhttp.Resource) (string, lotorhttp.ResourceEncryption, *lotorhttp.ResourceCatalogBinding) {
	return resource.PrincipalSubject, resource.Encryption, resource.CatalogBinding
}

func ProtectedOrigin() (http.Handler, error) {
	verifier, err := lotorhttp.NewGatewayAssertionVerifier(lotorhttp.GatewayAssertionVerifierOptions{
		Keys: map[string]ed25519.PublicKey{"gateway-key": make(ed25519.PublicKey, ed25519.PublicKeySize)},
		Authority: lotorhttp.GatewayAssertionAuthority{
			Issuer: "owner/placement", Audience: "https://api.example.test",
			TenantID: "tenant", ApplicationID: "application", EnvironmentID: "environment",
			BindingID: "binding", RouteID: "api",
			RoutePin: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			GatewayPlacementID: "gateway", RuntimePlacementID: "runtime",
			GatewayOwnershipEpoch: 1, RuntimeOwnershipEpoch: 1,
			ConfigurationVersion: 1, BindingActivationEpoch: 1,
		},
	})
	if err != nil { return nil, err }
	return lotorhttp.GatewayAssertionMiddleware(lotorhttp.GatewayAssertionMiddlewareOptions{
		Verifier: verifier, AuthenticateOrigin: lotorhttp.VerifiedClientCertificateOrigin,
		MaxBodyBytes: 1 << 20,
	}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
}
EOF

go mod tidy
go test ./...
go vet ./...
echo "clean consumer passed for $module@$version"
