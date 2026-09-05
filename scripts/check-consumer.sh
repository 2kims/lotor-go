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
)

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
