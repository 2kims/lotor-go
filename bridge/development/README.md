# Development bridge connections

Sandbox-only outbound transport for the existing signed bridge protocol. This
package contains no Control server or provider business logic. It is optional:
normal external HTTPS and mTLS deployments are unchanged.

1. Use the normal delegated `lotorhttp.ControlClient` to call
   `CreateDevelopmentConnection(ctx, resource, idempotencyKey)`. Keep its stable
   connection ID and endpoint. Creating a connection requires current resource
   owner/admin authority in a sandbox environment.
2. Register your existing bridge signing public key and manifest at that endpoint
   through the normal function-binding API. Keep the returned binding ID. A
   pending binding may connect for its ownership challenge; invocation still
   requires successful ordinary verification.
3. Construct `NewProofSessionProvider(ProofSessionOptions{...})` using the exact
   scope, connection ID, binding ID and **existing bridge signing identity**.
   ControlURL is the public Control origin; EndpointURL is the returned stable
   connection endpoint. Never use a provider credential for this configuration.
4. Construct `NewConnector(ConnectorOptions{Session: provider, Handler: runtime})`
   with your existing signed `bridge.Runtime` HTTP handler. Run `connector.Run(ctx)`
   in your bridge process and cancel its context during shutdown.
5. Complete normal binding verification. Keep the existing durable execution
   store and journal; the connector is not an execution store or authority grant.

The connector renews dedicated five-minute admission using purpose-separated
proofs signed by the registered bridge key. It does not persist user cookies or
an application secret. Reconnect preserves URLs and signing identity but never
resends pending invocations. A disconnect after handoff is an uncertain outcome;
resolve it using the existing signed invocation ID and durable execution journal,
not a new provider request.

## Optional container

From this Go module directory:

```sh
docker build -f cmd/lotor-development-connector/Dockerfile -t lotor-development-connector:local .
```

The image contains only the connector and CA roots. Supply a private, read-only
configuration file at `/run/lotor/development.json`, readable by UID 65532 with
mode `0400` or `0600`. Do not bake it into the image, commit it, or pass private
keys in command-line arguments. Required JSON fields:

```json
{
  "control_url": "https://api.example.com",
  "endpoint_url": "https://api.example.com/t/dvc_example",
  "connection_id": "dvc_example",
  "binding_id": "YOUR_EXISTING_BINDING_ID",
  "signing_key_id": "YOUR_EXISTING_BRIDGE_KEY_ID",
  "signing_private_key": "BASE64URL_EXISTING_PRIVATE_SEED_OR_KEY",
  "scope": {
    "tenant_id": "YOUR_TENANT",
    "application_id": "YOUR_APPLICATION",
    "environment_id": "YOUR_SANDBOX_ENVIRONMENT",
    "owner_resource": "YOUR_RESOURCE"
  },
  "local_origin": "http://your-local-bridge:8080"
}
```

The fixed local origin must be reachable from the container. Publish no inbound
connector port. Only the two signed function routes are forwarded, without
browser cookies, bearer headers, application secrets, redirects, or arbitrary
caller-selected destinations. HTTP proxy environment settings are not used for
the local leg. TLS is per leg; this transport does not by itself claim E2EE.
