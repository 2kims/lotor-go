# lotor-go

`lotor-go` is the Go client for Lotor's LWP/1 data-plane protocol. It provides
the low-level `lotor` client and the optional `lotorhttp` same-origin invitation
gateway. The module has no third-party runtime dependencies and requires Go
1.24 or newer.

## Verified function runtime

The unreleased `bridge` package provides a generic Ed25519-signed ownership
challenge and function invocation handler. Customer functions remain application
code; the runtime has no provider-specific behavior. `bridge/lambda` adapts API
Gateway HTTP API payload version 2 events to the same handler without an AWS
dependency. A deployed HTTPS service or a local tunnel uses the same protocol.

Construct `bridge.NewRuntime` with explicit function registrations, trusted issuer
keys, the exact binding/scope/revision, a current-authorization callback and a
durable `ExecutionStore`. There is no production in-memory store. Reservations
must be atomic and survive restarts; incomplete effects must not automatically
rerun. Completed results can be replayed for the same semantic operation.

Registration returns `binding.Scope`, `binding.Audience` and `binding.Revision`
for runtime configuration. Fetch issuer/public keys from your explicitly
configured HTTPS Control URL using `bridge.DiscoverControlKeys`; do not infer the
trusted origin from an incoming grant or customer function URL. Discovery never
uses an application secret and does not follow redirects or forward cookie jars.

The optional `bridge/sqlstore` package implements `ExecutionStore` using
PostgreSQL through the host application's `database/sql` driver. Construct it with
the custody-local database and a stable namespace (normally the binding ID).
Call `Initialize` explicitly as a deployment migration, not on each Lambda call.
Recreating the runtime with the same database/namespace preserves reservations
and completed results. Incomplete reservations are never expired or stolen;
changing namespaces or deleting journal rows can repeat external effects.
The journal can contain customer result data and must stay within the selected
runtime's custody boundary. It is not a central plaintext copy in Lotor Control.

The runtime validates signatures, expiry, audience, scope, manifest/version and
input digest before calling application code. Verification challenges never call
function handlers. Handler errors and panic text are not exposed as protocol
errors. A timeout, invalid output or handler failure conservatively reports an
unknown outcome rather than claiming that an external effect did not occur.

TLS/mTLS, process isolation, secret custody and durable storage are deployment
responsibilities. Context deadlines require cooperative handlers; this library
is not an arbitrary-code sandbox.

Use `ControlClient.ForUser` with `RegisterFunctionBinding`, `FunctionBindings`,
`FunctionBinding`, `VerifyFunctionBinding` and `RevokeFunctionBinding` to manage
resource-owned HTTPS registrations. Registration takes an idempotency key and
public identity/manifest metadata, never private keys. Verification returns an
accepted binding; poll its challenge/status for the asynchronous outcome. All
management operations require resource-management authority. Revocation does not
delete custody keys or choose another provider. These methods are distinct from
the existing organization E2EE polling-relay methods below.

Use `AuthorizeFunctionInvocation` on the delegated server-side client to obtain a
30-second signed grant for an exact registered function, input and resource set.
Preserve its idempotency key across retries: Control rechecks permissions while
retaining the operation ID. Only the signed authorization goes to the customer
runtime; never forward the application secret or principal token. `resource.read`
and `payload.read` are currently supported; neither grants cryptographic custody.
The application adapter selects its function and authenticates its policy bundle.
Browser publishable credentials alone cannot issue these grants.

The grant response includes the verified runtime's public signing identity and
authentication mode, so an authorized caller does not need binding-management
rights to verify its result. Use `grant.NewClient(controlKeys, transport.Options{})`
and then `caller.Invoke(ctx, grant.Authorization)`. The invocation client checks
the Control signature and exact binding/scope/revision before dispatch, and the
runtime signature and exact invocation binding before returning a result. Reuse
the client while that binding revision remains current.

Control authorization responses are also checked against the requested binding,
function, input digest, resource list and capabilities. A valid grant for another
operation is not accepted as this request's response.

`bridge/transport` is the same safe HTTPS implementation used by Control, with
DNS pinning, private/metadata destination rejection, no redirects or environment
proxies, HTTP/2 pooling and required-mTLS enforcement. Normal deployment options
allow a trusted DNS resolver/socket dialer; these must never come from requests.
Its 30-second HTTP timeout is additionally bounded by the signed grant deadline.
There is no automatic retry or alternate runtime. A transport failure or invalid
result after dispatch returns `bridge.ErrOutcomeUnknown`; preserve the invocation
identity instead of creating a new operation that might repeat the provider call.

Use `bridge.NewControlValidator` with the configured HTTPS Control URL and the
runtime's registered signing key, then set `Config.Authorize = validator.Authorize`.
The callback receives the decoded grant and its original signed message after
the runtime's signature/static-scope checks. The validator wraps that exact grant
in a purpose-separated runtime signature; Control rechecks the original issuance,
current binding/resource permissions, and workload credential expiry/revocation.
The bridge needs no application secret. Validation is read-only and not a lease
against future revocation. Application-specific checks can wrap this callback.
Harmless ownership challenges stay on Control's separate one-use worker path.

For resource reads inside a handler, construct `bridge.NewResourceClient` with
the same runtime identity and use its `Authorize` method as `Config.Authorize`.
`AccessPayload(ctx, resource, slot, payloadVersion)` uses the verified invocation
from the handler context; it cannot run with a background context or access a
resource without `payload.read` in that invocation. `InvocationFromContext` also
exposes the verified grant to application-owned SDK integrations; do not log it.
Resource-access proofs use a different signature purpose from validation proofs.

Control rechecks permissions and the exact requested version, returning the
stored representation and an object-download lease no longer than the grant's
remaining lifetime. Download and verify the object with
`lotorhttp.DownloadResourcePayloadObject`; no caller credentials are attached.
Encrypted payloads remain encrypted. `payload.read` never authorizes key
unwrapping, E2EE provisioning or provider execution by itself.

Scoped cryptographic clients and end-to-end tunnel onboarding remain unfinished;
this is not yet a ready-to-use production integration.

## SCIM directory setup

Use `ControlClient.ForUser` with `CreateSCIMDirectory`, `SCIMDirectory`,
`SCIMDirectories` and `UpdateSCIMDirectory`. The delegated user must manage the organization; the SDK
rejects application-only use before sending a request. Creation takes existing
directory/credential resource references, resource revision/lifecycle fences and
an idempotency key. Listing takes an opaque cursor and a limit from 1 to 100.
Updating takes the desired enabled state, current configuration revision and an
idempotency key; enabling requires an issued credential for the API-key child.

These methods expose configuration metadata, not a credential or proof of
provisioning. Register resource types with application authority before creating
graph nodes. Inbound SCIM protocol handling remains under implementation.

## Organization encryption boxes

Use a `ControlClient.ForUser` client with `CreateOrganizationFunctionBinding`,
`ListOrganizationFunctionBindings`, `GetOrganizationFunctionBinding` and
`RevokeOrganizationFunctionBinding`. The delegated user must manage the
organization; application authority alone is rejected and denials are not retried.
The bootstrap credential is returned once and expires after 15 minutes. Discovery
returns zero or one secret-free current binding, so a lost creation response can
be recovered by discovery, revocation and restart—not by retrieving the secret.
Status timestamps are Unix microseconds. Registration is not box readiness.
Call `StartOrganizationFunctionBindingChallenge` after registration; it returns
without waiting for the box. Read the binding's `Challenge.Status` for verified
readiness. `ExpiresAt` is the pending completion deadline, not a ready-key lease.

## Connect through verified ownership

Production applications should discover the current runtime owner through
Control instead of hard-coding a `lotord` address:

```go
import (
    "context"
    "crypto/tls"
    "os"

    "github.com/2kims/lotor-go/lotor"
)

resolver, err := lotor.NewOwnershipResolver(lotor.DiscoveryOptions{
    ControlURL: os.Getenv("LOTOR_CONTROL_URL"),
    APIKey:     os.Getenv("LOTOR_API_KEY"),
})
if err != nil {
    return err
}

decision, err := lotor.WithOwnerRetry(
    context.Background(),
    resolver,
    nil, // system roots; pass a *tls.Config for a private CA or mTLS
    func(client *lotor.Client) (lotor.Decision, error) {
        return client.AccessCheck("user:42", "view", "document:99")
    },
)
```

The API key determines exactly one tenant, application, and environment. The
SDK retrieves Control's public runtime-signing keys, verifies the short-lived
ownership assertion, connects to that owner, and authenticates the LWP
connection with the same key. Canonical scope identifiers are outputs for
diagnostics; callers cannot use them to establish authority.

`WithOwnerRetry` follows at most one authenticated `MOVED` response. A mutating
callback must reuse the same idempotency key if it is retried. The helper opens
and closes a connection for the operation. For a warm connection, call
`DialOwned`, authenticate it, reuse it concurrently, watch `Done()`, and always
call `Close()` during shutdown.

## Direct connections and TLS

`Dial` opens plaintext LWP and `DialTLS` opens LWPS. Prefer `DialOwned` unless a
trusted deployment component already supplied the exact address.

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    ServerName: "runtime.example.com",
}
client, err := lotor.DialTLS(ctx, "runtime.example.com:7420", tlsConfig)
if err != nil {
    return err
}
defer client.Close()

if err := client.Auth(os.Getenv("LOTOR_API_KEY")); err != nil {
    return err
}
```

Dial and protocol requests currently use five-second bounds. The dialing
methods honor cancellation while connecting; application shutdown should call
`Close`, which terminates the socket and closes `Done()`. A `Client` pipelines
concurrent requests over one connection and correlates responses internally.
Do not call operations after closing the client.

## User-scoped HTTP resource directories

For HTTP resource directories on behalf of a signed-in user, derive a
`ControlClient` with `ForUser(accessToken)`, then call
`AccountResources(ctx, AccountResourceListOptions{Parent: "project:example",
Types: []string{"vault"}, Limit: 50})`. This uses `/me/resources`, not
management search. Pass `NextCursor` unchanged with the same filters to read
another page. Use the returned `Resource` reference for subsequent API calls;
do not reconstruct it from an internal identifier. A denied delegated request
is never retried with application authority.

## User invitation inbox

For a signed-in user's invitation inbox, use `ForUser` and
`AccountInvitations(ctx, cursor, limit)`, followed by `AcceptAccountInvitation`
or `DeclineAccountInvitation`. Acceptance may return `pending_encryption`;
do not treat that as encrypted-content readiness. Inbox references identify the
invited resource but do not grant access before acceptance. Responses never
require Avault to reconstruct canonical resource references.

## Durable resource operations

Resource creation and lifecycle mutations return a `DurableOperation`. Use
`WaitForOperation` when the caller must observe completion before reading the
affected resource:

```go
operation, err := client.WaitForOperation(ctx, operationID, lotorhttp.OperationWaitOptions{
    MaxAttempts: 120,
    Interval:    500 * time.Millisecond,
})
if err == nil && operation.Status != "succeeded" {
    // Handle the returned failed or cancelled operation explicitly.
}
```

The zero-value options use those same defaults. Polling is bounded, honors
context cancellation during requests and delays, and returns failed or
cancelled operations unchanged. It does not retry mutations or change caller
authority.

## Organization billing portal

Organization managers can open a billing portal through the HTTP client with
`userClient.CreatePortalSession(ctx, lotorhttp.PortalSessionInput{OrganizationID:
"org_example", ReturnURL: "http://localhost:3300/settings"})`, where `userClient`
is derived using `ForUser`. Return URLs use HTTPS or loopback HTTP; returned
provider URLs must use HTTPS. The SDK does not navigate or retry denied requests.

## Data-plane operations

The supported v0 surface includes authentication verification, authorization,
configuration reads, metering, seats, invitations, member changes, allowances,
wallets, and watch events. Representative calls are:

```go
verified, err := client.AuthVerify(1, jwt) // 1 = JWT, 2 = sealed cookie
decision, err := client.AccessCheck("user:42", "view", "document:99")
usage, err := client.MeterConsume("org:acme", "api_calls", 1, idempotencyKey)
balance, err := client.WalletBalance("org:acme", "credits")
watchID, err := client.OnWalletLow(func(event lotor.WalletLowEvent) {
    // Dispatch quickly; event handlers run from the connection reader.
})
if err == nil {
    defer client.Unwatch(watchID)
}
```

Use a stable idempotency key for each intended mutation, and reuse that exact
key only for retries of the same input. Inspect structured protocol failures
with `lotor.IsLWPError` instead of parsing error strings.

## Same-origin invitation gateway

The supported `lotorhttp` package provides an `http.Handler` for applications
that keep browser session state on their backend. It accepts either the
application's opaque bearer or its configured session cookie, revalidates the
Control identity, compares canonical scope with signed runtime ownership, and
derives the LWP actor server-side.

```go
import "github.com/2kims/lotor-go/lotorhttp"

gateway, err := lotorhttp.New(lotorhttp.Options{
    ControlURL: os.Getenv("LOTOR_CONTROL_URL"),
    APIKey:     os.Getenv("LOTOR_API_KEY"),
    CookieName: "application_session",
    Sessions:   sessionStore,
})
if err != nil {
    return err
}
mux.Handle("/api/lotor/invitations/", gateway)
```

The application owns `SessionStore`; it must resolve opaque browser session
identifiers to Control bearers without returning those bearers to JavaScript.
The gateway exposes invitation acceptance and cancellation only. It returns
sanitized public fields and does not return runtime credentials, Control
bearers, canonical scope, or provider secrets.

## Resource graph management and workload execution

`lotorhttp.ControlClient` uses the application's secret key for trusted
resource, Catalog, payload, and resource-credential administration. A workload
must use the separate `lotorhttp.ResourceClient`; its constructor accepts only
the application publishable key and a Lotor-issued resource credential.

For a server request acting on behalf of a signed-in user, derive a separate
client with `userClient, err := applicationClient.ForUser(accessToken)`. It sends
the application secret and user bearer together: the secret selects the
application/environment, while the bearer determines permissions. Invalid user
sessions fail closed; application-only administration remains forbidden. The
original client is unchanged. Never use the application client as a retry after
a user authorization failure.

The delegated client also supports `ResourcePayload`, `AccessResourcePayload`
and `DownloadResourcePayload`: read the manifest, request a version-bound lease,
then download the exact object. Downloads verify the lease's size and SHA-256
digest and do not attach Lotor authentication headers to object storage. These
methods return stored bytes, not decrypted plaintext; encryption policy and key
custody still govern decryption. The same download implementation is used by
workload clients. Use a dedicated HTTP transport that does not inject credentials
into object-store requests.

```go
workload, err := lotorhttp.NewResourceClient(lotorhttp.ResourceClientOptions{
    BaseURL:            os.Getenv("LOTOR_API_URL"),
    ClientID:           os.Getenv("LOTOR_CLIENT_ID"),
    PublishableKey:     os.Getenv("LOTOR_PUBLISHABLE_KEY"),
    ResourceCredential: os.Getenv("LOTOR_RESOURCE_CREDENTIAL"),
})
if err != nil {
    return err
}

preflight, err := workload.PreflightExecution(ctx, "integration:slack", lotorhttp.ResourceExecutionRequest{
    Method: "POST", Path: "/chat.postMessage", Query: "channel=C123", ContentType: "application/json",
    RequestBodyDigest: bodySHA256, RequestBodySize: int64(len(body)),
})
if err != nil {
    return err
}
authorization, err := workload.CommitExecution(ctx, "integration:slack", preflight, lotorhttp.ResourceExecutionCommitInput{})
```

`Query` is the canonical encoded query without `?`; use `url.Values.Encode()`
and pass an empty string when no query exists. It is bound separately from the
Catalog operation path. The preflight token is server-issued, short-lived, and also serves as the
commit idempotency identity. There is no plan ID or caller-generated execution
idempotency key. Commit revalidates the resource, credential, Catalog entry,
payload, policy, and custody revisions before returning authorization evidence.
It never returns a custody endpoint or provider credential bytes.

The browser adapter also relays browser-user execution preflight and commit. It
converts the preflight response header into a 30-second, path-scoped HttpOnly
SameSite=Strict cookie and supplies that capability on commit without exposing
it to JavaScript. Server and CLI workloads continue to use a Lotor-issued
resource credential with the Go client.

## Verify application-gateway assertions

Origins behind a Lotor application gateway should combine a deployment-owned
origin boundary (for example, verified mTLS) with `GatewayAssertionMiddleware`.
Configure one verifier with the exact audience, route pin, configuration
version, binding epoch, and gateway/runtime placement epochs expected by that
handler. The middleware rejects direct traffic, validates the signed request
body and query hashes, strips the assertion header, and places verified claims
in the request context.

Replay-ineligible mutations additionally require a shared atomic
`GatewayAssertionReplayStore`; if that store is absent or unavailable, the
request fails closed. Replay-eligible mutations require a signed, matching
idempotency key. Do not derive verifier authority from request headers or from
the assertion itself.

## Compatibility

`v0.1.x` speaks LWP protocol version 1 and supports Control ownership assertions
with version 1. The public API is pre-1.0; breaking changes may occur in a minor
release and will be called out in the changelog. Published module versions and
tags are immutable.

## Security

Keep Lotor API keys, Control bearers, TLS client keys, and customer data in the
backend. Never log credentials or return them from an HTTP adapter. Report
vulnerabilities privately through the repository security advisory form.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
