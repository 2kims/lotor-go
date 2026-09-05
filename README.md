# lotor-go

`lotor-go` is the Go client for Lotor's LWP/1 data-plane protocol. It provides
the low-level `lotor` client and the optional `lotorhttp` same-origin invitation
gateway. The module has no third-party runtime dependencies and requires Go
1.24 or newer.

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
