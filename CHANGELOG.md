# Changelog

All notable public API and compatibility changes are documented here. This
project follows Semantic Versioning; breaking changes during `v0.x` releases
are called out explicitly.

## Unreleased

- Add bounded, context-cancellable durable-operation polling to the Control
  client. Failed and cancelled operations are returned for caller handling;
  mutations are never retried.

- Isolate payload storage transfers from caller cookie jars and reject
  credential-bearing upload headers; storage responses cannot mutate the jar.

- Add typed Control-client payload rewrap with delegated-user authority, key and
  lifecycle fencing, and optional browser-custody attestation fields.

- Add generic Control-client resource candidate search, link
  preflight/commit/send, unlink, collaborator listing and structured resource
  search with header-only link capabilities and strict response decoding.

- Add delegated organization E2EE policy read/configuration and resource guest
  policy mutation without application-authority fallback.

- Add fail-closed Ed25519 gateway assertion verification and HTTP middleware
  with exact route, placement, request, expiry, origin, and replay checks.

## v0.1.0-rc.2

- Add client-owned subject key enrollment and encrypted resource key-envelope
  lifecycle operations.
- Add encrypted invitations whose resource grants remain pending until a
  signed recipient envelope activates access.

## v0.1.0-rc.1

- Add the `github.com/2kims/lotor-go` module.
- Add verified runtime ownership discovery, LWP/LWPS connections, one-step
  authenticated owner retry, and the LWP/1 data-plane client.
- Add the supported `lotorhttp` same-origin invitation gateway.
- License the public distribution under Apache-2.0.
