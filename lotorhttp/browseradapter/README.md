# Same-origin browser adapter

Mount this handler at `/.lotor/v1/` in the application's server and configure
the headless browser SDK with `mode: "same-origin"`. Configure `APIURL`,
`BrowserOrigin`, `ClientID`, `PublishableKey` and server-only `SecretKey` through
`browseradapter.New(Config{...})`. Never expose the secret in browser config.

This package forwards requests to remote Lotor; it does not emulate identity,
resources, encryption, billing or environment selection. The remote API must
use HTTPS. The browser origin may use HTTP only on explicit loopback hosts.

Session and key-claim bearers stay in host-only Strict HttpOnly cookies. Writes
require the exact browser origin and CSRF proof. Link and payload capabilities
use five-minute, path-scoped HttpOnly cookies. Browser-supplied bearer/secret/
capability headers are not trusted. Resource requests use the configured
publishable key and the session cookie, never application authority.

Routes are allowlisted: authentication, session, pricing/checkout, organizations,
resources, directories, invitations, key-access flows, credential management,
payloads and bound catalog entries. Catalog administration and resource-type
provisioning are not browser adapter routes. Remote denials propagate without
exposing diagnostic bodies; redirects are not followed. Requests are bounded
to 64 KiB and responses to 4 MiB. Object bytes use the signed storage URLs and
do not pass through this handler.

The handler must see the configured host. Behind a reverse proxy, preserve that
host; do not trust arbitrary forwarded-host headers. Mount it before SPA
fallback routing so API errors cannot become HTML responses.
