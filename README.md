# axum-oidc-middleware

This crate authenticates bearer tokens in [Axum](https://github.com/tokio-rs/axum)
against one or more OIDC issuers. Google, Keycloak, and Entra ID work, and so
does any other issuer that publishes JWKS.

This crate is the **resource-server** half of OIDC: it verifies tokens that
something else fetches. Your frontend or another service completes the OIDC
redirect with the issuer, then sends the token here in an
`Authorization: Bearer <jwt>` header. This crate never redirects to a login page,
holds a session, or issues a cookie.

## Quick start

```rust,no_run
use axum_oidc_middleware::{AuthConfig, AuthUser, Authenticator, Issuer, require_auth};
use axum::{middleware, routing::post, Router};

async fn app() -> Result<Router, axum_oidc_middleware::AuthError> {
    // Each issuer names the audiences its own tokens may carry, as it is
    // built. There is no deployment-wide audience list for an issuer to
    // inherit, so a second issuer cannot quietly pick up the first one's
    // audience.
    let config = AuthConfig::empty().with_issuers([
        // Google never makes an `azp` claim, so this issuer names no client.
        // Its `azp` gate is off, and off for this issuer alone.
        Issuer::discover("https://accounts.google.com", ["myapp"])?,
        // Keycloak's stock `aud` is "account" for every API, so name the client
        // here too. This crate verifies `azp` in addition to the audience,
        // never instead of it. It goes on the issuer because a client id is
        // unique within a realm, not across realms.
        Issuer::discover("https://sso.example.com/realms/myapp", ["myapp"])?
            .authorized_party("myapp-client")?,
    ]);

    // This call fails now if an issuer is unreachable or its keys will not load.
    let auth = Authenticator::start(config).await?;

    Ok(Router::new()
        .route("/hello", post(handler))
        // Keep public routes outside this layer.
        .route_layer(middleware::from_fn_with_state(auth, require_auth)))
}

async fn handler(user: AuthUser) -> String {
    format!("hello {}", user.0.log_id())
}
```

`require_auth` rejects a request that has no `Authorization` header.
`optional_auth` verifies any token that a request supplies, with the same rules.
It attributes the request when a token is present. It leaves the request
anonymous when no token is present. It never relaxes verification.

## Run it

Two examples start their own OIDC issuer on loopback. They need no client ID, no
network access, and no configuration.

```console
$ cargo run --example protected_api
issuer   http://127.0.0.1:61735/realms/demo
api      http://127.0.0.1:61738/whoami
audience example-api

no credential                -> 401  Bearer error=invalid_request
token for this audience      -> 200  hello user-123@http://127.0.0.1:61735/realms/demo
token for another audience   -> 401  Bearer error=invalid_token, error_description="`aud` does not name an accepted audience (InvalidAudience)"
token from another issuer    -> 401  Bearer error=invalid_token, error_description="untrusted issuer `https://issuer.example/realms/demo`"
token after key withdrawal   -> 200

all five checks behaved as documented
```

The last line reports `200`. That is not a defect. The crate caches the JWKS for
`CachePolicy::ttl`, so a withdrawn key stays trusted for one TTL. This crate does
not call a revocation endpoint. Short-lived tokens and a narrow `aud` limit the
damage instead.

`cargo run --example optional_auth` covers the other shape. Under one layer, one
route accepts anonymous callers and another route refuses them. That example
also covers a forged token, which produces `401` instead of an anonymous pass.

`cargo run --example quickstart` runs the deployment-shaped server. It reads
`OIDC_ISSUERS` and `OIDC_AUDIENCE`, and it refuses to start if an issuer will not
answer.

CI builds all three examples and runs the first two.

## Effects on the host process

`Authenticator::start` installs `ring` as the process-wide default rustls crypto
provider. This crate uses `reqwest` through `rustls-no-provider`, which selects
no backend. `reqwest::Client` panics at construction in a process that has no
provider, and fetching a JWKS document is the first HTTPS request that most
services make.

`start` installs the provider once, at startup, and never on the request path.
The install is idempotent and first-writer-wins: if you want `aws-lc-rs`, install
it before you call `start`. The crate then uses your provider, including for its
own JWKS fetch.

Nothing else is global. `start` spawns no background task, and it reads no
environment variable.

No log level prints the bearer token or its signature. `TRACE` logs `sub`@`iss`,
`aud`, and `exp`. Treat trace output as access-log material.

## Guarantees

- `SignatureAlgorithm` is a closed enum. It cannot express `none` or any HMAC
  algorithm, so algorithm confusion is impossible rather than unlikely.
- The crate accepts only HTTPS issuer URLs and HTTPS JWKS endpoints. Setting
  `allow_insecure_http` relaxes that for a loopback host only: `127.0.0.0/8`,
  `::1`, `localhost`. A cleartext issuer on any other host stays refused. Only
  asymmetric keys of an allowlisted type enter the trust bundle.
- `kid` is mandatory. The crate verifies `iss` against the issuer whose key
  actually verified the signature.
- You cannot turn audience verification off. Once you trust a second issuer,
  each issuer must have its own audience list.
- The crate caps the size of each JWKS response as it streams in. It runs one
  refresh request at a time (single-flight) and rate-limits refreshes. A token
  verification therefore never blocks on a slow issuer.

## Documentation

The crate-level docs in `src/lib.rs` give the full verification order and the
list of deliberate limits: <https://docs.rs/axum-oidc-middleware>.

## Toolchain

`Cargo.toml` sets the MSRV to Rust 1.89, and this crate uses edition 2024.
`rust-toolchain.toml` pins Rust 1.100.0.

## Security

Report a vulnerability privately. Do not open a public issue.
[SECURITY.md](SECURITY.md) lists the supported versions and the disclosure
process, and it says where advisories appear, including the RustSec path
`crates/axum-oidc-middleware/RUSTSEC-YYYY-NNNN.md`.

## License

This project uses the MIT license. See [LICENSE](LICENSE).
