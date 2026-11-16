//! HTTP plumbing: the rustls crypto provider and the one client used to talk
//! to identity providers.

use std::time::Duration;

/// Install `ring` as the process-wide rustls crypto provider.
///
/// `reqwest` is built with the `rustls-no-provider` feature so that this
/// workspace can pick its own crypto backend. That feature makes no provider
/// available on its own. `reqwest::Client` **panics at construction** if no
/// provider is in place. This crate performs the first HTTPS request of most
/// deployments: fetching a JWKS. So it owns the install rather than leaving a
/// panic to whoever reaches HTTP first.
///
/// This call is idempotent. A second call, and a provider already installed by
/// the host binary, both succeed without error.
///
/// This is a promise to callers, not an implementation detail. It is stated
/// where a caller will read it: in the crate-level docs, under
/// "Effects on the host process". Keep the two in step from here.
fn install_crypto_provider() {
    // `install_default` fails only when a provider is already set. That is
    // success as far as we are concerned.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build the HTTP client used for OIDC discovery and JWKS fetching.
///
/// `timeout` bounds the whole request, not just the connect: a hung identity
/// provider must turn into one slow request, not a task that never returns.
///
/// `allow_http` lifts the TLS requirement. See
/// [`AuthConfig::allow_insecure_http`](crate::AuthConfig::allow_insecure_http):
/// it is for loopback tests, and forcing it on in production downgrades the
/// client that fetches your trust anchors to plain HTTP.
pub(crate) fn client(timeout: Duration, allow_http: bool) -> reqwest::Client {
    install_crypto_provider();

    reqwest::Client::builder()
        .timeout(timeout)
        // Only TLS-secured issuers by default: discovery documents and JWKS
        // responses establish trust and must not be able to arrive in cleartext.
        .https_only(!allow_http)
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        // A revoked or rotated certificate should fail closed here rather than
        // be served from a stale connection pool.
        .pool_idle_timeout(Duration::from_secs(30))
        .build()
        .expect("reqwest client with a pinned rustls provider builds")
}
