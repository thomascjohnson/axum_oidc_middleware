//! The shape of a real deployment: discovery against real issuers over HTTPS, a
//! required audience, and a server that refuses to come up if its identity
//! provider is unreachable.
//!
//! Unlike the other two examples this one needs an actual OIDC issuer, so it is
//! driven by the environment and is compile-checked in CI rather than run:
//!
//! ```console
//! $ export OIDC_AUDIENCE=my-service
//! $ export OIDC_ISSUERS=https://accounts.google.com
//! $ cargo run --example quickstart
//! ```
//!
//! `OIDC_ISSUERS` takes a comma- or space-separated list, so a service that
//! trusts both Google and a company Keycloak realm names both:
//!
//! ```console
//! $ export OIDC_ISSUERS='https://accounts.google.com https://sso.example.com/realms/work'
//! $ export OIDC_AZP=web-client,cli-client
//! ```
//!
//! Two things to notice as you read it. The example awaits `start` before it
//! calls `serve`. A bad issuer therefore fails the boot, instead of producing a
//! wave of `401`s after a boot that looked clean. And the layer registers no
//! route that a caller does not need: a health check behind `require_auth` is a
//! health check that fails.

use std::net::Ipv4Addr;

use axum::routing::post;
use axum::{Router, middleware};
use axum_oidc_middleware::{AuthConfig, AuthUser, Authenticator, Issuer, require_auth};

#[tokio::main]
async fn main() {
    let Some(audience) = env("OIDC_AUDIENCE") else {
        usage();
        std::process::exit(2);
    };
    let issuers: Vec<String> = env("OIDC_ISSUERS")
        .unwrap_or_default()
        .split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|iss| !iss.is_empty())
        .map(str::to_owned)
        .collect();
    if issuers.is_empty() {
        eprintln!("OIDC_ISSUERS is empty; name at least one issuer URL");
        usage();
        std::process::exit(2);
    }

    let mut config = AuthConfig::empty().with_audience(audience.clone());
    for iss in &issuers {
        config = config.with_issuer(Issuer::discover(iss.clone()).expect("each issuer is a URL"));
    }
    // Optional. In a stock Keycloak realm `aud` is "account" for every API, so
    // this is what distinguishes two services on one realm. It narrows the
    // audience, never replaces it.
    if let Some(parties) = env("OIDC_AZP") {
        let parties: Vec<String> = parties
            .split([',', ' '])
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect();
        if !parties.is_empty() {
            config = config.with_authorized_parties(parties);
        }
    }

    // No `with_insecure_http` here, and that is the point: the default rejects a
    // plain-HTTP issuer outright, which is what you want in a deployment.

    let port: u16 = env("PORT")
        .and_then(|value| value.parse().ok())
        .unwrap_or(8080);

    // Boot fails here if an issuer will not answer or its keys will not parse.
    let auth = Authenticator::start(config)
        .await
        .expect("every issuer is reachable and published usable keys");

    let app = Router::new()
        .route("/hello", post(hello))
        .route_layer(middleware::from_fn_with_state(auth, require_auth));

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .expect("bind the port in $PORT");

    println!(
        "trusting {} issuer(s): {}",
        issuers.len(),
        issuers.join(", ")
    );
    println!("requiring audience {audience}");
    println!("listening on http://127.0.0.1:{port}/hello");
    println!("send:  curl -X POST -H 'Authorization: Bearer $TOKEN' http://127.0.0.1:{port}/hello");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            // `ctrl_c` is why `signal` is a dev-dependency feature and not a
            // dependency feature: a library has no business deciding when its
            // caller's process should stop.
            if let Err(err) = tokio::signal::ctrl_c().await {
                eprintln!("lost the terminal: {err}");
            }
        })
        .await
        .expect("serve until interrupted");
}

/// The handler never inspects a header and never handles an absent caller.
/// Taking [`AuthUser`] is how the handler says the route needs a caller, and
/// `require_auth` already enforced that.
async fn hello(user: AuthUser) -> String {
    format!("Hello {} with audience {:?}", user.0.log_id(), user.0.aud)
}

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn usage() {
    eprintln!(
        "\
usage: OIDC_AUDIENCE=<aud> OIDC_ISSUERS=<url>[ <url>...] cargo run --example quickstart

  OIDC_AUDIENCE   required; the `aud` this service accepts
  OIDC_ISSUERS    required; whitespace- or comma-separated issuer URLs, HTTPS only
  OIDC_AZP        optional; comma-separated `azp` values allowed to call
  PORT            optional; defaults to 8080

For an example that stands up its own issuer and needs no configuration, run:
  cargo run --example protected_api"
    );
}
