//! One layer, two kinds of route: the handler that tolerates an anonymous
//! caller, and the one that does not.
//!
//! Run it:
//!
//! ```console
//! $ cargo run --example optional_auth
//! ```
//!
//! [`optional_auth`] runs the full verification path on every token that
//! reaches it. It does not decide whether a route needs a caller. The extractor
//! in the handler signature decides that. `OptionalAuthUser` accepts a request
//! with no credential. [`AuthUser`] behind the same layer rejects that same
//! request.
//!
//! The case worth watching is `/hello` with a token that fails verification. A
//! token that fails produces a `401`, not an anonymous pass. A route that can
//! answer both an attributed caller and an anonymous one must never fall back to
//! "anonymous" because an attacker forged the token. That fallback is the
//! downgrade this split exists to prevent.

mod common;

use axum::routing::get;
use axum::{Router, middleware};
use axum_oidc_middleware::{
    AuthConfig, AuthUser, Authenticator, Issuer, OptionalAuthUser, optional_auth,
};
use common::{AUDIENCE, MockIssuer, SigningKey};

#[tokio::main]
async fn main() {
    let key = SigningKey::generate();
    let issuer = MockIssuer::start(&key).await;

    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(issuer.iss()).expect("the mock issuer's iss is a URL"))
        .with_audience(AUDIENCE)
        .with_insecure_http(true);
    let auth = Authenticator::start(config)
        .await
        .expect("start against the mock issuer");

    let app = Router::new()
        // Attributed when a token arrives, anonymous when none does.
        .route("/hello", get(hello))
        // This route still needs a caller. The extractor decided that, not the
        // layer above it.
        .route("/audit", get(audit))
        .route_layer(middleware::from_fn_with_state(auth, optional_auth));

    let (addr, server) = common::serve(app).await;
    let client = reqwest::Client::new();

    let good = key.token(issuer.iss(), AUDIENCE);
    let forged = key.token(issuer.iss(), "someone-elses-api");

    // One row per case: route, credential, token, status, substring.
    let cases = [
        ("/hello", "none", None, 200, "anonymous"),
        ("/hello", "valid", Some(&good), 200, common::SUBJECT),
        ("/hello", "wrong audience", Some(&forged), 401, ""),
        ("/audit", "none", None, 401, ""),
        ("/audit", "valid", Some(&good), 200, common::SUBJECT),
    ];

    println!("api http://{addr}\n");
    println!(
        "{:<11} {:<15} {:>4}  body or challenge",
        "route", "credential", "status"
    );

    for (route, credential, token, expected_status, expected_substring) in cases {
        let mut request = client.get(format!("http://{addr}{route}"));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.expect("the API answered");
        let status = response.status().as_u16();
        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body = response.text().await.expect("read the response body");

        let detail = if challenge.is_empty() {
            body.trim()
        } else {
            challenge.trim()
        };
        println!("{route:<11} {credential:<15} {status:>4}  {detail}");

        assert_eq!(
            status, expected_status,
            "{route} with {credential} credential got an unexpected status"
        );
        if !expected_substring.is_empty() {
            assert!(
                body.contains(expected_substring),
                "{route} with {credential} credential did not say {expected_substring:?}"
            );
        }
    }

    server.abort();
    println!("\nboth shapes behaved as documented");
}

/// `OptionalAuthUser` reads what the layer left behind: `Some` for a good token,
/// `None` when there was no header, never a bad one.
async fn hello(user: OptionalAuthUser) -> String {
    match &user.0 {
        Some(claims) => format!("Hello {}!", claims.log_id()),
        None => "Hello, anonymous user!".to_owned(),
    }
}

/// The same layer, a stricter extractor. With no claims in scope the extractor
/// answers `401` before this body runs.
async fn audit(user: AuthUser) -> String {
    format!("audit entry attributed to {}", user.0.log_id())
}
