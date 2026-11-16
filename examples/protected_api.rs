//! A bearer-token-protected Axum API with no identity provider, no network
//! access, and nothing to configure by hand.
//!
//! Run it:
//!
//! ```console
//! $ cargo run --example protected_api
//! ```
//!
//! Run this example rather than only read it. The real verification path
//! answers the five requests below, against a real JWKS document that it fetches
//! over a socket. The crate fakes nothing here. The last two cases are the
//! interesting ones: this key signed both tokens correctly, minutes ago, and the
//! crate still refuses them.
//!
//! `examples/common/mod.rs` holds the mock issuer. It is a deliberately small
//! imitation of a Keycloak realm: discovery document, JWKS endpoint, one RSA
//! key, plain HTTP on loopback.
//!
//! Rejections come back with an empty body and the reason in
//! `WWW-Authenticate`, which is what RFC 6750 asks for. That is why this prints
//! the header rather than the body.

mod common;

use axum::routing::get;
use axum::{Router, middleware};
use axum_oidc_middleware::{AuthConfig, AuthUser, Authenticator, Issuer, require_auth};
use common::{AUDIENCE, MockIssuer, SigningKey};

#[tokio::main]
async fn main() {
    let key = SigningKey::generate();
    let issuer = MockIssuer::start(&key).await;

    // Built through the chain, so there is no way to leave the audience empty.
    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(issuer.iss()).expect("the mock issuer's iss is a URL"))
        .with_audience(AUDIENCE)
        // Loopback only, and only because the mock issuer has no certificate.
        // This is the one switch in the crate that downgrades the client which
        // fetches your trust anchors. `src/http.rs` refuses `http://` without it.
        .with_insecure_http(true);

    // This call fetches the JWKS document. It fails here rather than on the
    // first request a user makes, which is the whole argument for a `start`
    // function instead of a lazily-initialized middleware.
    let auth = Authenticator::start(config)
        .await
        .expect("start against the mock issuer");

    let app = Router::new()
        .route("/whoami", get(whoami))
        .route_layer(middleware::from_fn_with_state(auth, require_auth));

    let (addr, server) = common::serve(app).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/whoami");

    println!("issuer   {}", issuer.iss());
    println!("api      http://{addr}/whoami");
    println!("audience {AUDIENCE}\n");

    // (label, token, expected status, expected RFC 6750 `error` code,
    //  whether the response names the caller)
    //
    // The two rejection codes differ on purpose. A request that sends no usable
    // credential produces `invalid_request`. `invalid_token` means the crate
    // checked a credential and rejected it.
    let cases = [
        ("no credential", None, 401, Some("invalid_request"), false),
        (
            "token for this audience",
            Some(key.token(issuer.iss(), AUDIENCE)),
            200,
            None,
            true,
        ),
        (
            "token for another audience",
            Some(key.token(issuer.iss(), "someone-elses-api")),
            401,
            Some("invalid_token"),
            false,
        ),
        (
            "token from another issuer",
            Some(key.token("https://issuer.example/realms/demo", AUDIENCE)),
            401,
            Some("invalid_token"),
            false,
        ),
    ];

    for (label, token, expected_status, expected_code, attributed) in cases {
        let mut request = client.get(&url);
        if let Some(token) = &token {
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

        // A rejection carries an empty body on purpose. RFC 6750 puts the
        // explanation in the challenge, and `AuthError` follows that rule. So
        // the header is the part worth printing, not the empty body under it.
        let detail = if challenge.is_empty() {
            body.trim()
        } else {
            challenge.trim()
        };
        println!("{label:28} -> {status}  {detail}");

        assert_eq!(status, expected_status, "{label} got an unexpected status");
        match expected_code {
            Some(code) => assert!(
                challenge.contains(code),
                "{label} challenged with {challenge:?}, which does not name {code}"
            ),
            None => assert!(
                challenge.is_empty(),
                "{label} should not have been challenged, got {challenge:?}"
            ),
        }
        assert_eq!(
            body.contains(common::SUBJECT),
            attributed,
            "{label} was attributed differently than expected"
        );
    }

    // The fifth case is not a rejection, and that is deliberate. The crate
    // caches a JWKS document for `CachePolicy::ttl`, so a key you withdraw is
    // trusted until that entry expires. Withdrawing a key is not revocation:
    // it takes one TTL to land, which is why short-lived tokens and a narrow
    // `aud` matter more than rotation alone.
    issuer.withhold_keys();
    let still_valid = client
        .get(&url)
        .bearer_auth(key.token(issuer.iss(), AUDIENCE))
        .send()
        .await
        .expect("the API answered");
    println!(
        "{:28} -> {}",
        "token after key withdrawal",
        still_valid.status().as_u16()
    );
    assert_eq!(
        still_valid.status(),
        axum::http::StatusCode::OK,
        "a cached trust bundle is expected to keep verifying until its TTL"
    );

    server.abort();
    println!("\nall five checks behaved as documented");
}

/// `AuthUser` is the extractor that decides this route needs a caller. Behind
/// `require_auth` it cannot be reached without one, so the handler never has to
/// check.
async fn whoami(user: AuthUser) -> String {
    format!("hello {}", user.0.log_id())
}
