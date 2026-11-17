//! The Axum surface: header parsing, status codes, `WWW-Authenticate`, and
//! which routes the layer actually covers.
//!
//! `validation.rs` covers verification itself. This file is about the seam
//! between the crate and a running server. There, a wrong status code or
//! a missing header turns a correct decision into a client that retries
//! forever.

mod common;

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use axum_oidc_middleware::{AuthUser, Authenticator, require_auth};
use common::{StubIssuer, TestKey, now};

const AUDIENCE: &str = "myaudience";

/// A server with `/private` behind `require_auth` and `/public` outside it.
struct TestServer {
    base_url: String,
    _stub: StubIssuer,
    _server: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start(key: &TestKey) -> Self {
        let stub = StubIssuer::start_local(std::slice::from_ref(key)).await;
        let iss = stub.iss();

        let config = axum_oidc_middleware::AuthConfig::empty()
            .with_issuer(
                axum_oidc_middleware::Issuer::discover(&iss, [AUDIENCE]).expect("valid issuer"),
            )
            .with_insecure_http(true)
            .with_policy(axum_oidc_middleware::CachePolicy {
                min_fetch_gap: std::time::Duration::from_secs(1),
                timeout: std::time::Duration::from_secs(2),
                ..Default::default()
            });

        let auth = Authenticator::start(config)
            .await
            .expect("start the authenticator");

        let app = Router::new()
            .route("/public", get(public))
            // Only the layer guards `/private`. `route_layer` applies to every
            // route already registered on *that* router. So the guarded routes
            // go on their own router, and the merge brings them in. Layering
            // here would lock `/public` too.
            .merge(
                Router::new()
                    .route("/private", post(private))
                    .route_layer(middleware::from_fn_with_state(auth, require_auth)),
            );

        let listener = tokio::net::TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
            .await
            .expect("bind a loopback port");
        let SocketAddr::V4(addr) = listener.local_addr().expect("read the bound address") else {
            unreachable!("bound over IPv4 loopback")
        };

        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve the test app");
        });

        Self {
            base_url: format!("http://{addr}"),
            _stub: stub,
            _server: server,
        }
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("build a test client")
    }

    /// `POST /private` with an `Authorization` header built by this crate's own
    /// [`axum_oidc_middleware::authorization`].
    ///
    /// The docs present the helper as the way to build one, for tests and for
    /// clients assembling a request by hand. Nothing else in the suite checks
    /// that its output is what the parser on the other end accepts. A helper
    /// that drifted from `bearer` would still compile and still look right.
    async fn post_private_with(&self, token: &str) -> reqwest::Response {
        self.client()
            .post(format!("{}/private", self.base_url))
            .header(
                reqwest::header::AUTHORIZATION,
                axum_oidc_middleware::authorization(token),
            )
            .send()
            .await
            .expect("reach the test server")
    }

    async fn post_private(&self, authorization: Option<&str>) -> reqwest::Response {
        let request = self.client().post(format!("{}/private", self.base_url));
        match authorization {
            Some(value) => {
                request
                    .header(reqwest::header::AUTHORIZATION, value)
                    .send()
                    .await
            }
            None => request.send().await,
        }
        .expect("reach the test server")
    }
}

async fn private(user: AuthUser) -> String {
    user.0.sub
}

async fn public() -> &'static str {
    "anonymous"
}

// ── The happy path. ──────────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_token_reaches_the_handler_with_its_claims() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;
    let iss = server._stub.iss();

    let token = key.sign(&key.claims(&iss, AUDIENCE));
    // Built with the crate's own helper rather than a hand-written
    // `format!("Bearer {token}")`. So this also proves the helper and the
    // parser agree on the spelling of a credential.
    let response = server.post_private_with(&token).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a good token is admitted"
    );
    assert_eq!(
        response.text().await.expect("read the body"),
        "user-123",
        "the handler sees the verified subject"
    );
}

#[tokio::test]
async fn the_bearer_scheme_is_case_insensitive() {
    // RFC 7235 §2.1 says the scheme is case-insensitive. A client that sends
    // `bearer` is not making an error.
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;
    let iss = server._stub.iss();
    let token = key.sign(&key.claims(&iss, AUDIENCE));

    for scheme in ["Bearer", "bearer", "BEARER"] {
        let response = server
            .post_private(Some(&format!("{scheme} {token}")))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "`{scheme}` is accepted");
    }
}

#[tokio::test]
async fn routes_outside_the_layer_stay_public() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;

    let response = server
        .client()
        .get(format!("{}/public", server.base_url))
        .send()
        .await
        .expect("reach the test server");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a route without the layer needs no credentials"
    );
    assert_eq!(response.text().await.expect("read the body"), "anonymous");
}

// ── Rejections ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn no_header_is_401_with_a_challenge() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;

    let response = server.post_private(None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .expect("a 401 must carry a challenge")
        .to_str()
        .expect("ASCII challenge");
    assert!(
        challenge.starts_with("Bearer error=invalid_request"),
        "a missing credential is `invalid_request`, got {challenge:?}"
    );
}

#[tokio::test]
async fn a_foreign_scheme_is_401_not_200() {
    // Basic auth must not fall through to "anonymous" or be mistaken for a
    // malformed bearer token.
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;

    let response = server.post_private(Some("Basic dXNlcjpwYXNz")).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .is_some(),
        "the challenge names the scheme we want"
    );
}

#[tokio::test]
async fn a_bad_token_is_401_invalid_token() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;

    let response = server.post_private(Some("Bearer not.a.jwt")).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .expect("challenge")
        .to_str()
        .expect("ASCII challenge");
    // `error` is a bare token per RFC 6750 §3.1. Only `error_description` is
    // a quoted string.
    assert!(
        challenge.starts_with("Bearer error=invalid_token"),
        "a present-but-bad credential is `invalid_token`, got {challenge:?}"
    );
}

#[tokio::test]
async fn a_token_for_the_wrong_audience_is_401() {
    // Proves the guard is live in the HTTP stack, not only in the library:
    // another service's correctly signed token does not open this door.
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;
    let iss = server._stub.iss();

    let response = server
        .post_private(Some(&format!(
            "Bearer {}",
            key.sign(&key.claims(&iss, "another-service"))
        )))
        .await;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "another service's audience must not authenticate here"
    );
}

#[tokio::test]
async fn an_expired_token_is_401() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;
    let iss = server._stub.iss();

    let mut expired = key.claims(&iss, AUDIENCE);
    expired["exp"] = serde_json::json!(now() - 120);

    let response = server
        .post_private(Some(&format!("Bearer {}", key.sign(&expired))))
        .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_bearer_value_with_interior_spaces_is_refused() {
    // Two space-separated values is not one credential. Accepting it would
    // let a proxy or a doubled header smuggle a second token.
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;
    let iss = server._stub.iss();
    let token = key.sign(&key.claims(&iss, AUDIENCE));

    for header in [
        format!("Bearer {token} extra"),
        "Bearer".to_owned(),
        "Bearer ".to_owned(),
        "Bearer\ttoken".to_owned(),
    ] {
        let response = server.post_private(Some(&header)).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "`{header}` is not one bearer credential"
        );
    }
}

#[tokio::test]
async fn the_issuer_never_appears_in_an_error_response() {
    // `error_description` goes to the client. It may name the failure, but it
    // must not enumerate the trust anchors or echo the token.
    let key = TestKey::generate("k1");
    let server = TestServer::start(&key).await;

    let response = server.post_private(Some("Bearer garbage.token.here")).await;
    let challenge = response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .expect("challenge")
        .to_str()
        .expect("ASCII challenge")
        .to_owned();

    assert!(challenge.contains("invalid_token"), "{challenge}");
    assert!(
        !challenge.contains("garbage.token"),
        "the token must not be echoed back: {challenge}"
    );
    assert!(
        !challenge.contains(&server._stub.iss()),
        "trusted issuers must not be listed to an anonymous caller: {challenge}"
    );
}

/// The `Authorization` value the helper builds, checked as text.
///
/// Paired with the round trip above. That one proves the middleware accepts
/// the header. This one pins the spelling, which is the part a client reads
/// off the docs and re-implements.
#[test]
fn authorization_prefixes_the_token_with_the_bearer_scheme() {
    let header = axum_oidc_middleware::authorization("eyJhbGciOiJIUzI1NiJ9.payload.signature");

    assert_eq!(
        header.to_str().expect("a bearer header is ASCII"),
        "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature"
    );
}
