//! What the crate *says* about a request, not just how it answers it.
//!
//! An operator debugging a login failure at 3am has only the log line. Every
//! other kind of test is blind to a `tracing` macro. The macro evaluates its
//! arguments only when a subscriber enables that level. With no subscriber
//! installed, the whole body of a `debug!` is dead code. Three faults then stay
//! invisible to assertions written against a response. A field name can be
//! misspelled. A reason can land on a level that production filters out. A token
//! can ride quietly into a log file.
//!
//! So these tests install [`LogCapture`] and assert on the events themselves.
//! Three properties are ones a response cannot express. A rejection has to be
//! attributable to a route. A provider failure has to be loud while client noise
//! stays quiet. And nothing secret may appear in any of it.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse as _;
use axum::routing::post;
use axum_oidc_middleware::{
    AuthError, AuthUser, Authenticator, OptionalAuthUser, optional_auth, require_auth,
};
use common::{LogCapture, StubIssuer, TestKey};

const AUDIENCE: &str = "my-audience";

/// These are the three route shapes. Every log line the request path can emit
/// has a route that produces it. The shapes are an attributed request, an
/// anonymous request that a closed route refuses, and a provider failure.
struct TestServer {
    base_url: String,
    stub: StubIssuer,
    _server: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn start(keys: &[TestKey]) -> Self {
        let published: Vec<serde_json::Value> = keys.iter().map(TestKey::jwk).collect();
        Self::start_publishing(&published).await
    }

    /// Start with an exact JWKS document, for a published JWK that is not a
    /// key's honest shape. Here it is an EC key with no `alg`. That is the one
    /// shape that reaches the trust bundle while `ES256` is unconfigured.
    async fn start_publishing(published: &[serde_json::Value]) -> Self {
        let stub = StubIssuer::start_local(&[]).await;
        // Published before the authenticator starts, so the very first fetch —
        // the one warm-up performs — sees it. Republishing afterwards would
        // test nothing: the warmed bundle is served for its whole TTL.
        stub.publish(published.to_vec());
        let iss = stub.iss();

        let auth = Authenticator::start(
            axum_oidc_middleware::AuthConfig::empty()
                .with_issuer(axum_oidc_middleware::Issuer::discover(&iss).expect("valid issuer"))
                .with_insecure_http(true)
                .with_policy(axum_oidc_middleware::CachePolicy {
                    min_fetch_gap: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                    ..Default::default()
                })
                .with_audience(AUDIENCE),
        )
        .await
        .expect("start the authenticator");

        let app = Router::new()
            .merge(
                Router::new()
                    .route("/optional", post(optional))
                    // Left open by the layer, closed by the extractor.
                    .route("/mandatory", post(mandatory))
                    .route("/outage", post(outage))
                    .route_layer(middleware::from_fn_with_state(auth.clone(), optional_auth)),
            )
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
            axum::serve(listener, app).await.expect("serve");
        });

        Self {
            base_url: format!("http://{addr}"),
            stub,
            _server: server,
        }
    }

    async fn post(&self, path: &str, authorization: Option<&str>) -> reqwest::Response {
        let request = self.client().post(format!("{}{}", self.base_url, path));
        let request = match authorization {
            Some(value) => request.header(reqwest::header::AUTHORIZATION, value),
            None => request,
        };
        request.send().await.expect("reach the test server")
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build a client")
    }

    fn bearer_for(&self, key: &TestKey) -> String {
        format!(
            "Bearer {}",
            key.sign(&key.claims(&self.stub.iss(), AUDIENCE))
        )
    }
}

async fn optional(OptionalAuthUser(user): OptionalAuthUser) -> String {
    user.map(|claims| claims.sub)
        .unwrap_or_else(|| "anonymous".to_owned())
}

async fn mandatory(user: AuthUser) -> String {
    user.0.sub
}

async fn private(user: AuthUser) -> String {
    user.0.sub
}

/// The two failures an operator sees as `5xx`, reached through the same
/// `IntoResponse` the middleware uses.
///
/// `Authenticator::start` verifies the configuration on the way in, so a running
/// server does not produce `Configuration` by itself. A host reaches it by
/// carrying an `AuthError` from its own setup, which goes through this same
/// rendering. What is under test is the rendering, and specifically that both of
/// these are *loud*. A `5xx` from this crate means our dependency or our
/// configuration. Either way, a `debug!` would hide it in the noise that
/// unauthenticated traffic is allowed to make.
async fn outage() -> Result<&'static str, AuthError> {
    Err(AuthError::ProviderUnavailable(
        "https://sso.example/realms/demo/jwks.json answered 503".to_owned(),
    ))
}

/// The subject is qualified by issuer, so two providers minting the same `sub`
/// do not collide. That only holds if the issuer really is in the field.
#[tokio::test]
async fn the_authenticated_subject_carries_the_issuer_it_came_from() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;
    let (capture, _guard) = LogCapture::install();

    server
        .post("/private", Some(&server.bearer_for(&key)))
        .await;

    let line = capture.only("authenticated");
    let subject = line.field("subject").expect("a subject field");
    assert!(
        subject.starts_with("user-123@http://127.0.0.1:"),
        "`subject` should be `sub@iss`, got {subject}"
    );

    // These answer the operator's other two questions from the log, without the
    // token. Was this token good for this route? When did it expire?
    assert_eq!(line.field("aud"), Some(r#"["my-audience"]"#));
    assert!(
        line.field("exp").is_some_and(|exp| exp.len() > 9),
        "`exp` should be a real timestamp, got {:?}",
        line.field("exp")
    );
    assert_eq!(
        line.level,
        tracing::Level::TRACE,
        "per-request noise stays quiet"
    );
}

/// The property this file exists for. The token is the bearer credential. A log
/// line that contains it makes the whole log file replayable: anyone who can
/// read it can call the API as that caller. That is a different and much larger
/// secret than the subject and expiry.
#[tokio::test]
async fn nothing_on_the_success_path_logs_the_token_itself() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;
    let (capture, _guard) = LogCapture::install();

    let token = server.bearer_for(&key);
    server.post("/private", Some(&token)).await;
    // And the failure paths, which are the ones that quote input.
    server.post("/private", Some("Bearer not-a-jwt")).await;
    server
        .post("/optional", Some(&server.bearer_for(&key)))
        .await;

    // Every signature component of the token, matched as a substring: a log
    // line that printed the token would print this too.
    let signature = token.rsplit('.').next().expect("a signed token");
    assert!(
        capture.excludes(signature),
        "a log line carried the token's signature:\n{}",
        capture.text()
    );
    assert!(
        capture.excludes(&token),
        "a log line carried the whole token:\n{}",
        capture.text()
    );
}

/// "This route demands a caller and nobody authenticated" is a reportable fact
/// about a request. The route is the only part of that fact that says what to
/// fix.
#[tokio::test]
async fn a_closed_route_names_itself_when_it_refuses_an_anonymous_caller() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;
    let (capture, _guard) = LogCapture::install();

    let response = server.post("/mandatory", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let line = capture.only("no verified claims");
    assert_eq!(
        line.field("path"),
        Some("/mandatory"),
        "the log has to say which route refused: {:?}",
        line.fields
    );

    // And the level. Anyone who can open a socket can reach this path. One
    // unbounded `warn!` per anonymous request is a log-flood primitive. So it
    // has to stay at `debug`, while the `401` still carries the reason to the
    // caller that needs it.
    assert_eq!(
        line.level,
        tracing::Level::DEBUG,
        "client-producible traffic must not reach `warn!` and above: {}",
        capture.text()
    );
}

/// A provider failure is ours, not the caller's. It is the one class of
/// rejection that an operator has to see without enabling debug logging.
#[test]
fn a_provider_failure_is_logged_at_warn_with_the_reason() {
    let (capture, _guard) = LogCapture::install();

    let response = AuthError::ProviderUnavailable(
        "http://127.0.0.1:9/jwks.json: connection refused".to_owned(),
    )
    .into_response();

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let line = capture.only("identity provider unavailable");
    assert_eq!(line.level, tracing::Level::WARN);
    assert_eq!(
        line.field("reason"),
        Some("http://127.0.0.1:9/jwks.json: connection refused"),
        "the reason is the actionable half: {:?}",
        line.fields
    );
    assert_eq!(line.field("status"), Some("503 Service Unavailable"));
}

/// The same argument applies one level up. A misconfigured deployment is not
/// traffic. It must not be findable only by someone who already guessed to turn
/// on debug logging.
#[test]
fn a_misconfiguration_is_logged_at_error() {
    let (capture, _guard) = LogCapture::install();

    let response =
        AuthError::Configuration("no trusted issuers configured".to_owned()).into_response();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let line = capture.only("authentication misconfigured");
    assert_eq!(line.level, tracing::Level::ERROR);
    assert_eq!(line.field("reason"), Some("no trusted issuers configured"));
    assert_eq!(line.field("status"), Some("500 Internal Server Error"));
}

/// Rejections an unauthenticated caller can generate at will are `debug`, so
/// the same volume of hostile traffic cannot fill a log.
#[test]
fn caller_producible_rejections_stay_at_debug() {
    let (capture, _guard) = LogCapture::install();

    for error in [
        AuthError::MissingToken,
        AuthError::NotBearer,
        AuthError::InvalidToken("unknown `kid` `rotating-in`".to_owned()),
    ] {
        let _ = error.into_response();
    }

    let lines = capture.matching("request rejected");
    assert_eq!(
        lines.len(),
        3,
        "one line per rejection:\n{}",
        capture.text()
    );
    for line in lines {
        assert_eq!(line.level, tracing::Level::DEBUG, "{}", capture.text());
    }
}

/// A key the issuer publishes but no accepted algorithm can use is the one
/// configuration mistake that looks like a wave of forged tokens. The log has to
/// say which family arrived and what the deployment accepted. Otherwise the
/// operator debugs signatures while the bug sits in the algorithm list.
#[tokio::test]
async fn a_key_that_cannot_verify_anything_accepted_says_which_family_it_was() {
    let rsa = TestKey::generate("rsa1");
    let ec = TestKey::generate_es256("ec1");
    // `alg` removed. A JWK that *claims* `ES256` is refused as an unconfigured
    // algorithm and never reaches the bundle. So the family mismatch below would
    // never be reached. With no `alg` — which RFC 7515 §4.1.1 and RFC 7518 §4.4
    // both allow — the key is admitted on its `kty` alone. This is then a realm
    // that published an EC key and stopped short of saying what for.
    let mut naked_ec = ec.jwk();
    naked_ec
        .as_object_mut()
        .expect("a JWK object")
        .remove("alg");
    let server = TestServer::start_publishing(&[rsa.jwk(), naked_ec]).await;
    let (capture, _guard) = LogCapture::install();

    // RS256 alone is configured, and the issuer publishes an EC key beside its
    // RSA one — a realm mid-migration. The token's own `alg` is accepted, so
    // gate 1 lets it through. The mismatch only surfaces when the `kid` in its
    // header names the EC key. That key cannot verify anything here.
    let iss = server.stub.iss();
    let token = rsa.sign_with_header(
        &rsa.claims(&iss, AUDIENCE),
        serde_json::json!({ "kid": "ec1" }),
    );
    let response = server
        .post("/private", Some(&format!("Bearer {token}")))
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let line = capture.only("cannot verify any accepted algorithm");
    let family = line.field("family").unwrap_or_default();
    assert!(
        family.eq_ignore_ascii_case("ec") || family.contains("EllipticCurve"),
        "the refusal should name the family that arrived, got {family:?}: {:?}",
        line.fields
    );

    let accepted = line.field("accepted").unwrap_or_default();
    assert!(
        accepted.contains("RS256") && !accepted.contains("ES256"),
        "and it should list what this deployment accepts, so the two lists can \
         be compared side by side: {accepted}"
    );

    // The level is the other half. A realm mid-migration produces one of these
    // per token from a client that will retry, so it cannot be a `warn!`. And
    // `trace!` would hide the one misconfiguration that looks exactly like a
    // flood of bad signatures.
    assert_eq!(line.level, tracing::Level::DEBUG, "{}", capture.text());
}
/// Start-up reports what it loaded.
///
/// The one log line that answers "did this deployment load the keys it expects".
/// The count and the location are what an operator compares against the
/// provider. An issuer that quietly stopped publishing two of its keys looks
/// like a rotation problem downstream long before it looks like this.
#[tokio::test]
async fn start_up_logs_which_issuer_it_loaded_and_how_many_keys_it_found() {
    let (capture, _guard) = LogCapture::install();
    let first = TestKey::generate("k1");
    let second = TestKey::generate("k2");
    let stub = StubIssuer::start_local(&[first, second]).await;
    let iss = stub.iss();

    let auth = Authenticator::start(
        axum_oidc_middleware::AuthConfig::empty()
            .with_issuer(axum_oidc_middleware::Issuer::discover(&iss).expect("valid issuer"))
            .with_insecure_http(true)
            .with_audience(AUDIENCE),
    )
    .await
    .expect("start against the stub");
    assert_eq!(auth.issuers().count(), 1);

    let line = capture.only("loaded issuer keys");
    assert_eq!(line.field("iss"), Some(iss.as_str()));
    assert_eq!(
        line.field("keys"),
        Some("2"),
        "the count is the whole point: {:?}",
        line.fields
    );
    assert_eq!(
        line.field("jwks_url"),
        Some(&format!("{iss}/jwks.json")[..]),
        "and the location it came from, so a wrong `jwks_uri` is visible here: {:?}",
        line.fields
    );
    assert_eq!(
        line.level,
        tracing::Level::INFO,
        "a fact about the deployment belongs at info, not buried in debug"
    );
}
