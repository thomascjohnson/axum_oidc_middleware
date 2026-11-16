//! `optional_auth`: honour a token the caller offers, reject one that does
//! not verify, and treat only a missing `Authorization` header as anonymous.
//!
//! The bug this suite exists for was a disagreement between the extractor and
//! the middleware, so every test here drives a **real router through the
//! middleware** and reads what the handler answered. Testing
//! `OptionalAuthUser::from_request_parts` alone cannot see it. The extractor
//! only ever reads an extension. The layer answers the question that matters:
//! which requests get one inserted, and which never reach the
//! handler.
//!
//! The property that matters most is the third one below. The layer must
//! *reject* a token that is present and invalid. Serving that request
//! anonymously is a silent downgrade, and a `200` is the last thing a client
//! with a broken token needs.

mod common;

use std::net::{IpAddr, SocketAddr};

use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use axum_oidc_middleware::{
    AuthUser, Authenticator, OptionalAuthUser, optional_auth, require_auth,
};
use common::{StubIssuer, TestKey, now};

const AUDIENCE: &str = "my-audience";

/// One server, three shapes of route:
///
/// - `/optional` — `OptionalAuthUser` behind `optional_auth`, the pair under
///   test: answers the subject, or `anonymous`.
/// - `/mandatory` — `AuthUser` behind the *same* `optional_auth` layer, the
///   per-route switch that keeps a route closed while its neighbours are open.
/// - `/private` — `AuthUser` behind `require_auth`, to prove the mandatory path
///   still behaves exactly as it did.
/// - `/public` — no layer at all, no token read.
struct TestServer {
    base_url: String,
    stub: StubIssuer,
    _server: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Start, publishing `keys` as the issuer's key set.
    async fn start(keys: &[TestKey]) -> Self {
        let stub = StubIssuer::start_local(keys).await;
        let iss = stub.iss();

        let config = axum_oidc_middleware::AuthConfig::empty()
            .with_issuer(axum_oidc_middleware::Issuer::discover(&iss).expect("valid issuer"))
            .with_insecure_http(true)
            .with_policy(axum_oidc_middleware::CachePolicy {
                min_fetch_gap: std::time::Duration::from_secs(1),
                timeout: std::time::Duration::from_secs(2),
                ..Default::default()
            })
            .with_audience(AUDIENCE);

        let auth = Authenticator::start(config)
            .await
            .expect("start the authenticator");

        let app = Router::new()
            .route("/public", get(public))
            .merge(
                Router::new()
                    .route("/optional", post(optional))
                    .route("/mandatory", post(mandatory))
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
            axum::serve(listener, app)
                .await
                .expect("serve the test app");
        });

        Self {
            base_url: format!("http://{addr}"),
            stub,
            _server: server,
        }
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("build a test client")
    }

    /// `POST {path}`, with the given raw `Authorization` value if any.
    async fn post(&self, path: &str, authorization: Option<&str>) -> reqwest::Response {
        let request = self.client().post(format!("{}{}", self.base_url, path));
        let request = match authorization {
            Some(value) => request.header(reqwest::header::AUTHORIZATION, value),
            None => request,
        };
        request.send().await.expect("reach the test server")
    }

    /// `POST {path}` with an `Authorization` header carrying raw bytes.
    ///
    /// For a value the type system will not let a `&str` express. A header is
    /// bytes. UTF-8 is this crate's requirement on reading one, not HTTP's,
    /// and `HeaderValue` accepts the whole octet range apart from the forbidden
    /// control characters. So a non-UTF-8 `Authorization` is a credential a
    /// client can really send, and it has to be handled where it arrives.
    async fn post_raw(&self, path: &str, value: &[u8]) -> reqwest::Response {
        // Read before use, rather than through `unwrap_or_else`, so this block
        // has no `panic!` arm that the happy path can only walk past. The
        // failure still carries both the offending bytes and the rejecting
        // layer's own reason.
        let value = reqwest::header::HeaderValue::from_bytes(value);
        assert!(
            value.is_ok(),
            "`{value:?}` should be a sendable header: {:?}",
            value.as_ref().err()
        );
        let value = value.expect("asserted above");

        self.client()
            .post(format!("{}{}", self.base_url, path))
            .header(reqwest::header::AUTHORIZATION, value)
            .send()
            .await
            .expect("reach the test server")
    }

    /// `Authorization: Bearer <a token signed by `key` for this issuer>`.
    fn bearer_for(&self, key: &TestKey) -> String {
        format!(
            "Bearer {}",
            key.sign(&key.claims(&self.stub.iss(), AUDIENCE))
        )
    }
}

async fn optional(OptionalAuthUser(user): OptionalAuthUser) -> String {
    match user {
        Some(claims) => claims.sub,
        None => "anonymous".to_owned(),
    }
}

/// The route that stays closed: the layer let an anonymous request through, and
/// this extractor is what rejects it.
async fn mandatory(user: AuthUser) -> String {
    user.0.sub
}

async fn private(user: AuthUser) -> String {
    user.0.sub
}

async fn public() -> &'static str {
    "public"
}

/// A rejected request, tested the way a client would notice it. Returns the
/// `WWW-Authenticate` challenge in the response.
///
/// The status alone is not enough. If the middleware swallowed verification
/// errors into `None`, the response would be a `200` whose body says
/// `anonymous`. Every assertion written only against "not `Some`" would still
/// pass. Assert status, body, and challenge together, in one place, so no test
/// can forget the body.
async fn assert_refused_not_anonymous(response: reqwest::Response, header: &str) -> String {
    let status = response.status();
    // Read as an option, not `expect`. If the middleware swallowed the
    // verification error, the response is a `200` with no challenge at all.
    // The assertion below has to be the thing that says so.
    let challenge = response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response.text().await.expect("read the body");

    assert_ne!(
        status,
        StatusCode::OK,
        "`{header}` was accepted with a `200` and body {body:?}: a credential that was sent and \
         could not be verified must never become an anonymous caller"
    );
    assert_eq!(status, StatusCode::UNAUTHORIZED, "`{header}` is a 401");
    assert_ne!(
        body, "anonymous",
        "the handler served the anonymous path for `{header}`"
    );

    challenge.expect("a 401 must carry a challenge")
}

// ── Absent is optional ───────────────────────────────────────────────────────

#[tokio::test]
async fn no_header_is_served_as_anonymous() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let response = server.post("/optional", None).await;

    assert_eq!(response.status(), StatusCode::OK, "no token is optional");
    assert_eq!(
        response.text().await.expect("read the body"),
        "anonymous",
        "the handler sees `None`"
    );
}

#[tokio::test]
async fn an_anonymous_request_gets_no_challenge() {
    // A `200` with `WWW-Authenticate` on it would tell a client the request
    // needed credentials it deliberately did not send.
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let response = server.post("/optional", None).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .is_none(),
        "an anonymously served request must not claim to have been challenged"
    );
}

// ── Present and valid is honoured. ───────────────────────────────────────

#[tokio::test]
async fn a_valid_token_is_attributed_to_its_subject() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let header = server.bearer_for(&key);
    let response = server.post("/optional", Some(&header)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.text().await.expect("read the body"),
        "user-123",
        "a valid token on an optional route is honoured, not discarded"
    );
}

#[tokio::test]
async fn the_bearer_scheme_stays_case_insensitive() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;
    let token = key.sign(&key.claims(&server.stub.iss(), AUDIENCE));

    for scheme in ["Bearer", "bearer", "BEARER"] {
        let response = server
            .post("/optional", Some(&format!("{scheme} {token}")))
            .await;
        assert_eq!(response.status(), StatusCode::OK, "`{scheme}` is accepted");
        assert_eq!(response.text().await.expect("read the body"), "user-123");
    }
}

// ── Present and invalid is a rejection ───────────────────────────────────────

#[tokio::test]
async fn an_expired_token_is_refused_not_anonymised() {
    // The property this whole file is about: the middleware must not turn a
    // token it could not verify into `None`.
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let mut expired = key.claims(&server.stub.iss(), AUDIENCE);
    expired["exp"] = serde_json::json!(now() - 120);

    let header = format!("Bearer {}", key.sign(&expired));
    let response = server.post("/optional", Some(&header)).await;

    let challenge = assert_refused_not_anonymous(response, "an expired token").await;
    assert!(
        challenge.starts_with("Bearer error=invalid_token"),
        "a present-but-bad credential is `invalid_token`, got {challenge:?}"
    );
}

#[tokio::test]
async fn a_token_signed_by_an_untrusted_key_is_refused_not_anonymised() {
    // Signed by a key the issuer never published: right shape, right `iss`,
    // right `aud`, and no key in the bundle that can verify it.
    let trusted = TestKey::generate("k1");
    let attacker = TestKey::generate("k2");
    let server = TestServer::start(std::slice::from_ref(&trusted)).await;

    let header = server.bearer_for(&attacker);
    let response = server.post("/optional", Some(&header)).await;

    assert_refused_not_anonymous(response, "a token from an untrusted key").await;
}

#[tokio::test]
async fn a_token_for_another_audience_is_refused_not_anonymised() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let header = format!(
        "Bearer {}",
        key.sign(&key.claims(&server.stub.iss(), "another-service"))
    );
    let response = server.post("/optional", Some(&header)).await;

    assert_refused_not_anonymous(response, "another service's token").await;
}

// ── Present and malformed: rejected, on purpose ──────────────────────────────

#[tokio::test]
async fn a_malformed_credential_is_refused_not_anonymised() {
    // The deliberate decision: *absent* is optional, *malformed* is invalid.
    // Omitting the header is the only honest way to ask for the anonymous
    // path. So the crate never downgrades a request that really offered a
    // credential to it.
    //
    // `Basic dXNlcjpwYXNz` is a client that means a different scheme. Answering
    // it with the anonymous path tells it nothing is wrong. `Bearer` with no
    // token is a header that lost its token on the way here. Usual causes: a
    // proxy rewrite, a doubled header joined into one value, or someone
    // stripping it. A server that reads that as "anonymous" lets anything on
    // the path remove a caller's identity. It even answers `200`. A `401` naming
    // the bearer scheme is the only answer that is debuggable from the client
    // side.
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    for header in [
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer ",
        "not.a.jwt",
        "Bearer also=a.second.token",
    ] {
        let response = server.post("/optional", Some(header)).await;
        assert_refused_not_anonymous(response, header).await;
    }
}

/// A header that is not UTF-8 at all.
///
/// The distinction this pins is the one the whole middleware rests on: only a
/// *missing* header is absence. A header this crate cannot read is a credential
/// that was offered and could not be understood. So it gets the `401`, not the
/// anonymous answer. Read it the other way, and an on-path middlebox that
/// mangles header bytes silently demotes real callers to anonymous. The `200`
/// they then see would look like success.
#[tokio::test]
async fn a_credential_that_is_not_utf8_is_refused_not_anonymised() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    // `Bearer `<token> with a byte that cannot appear in UTF-8 in place of part
    // of the token: a credential, unreadable.
    let mut mangled = b"Bearer ".to_vec();
    mangled.extend_from_slice(&[0xc3, 0x28, 0xa0, 0x41]);

    let response = server.post_raw("/optional", &mangled).await;
    let challenge = assert_refused_not_anonymous(response, "<non-UTF-8 bearer>").await;

    assert!(
        challenge.contains("invalid_request"),
        "an unreadable header is a malformed credential, not a bad signature: \
         {challenge}"
    );

    // The same byte string on the route that demands a caller, and on the route
    // that requires a token outright. One rule, applied identically by all
    // three shapes.
    for path in ["/mandatory", "/private"] {
        let response = server.post_raw(path, &mangled).await;
        assert_refused_not_anonymous(response, "<non-UTF-8 bearer>").await;
    }
}

// ── The mandatory paths, unchanged ───────────────────────────────────────────

#[tokio::test]
async fn require_auth_still_refuses_a_missing_token() {
    // `optional_auth` must not have softened the middleware that demands one.
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let response = server.post("/private", None).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .expect("a 401 must carry a challenge")
        .to_str()
        .expect("ASCII challenge")
        .to_owned();
    assert!(
        challenge.starts_with("Bearer error=invalid_request"),
        "a missing credential is `invalid_request`, got {challenge:?}"
    );
}

#[tokio::test]
async fn require_auth_still_attributes_a_valid_token() {
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let header = server.bearer_for(&key);
    let response = server.post("/private", Some(&header)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.expect("read the body"), "user-123");
}

#[tokio::test]
async fn authuser_closes_a_route_that_optional_auth_left_open() {
    // The layer is per-router and permissive. `AuthUser` is the per-route
    // refusal. Both halves matter: an anonymous request is a 401 here while its
    // neighbour two lines away answers `anonymous`, and a valid token opens it.
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let anonymous = server.post("/mandatory", None).await;
    assert_eq!(
        anonymous.status(),
        StatusCode::UNAUTHORIZED,
        "a route that needs a caller must not serve an anonymous one"
    );
    assert!(
        anonymous
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .is_some(),
        "the extractor's rejection carries the challenge, not just the status"
    );

    let header = server.bearer_for(&key);
    let attributed = server.post("/mandatory", Some(&header)).await;
    assert_eq!(attributed.status(), StatusCode::OK);
    assert_eq!(attributed.text().await.expect("read the body"), "user-123");
}

#[tokio::test]
async fn a_route_outside_every_layer_reads_no_token_at_all() {
    // The third honest shape: no layer, so the crate reads no token. It does
    // not honour a valid token here, because there is nothing to verify it
    // with. That is exactly why a route that wants a caller goes under a layer.
    let key = TestKey::generate("k1");
    let server = TestServer::start(std::slice::from_ref(&key)).await;

    let response = server
        .client()
        .get(format!("{}/public", server.base_url))
        .send()
        .await
        .expect("reach the test server");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.expect("read the body"), "public");
}
