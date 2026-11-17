//! What happens when the key endpoint answers, and what it answers is wrong.
//!
//! Two distinct duties are under test here, and they pull in opposite
//! directions. A JWKS the client cannot read must be a **failure** — a
//! half-parsed trust bundle is worse than no trust bundle, because it silently
//! accepts fewer callers than the deployment believes it does. A single unusable
//! JWK inside an otherwise good document must **not** be a failure: one
//! encryption key, one key with no `kid`, or one provider publishing a shape
//! `jsonwebtoken` cannot represent must not cost an issuer all of its working
//! keys. Skipping is only safe because the skip is logged and the reason is
//! specific, so the skipped keys are asserted on as well.

mod common;

use std::time::Duration;

use axum_oidc_middleware::{AuthConfig, AuthError, Authenticator, CachePolicy, Issuer};
use common::{LogCapture, StubIssuer, TestKey};

const AUDIENCE: &str = "my-audience";
const KEY_ID: &str = "k1";

/// Warm an authenticator against a stub publishing exactly `published`.
///
/// The stub starts empty. The helper installs the document before it builds the
/// authenticator, so warm-up is the first fetch that sees it.
async fn harness(published: &[serde_json::Value]) -> (StubIssuer, Authenticator, String) {
    let stub = StubIssuer::start_local(&[]).await;
    stub.publish(published.to_vec());
    let iss = stub.iss();

    let auth = Authenticator::start(
        AuthConfig::empty()
            .with_issuer(Issuer::discover(iss.clone(), [AUDIENCE]).expect("valid issuer"))
            .with_insecure_http(true)
            .with_policy(CachePolicy {
                min_fetch_gap: Duration::from_secs(1),
                timeout: Duration::from_secs(2),
                ..CachePolicy::default()
            }),
    )
    .await
    .expect("start against the stub");

    (stub, auth, iss)
}

/// A JWKS served verbatim, without the stub's JSON encoder touching it.
async fn harness_from_body(body: &str) -> (StubIssuer, AuthConfig, String) {
    let stub = StubIssuer::start_local(&[]).await;
    stub.serve_jwks_body(body);
    let iss = stub.iss();

    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(iss.clone(), [AUDIENCE]).expect("valid issuer"))
        .with_insecure_http(true);

    (stub, config, iss)
}

// ── The document itself is unreadable. ──────────────────────────────────────

/// A `200` whose body is not JSON — the proxy's error page, the login form a
/// captive portal substitutes. This is an outage, not "an issuer with no keys".
/// The difference decides whether the operator looks at the provider or at the
/// caller.
#[tokio::test]
async fn a_jwks_that_is_not_json_is_an_outage_not_an_empty_key_set() {
    let (_stub, config, _iss) =
        harness_from_body("<html><body>502 Bad Gateway</body></html>").await;

    let err = Authenticator::start(config)
        .await
        .expect_err("HTML is not a key set");

    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "the provider answered with something unreadable: {err:?}"
    );
    assert!(
        err.to_string().contains("unreadable JSON"),
        "say that the body could not be read: {err}"
    );
}

/// JSON that is well-formed and not a JWKS.
///
/// Two classes, decided differently on purpose. A document that genuinely has no
/// keys — `keys` empty, or absent — is an issuer that published nothing usable.
/// That is the same refusal an all-unusable key set earns. A document that is not
/// a JWKS in *shape* is the unreadable-body case. Conflating the two would send
/// an operator to look at their realm's keys when the endpoint is serving
/// something else entirely.
///
/// The bare `[]` is the interesting one. serde reads a struct from a sequence, so
/// an empty array deserialises as a document with no `keys` rather than failing.
/// That is precisely why "no usable keys" has to stop startup. A client that read
/// it as a healthy issuer with zero keys would boot and then refuse every caller
/// forever.
#[tokio::test]
async fn a_json_document_that_is_not_a_jwks_is_refused_by_class() {
    for body in [r#"{"keys": []}"#, "{}", "[]"] {
        let (_stub, config, iss) = harness_from_body(body).await;

        let err = Authenticator::start(config)
            .await
            .err()
            .unwrap_or_else(|| panic!("`{body}` names no keys, so this must not boot"));

        assert!(
            matches!(err, AuthError::ProviderUnavailable(_)),
            "`{body}`: {err:?}"
        );
        assert!(
            err.to_string().contains("published no usable keys") && err.to_string().contains(&iss),
            "`{body}` should be refused as an empty key set, and `{iss}` named: {err}"
        );
    }

    for body in [
        "null",
        r#""a key set""#,
        r#"{"keys": null}"#,
        r#"{"keys": "one"}"#,
    ] {
        let (_stub, config, _iss) = harness_from_body(body).await;

        let err = Authenticator::start(config)
            .await
            .err()
            .unwrap_or_else(|| panic!("`{body}` is not a JWKS, so this must not boot"));

        assert!(
            matches!(err, AuthError::ProviderUnavailable(_)),
            "`{body}`: {err:?}"
        );
        assert!(
            err.to_string().contains("unreadable JSON"),
            "`{body}` is not a key set in shape, which is a different complaint \
             from an empty one: {err}"
        );
    }
}

/// A response that stops mid-body: headers say 200, the body is cut off. Read
/// as JSON this is a parse failure, and read as a truncated *body* it is a
/// transport failure. Either way it must be an outage, and it must not be
/// mistaken for an issuer whose keys are all fine.
#[tokio::test]
async fn a_jwks_truncated_mid_body_is_an_outage() {
    // A bare listener, not the stub. The point is a response that lies about its
    // own length and then hangs up. No honest encoder can produce that.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let addr = listener.local_addr().expect("read the bound address");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            use tokio::io::AsyncWriteExt as _;
            // `content-length` promises far more than is ever written, so the
            // read fails part-way through the body rather than at the status.
            let partial = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                           content-length: 4096\r\n\r\n{\"keys\":[{\"kid\":\"k1\",";
            let _ = socket.write_all(partial.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });

    let iss = format!("http://{addr}");
    let err = Authenticator::start(
        AuthConfig::empty()
            // The issuer identifier is a URL, and the JWKS is discovered from
            // it — so discovery must be reached too. Point it at the same dead
            // endpoint and let the first failure decide, which is discovery's.
            // The JWKS body case is covered by `serve_jwks_body` above. To
            // reach the JWKS read instead, name the key endpoint directly.
            .with_issuer(
                Issuer::with_jwks_url(
                    &iss,
                    url::Url::parse(&format!("{iss}/jwks.json")).expect("parse a JWKS URL"),
                    [AUDIENCE],
                )
                .expect("valid issuer"),
            )
            .with_insecure_http(true),
    )
    .await
    .expect_err("a body that ends mid-document is not a key set");

    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "a truncated response is the provider's failure: {err:?}"
    );
}

/// The issuer goes away *after* startup, while the crate asks for a refresh. The
/// keys already in hand are still valid public keys, so valid tokens keep
/// working. The refusal for a key that is still missing is `503`, not the `401`
/// that tells a client to throw away a good token.
#[tokio::test]
async fn an_issuer_that_dies_during_a_refresh_is_a_503_not_a_401() {
    let key = TestKey::generate(KEY_ID);
    let (stub, auth, iss) = harness(&[key.jwk()]).await;
    let (capture, _guard) = LogCapture::install();

    // Proven warm, then the provider is removed entirely rather than made to
    // answer 500 — a refused connection and a 5xx take different paths.
    let warm = key.sign(&key.claims(&iss, AUDIENCE));
    auth.authenticate(&warm).await.expect("the warm key works");
    stub.stop();

    // Past `min_fetch_gap`, so this is allowed to try.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    // A token naming a key this issuer has not published, which is what forces
    // the refresh.
    let rotating = common::raw_token(
        &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "kid-rotating-in" }),
        &key.claims(&iss, AUDIENCE),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );

    let err = auth
        .authenticate(&rotating)
        .await
        .expect_err("the key is not here and never will be while the issuer is down");

    // This is the distinction the whole retry story rests on. `InvalidToken`
    // tells the client its credential is dead, and it will discard a token that
    // is waiting on a key one fetch away.
    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "the refresh failed, not the token: {err:?}"
    );
    assert!(err.retryable(), "the caller should retry unchanged");
    assert!(
        err.to_string().contains("kid-rotating-in"),
        "name the key that did not arrive: {err}"
    );

    // And the outage is in the log, at `warn`, with the reason. A path that
    // serves cached keys through an outage and leaves no trace looks exactly
    // like a healthy provider.
    let line = capture.only("JWKS refresh failed");
    assert_eq!(line.level, tracing::Level::WARN, "{}", capture.text());
    assert!(
        line.field("error").is_some_and(|error| !error.is_empty()),
        "the reason is the actionable half: {:?}",
        line.fields
    );
    assert_eq!(line.field("iss"), Some(iss.as_str()));

    // Already-held keys still verify, during the same outage.
    auth.authenticate(&warm)
        .await
        .expect("the cached key is still a valid public key");
}

// ── One unusable JWK must not cost the issuer its good keys. ────────────────

/// Every unusable shape a real provider publishes, in one document, beside a
/// key that works.
///
/// The assertion that matters is not that each is refused — it is that the
/// working key still authenticates afterwards. A provider publishes a
/// `use: enc` key during a routine change and every caller of that realm starts
/// getting `401` is the outage this guards.
#[tokio::test]
async fn unusable_jwks_are_skipped_and_the_good_key_still_works() {
    let good = TestKey::generate(KEY_ID);
    let (capture, _guard) = LogCapture::install();
    let published = vec![
        // No `kid` at all: it can never be selected, since selection is by
        // exact `kid` match.
        serde_json::json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "n": "AAA", "e": "AQAB" }),
        // An encryption key. Different key, different purpose. It must never
        // verify a signature whatever else is true about it.
        serde_json::json!({
            "kty": "RSA", "use": "enc", "kid": "enc-key", "alg": "RSA1_5",
            "n": good.jwk()["n"], "e": good.jwk()["e"],
        }),
        // A JWK whose common parameters are the wrong JSON type, so the whole
        // entry is unreadable.
        serde_json::json!({ "kty": "RSA", "kid": "wrong-type", "use": 42, "n": "AAA", "e": "AQAB" }),
        // Components that are present and nonsense: `try_from` cannot build a
        // key from a non-base64 modulus.
        serde_json::json!({
            "kty": "RSA", "use": "sig", "kid": "bad-components", "alg": "RS256",
            "n": "not base64 at all!!", "e": "AQAB",
        }),
        // A symmetric key. A `kty: oct` entry in the trust bundle is the HMAC leg
        // of algorithm confusion. So this skip is a security decision, not a
        // parse one.
        oct_jwk("symmetric-key"),
        good.jwk(),
    ];

    let (_stub, auth, iss) = harness(&published).await;

    // The good key authenticates: none of the above took the document down.
    let claims = auth
        .authenticate(&good.sign(&good.claims(&iss, AUDIENCE)))
        .await
        .expect("the one working key is enough");
    assert_eq!(claims.sub, "user-123");

    // And the crate reports every skipped key, so an operator can learn that it
    // ignores a published key. "We skipped it" is a safe default only while the
    // skip is visible.
    for (what, message) in [
        ("no `kid`", "skipping JWK with no `kid`"),
        ("`use: enc`", "skipping JWK with `use`: enc"),
        ("unreadable", "skipping unreadable JWK"),
        (
            "unreadable components",
            "skipping JWK with unreadable components",
        ),
        ("symmetric", "skipping JWK of unsupported key type"),
    ] {
        let lines = capture.matching(message);
        assert!(
            !lines.is_empty(),
            "the {what} JWK was skipped in silence:\n{}",
            capture.text()
        );

        // Every skip but the kid-less one names the `kid`. That name is the only
        // handle an operator can quote when reporting it to the provider.
        if what != "no `kid`" {
            assert!(
                lines
                    .iter()
                    .any(|line| line.field("kid").is_some_and(|kid| !kid.is_empty())),
                "the {what} skip should name the `kid` being dropped: {:?}",
                lines
            );
        }
    }
}

/// An `oct` JWK, with no `alg`: with one, the algorithm gate refuses the key
/// first and the test would prove nothing about the `kty` allowlist.
fn oct_jwk(kid: &str) -> serde_json::Value {
    serde_json::json!({
        "kty": "oct",
        "use": "sig",
        "kid": kid,
        "k": "c2hhcmVkLXN5bW1ldHJpYy1zZWNyZXQ",
    })
}
