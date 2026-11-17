//! OIDC discovery: what a malformed or dishonest document does to startup.
//!
//! `Authenticator::start` refuses to come up unless every issuer's document
//! says who it is and where its keys are. The alternative is a running server
//! that quietly trusts the wrong keys. Each test here hands the client one of
//! the documents a real deployment actually meets: a captive portal's HTML
//! where JSON should be, a realm whose metadata omits `issuer`, or a
//! `jwks_uri` that is a relative path. Each test asserts both that startup
//! fails and that the failure names the document it read. "Discovery failed"
//! with no URL is not actionable at 3am.

mod common;

use std::time::Duration;

use axum_oidc_middleware::{AuthConfig, AuthError, Authenticator, CachePolicy, Issuer};
use common::{StubIssuer, TestKey};

const AUDIENCE: &str = "myaudience";
const KEY_ID: &str = "k1";

/// A stub issuer and a config that trusts it, with the discovery document
/// still the stub's honest one. A test's override is then the only difference
/// between a start that works and one that does not.
async fn stub_and_config(keys: &[TestKey]) -> (StubIssuer, AuthConfig) {
    let stub = StubIssuer::start_local(keys).await;

    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(stub.iss(), [AUDIENCE]).expect("valid issuer"))
        .with_insecure_http(true)
        .with_policy(CachePolicy {
            timeout: Duration::from_secs(2),
            ..CachePolicy::default()
        });

    (stub, config)
}

/// Serve `document` in place of the discovery document, verbatim.
fn replace_document(stub: &StubIssuer, document: serde_json::Value) {
    stub.serve_discovery_body(document.to_string());
}

/// Start, expecting failure, and hand back the message for inspection.
async fn refusal(config: AuthConfig, why: &str) -> AuthError {
    Authenticator::start(config).await.expect_err(why)
}

// ── The provider could not be read ───────────────────────────────────────────

#[tokio::test]
async fn an_issuer_that_hangs_up_during_discovery_is_a_provider_failure() {
    // The connection is refused: nothing answered. This is distinct from the
    // 500 case below, and distinct from `InvalidToken`. Nobody sent anything
    // bad. We could not do our job. Conflating the two lets an outage read as
    // an attack, in the logs and in any alert built on them.
    let key = TestKey::generate(KEY_ID);
    let (stub, config) = stub_and_config(std::slice::from_ref(&key)).await;
    stub.stop();

    let err = refusal(config, "a dead issuer cannot be warmed").await;
    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "a refused connection is our dependency failing: {err:?}"
    );
    let reason = err.to_string();
    assert!(
        reason.contains("/.well-known/openid-configuration"),
        "the message should name the document it tried to read: {reason}"
    );
}

#[tokio::test]
async fn a_captive_portal_in_place_of_the_document_is_reported_as_unreadable() {
    // A `200` whose body is not JSON: the sign-in page a guest network serves
    // instead of the metadata it was asked for. The client reaches the URL, so
    // this is not an outage. The document is simply not a document.
    let key = TestKey::generate(KEY_ID);
    let (stub, config) = stub_and_config(std::slice::from_ref(&key)).await;
    stub.serve_discovery_body("<!doctype html><title>Sign in to continue</title>");

    let err = refusal(config, "HTML is not an OIDC document").await;
    assert!(matches!(err, AuthError::ProviderUnavailable(_)), "{err:?}");
    assert!(
        err.to_string().contains("unreadable JSON"),
        "say the document could not be read, rather than that the issuer is dead: \
         {err}"
    );
}

// ── The document is readable and unusable ────────────────────────────────────

/// `issuer` is REQUIRED by OIDC Discovery §3. A document without it is not a
/// document with an empty issuer. It is a document that does not say whose
/// keys its `jwks_uri` points at. Guessing is the confusion a multi-tenant
/// Keycloak makes easy.
#[tokio::test]
async fn a_document_with_no_issuer_refuses_to_boot_and_says_which_document() {
    let key = TestKey::generate(KEY_ID);
    let (stub, config) = stub_and_config(std::slice::from_ref(&key)).await;
    let jwks_url = stub.jwks_url();
    replace_document(&stub, serde_json::json!({ "jwks_uri": jwks_url.as_str() }));

    let err = refusal(
        config,
        "a document that does not identify its issuer cannot be trusted",
    )
    .await;

    // `Configuration`, not `ProviderUnavailable`: the provider is answering
    // correctly and what it publishes does not conform. Retrying changes
    // nothing. Someone has to fix the realm or the deployment.
    assert!(
        matches!(err, AuthError::Configuration(_)),
        "a non-conforming document is a deployment problem to be named: {err:?}"
    );
    let reason = err.to_string();
    assert!(
        reason.contains("has no `issuer`") && reason.contains(".well-known/openid-configuration"),
        "name the missing claim and the document that lacks it: {reason}"
    );
}

#[tokio::test]
async fn a_document_with_no_jwks_uri_refuses_to_boot() {
    // An issuer with no key location cannot verify anything, so a server that
    // booted with it would answer `401` forever and look like a token problem.
    let key = TestKey::generate(KEY_ID);
    let (stub, config) = stub_and_config(std::slice::from_ref(&key)).await;
    let iss = stub.iss();
    replace_document(&stub, serde_json::json!({ "issuer": iss }));

    let err = refusal(config, "no key location is no way to verify a token").await;
    assert!(matches!(err, AuthError::Configuration(_)), "{err:?}");
    assert!(
        err.to_string().contains("has no `jwks_uri`"),
        "name the missing claim: {err}"
    );
}

/// A `jwks_uri` that is not absolute is the same class of bug with a different
/// message. The message has to quote the value, because this is the field
/// somebody edited by hand.
#[tokio::test]
async fn a_relative_jwks_uri_is_refused_with_the_offending_value() {
    let key = TestKey::generate(KEY_ID);
    let (stub, config) = stub_and_config(std::slice::from_ref(&key)).await;
    let iss = stub.iss();
    replace_document(
        &stub,
        serde_json::json!({ "issuer": iss, "jwks_uri": "jwks.json" }),
    );

    let err = refusal(config, "a relative jwks_uri is nowhere to fetch").await;
    assert!(matches!(err, AuthError::Configuration(_)), "{err:?}");

    let reason = err.to_string();
    assert!(
        reason.contains("jwks.json") && reason.contains("not a URL"),
        "quote the value so the fix is obvious: {reason}"
    );
}

/// An empty `jwks_uri` is a document that is present, parses, and names no
/// key source. The crate has to reject it as a bad URL rather than resolve it
/// as a relative path against the issuer's own origin. That would silently
/// point the client at `<issuer>/` and read whatever came back.
#[tokio::test]
async fn an_empty_jwks_uri_is_not_resolved_against_the_issuer() {
    let key = TestKey::generate(KEY_ID);
    let (stub, config) = stub_and_config(std::slice::from_ref(&key)).await;
    let iss = stub.iss();
    replace_document(&stub, serde_json::json!({ "issuer": iss, "jwks_uri": "" }));

    let err = refusal(config, "an empty jwks_uri is not a location").await;
    assert!(
        matches!(err, AuthError::Configuration(_)),
        "the empty value is the misconfiguration, not a path to try: {err:?}"
    );
    assert!(
        err.to_string().contains("not a URL"),
        "`{iss}` published `\"jwks_uri\": \"\"`: {err}"
    );
}
