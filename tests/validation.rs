//! What the verifier accepts and refuses.
//!
//! Each test here is a property that a real multi-issuer deployment depends on.
//! Several are deliberately the attacks that an `iss`-unchecked or
//! `aud`-optional validator survives: an issuer you trust minting a token for
//! a *different* issuer, a token minted for a *different* client of the same
//! issuer, and `HS256` signed with the issuer's public key.

mod common;

use std::time::Duration;

use axum_oidc_middleware::{
    AuthConfig, AuthError, Authenticator, CachePolicy, Issuer, SignatureAlgorithm,
};
use common::{StubIssuer, TestKey, now, raw_token};

const AUDIENCE: &str = "my-audience";

/// `min_fetch_gap` is 1s here rather than the 10s default, so the rotation
/// test does not sleep for ten seconds waiting to be allowed to re-fetch.
fn fast_policy() -> CachePolicy {
    CachePolicy {
        min_fetch_gap: Duration::from_secs(1),
        timeout: Duration::from_secs(2),
        ..CachePolicy::default()
    }
}

/// A stub issuer and an `Authenticator` configured to trust exactly it.
struct Harness {
    stub: StubIssuer,
    auth: Authenticator,
    iss: String,
}

impl Harness {
    async fn start(keys: &[TestKey]) -> Self {
        // The stub reports itself as its own loopback URL, so discovery's
        // `issuer` matches the configured one and the client can reach both
        // endpoints over the network.
        let stub = StubIssuer::start_local(keys).await;
        let iss = stub.iss();
        let auth = Authenticator::start(config(vec![iss.clone()], None))
            .await
            .expect("start an authenticator against the stub issuer");

        Self { stub, auth, iss }
    }
}

/// One audience per issuer, for every issuer in `issuers`.
///
/// Each entry names its own audience as it is built: there is no ceiling to
/// inherit, so an issuer here is a complete statement of what it serves. These
/// tests are about *issuer* trust, so the audience is one constant for all of
/// them. That constant cannot be the reason a token fails.
fn config(issuers: Vec<String>, jwks_url: Option<url::Url>) -> AuthConfig {
    let issuers = issuers
        .iter()
        .map(|iss| match &jwks_url {
            Some(url) => Issuer::with_jwks_url(iss, url.clone(), [AUDIENCE]),
            None => Issuer::discover(iss, [AUDIENCE]),
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("build issuers");

    AuthConfig::empty()
        .with_issuers(issuers)
        .with_policy(fast_policy())
        .with_insecure_http(true)
}

// ── The happy path ───────────────────────────────────────────────────────────

#[tokio::test]
async fn accepts_a_token_from_a_discovered_issuer() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let claims = h
        .auth
        .authenticate(&key.sign(&key.claims(&h.iss, AUDIENCE)))
        .await
        .expect("a correctly signed token is accepted");

    assert_eq!(claims.iss, h.iss);
    assert_eq!(claims.sub, "user-123");
    assert_eq!(claims.aud, vec![AUDIENCE.to_owned()]);
    assert_eq!(
        claims.verified_email(),
        Some("user@example.com"),
        "a verified email is readable"
    );
    assert_eq!(
        claims.log_id(),
        format!("user-123@{}", h.iss),
        "logs qualify the subject by issuer"
    );
}

#[tokio::test]
async fn accepts_both_aud_shapes() {
    // Google sends `aud` as a string, RFC 9068 mandates an array. Both must
    // work, or one of the two providers is silently unusable.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let mut string_aud = key.claims(&h.iss, AUDIENCE);
    string_aud["aud"] = serde_json::json!(AUDIENCE);
    h.auth
        .authenticate(&key.sign(&string_aud))
        .await
        .expect("a string `aud` is accepted");

    let mut array_aud = key.claims(&h.iss, AUDIENCE);
    array_aud["aud"] = serde_json::json!([AUDIENCE, "another-client"]);
    let claims = h
        .auth
        .authenticate(&key.sign(&array_aud))
        .await
        .expect("an array `aud` is accepted");
    assert_eq!(claims.aud.len(), 2, "both audiences are preserved");
}

#[tokio::test]
async fn works_without_discovery_when_the_jwks_url_is_given() {
    let key = TestKey::generate("k1");
    let stub = StubIssuer::start(
        "https://identity.example/realms/sagaci",
        std::slice::from_ref(&key),
    )
    .await;

    let mut cfg = config(vec![stub.iss()], None);
    // Point straight at the keys, bypassing the discovery document entirely.
    cfg.issuers = vec![
        Issuer::with_jwks_url(stub.iss(), stub.jwks_url(), [AUDIENCE])
            .expect("build an issuer from a JWKS URL"),
    ];

    let auth = Authenticator::start(cfg)
        .await
        .expect("start without discovery");
    let iss = stub.iss();
    assert!(
        auth.authenticate(&key.sign(&key.claims(&iss, AUDIENCE)))
            .await
            .is_ok(),
        "a pinned JWKS URL authenticates the same tokens"
    );
}

// ── Issuer trust ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn rejects_a_token_from_an_untrusted_issuer() {
    // The core test. A token signed by a key we hold, but that claims a
    // different issuer, must fail. Without this rule, the middleware would
    // trust every issuer in the JWKS for every other one.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let err = h
        .auth
        .authenticate(&key.sign(&key.claims("https://evil.example", AUDIENCE)))
        .await
        .expect_err("an untrusted issuer is refused");

    assert!(
        matches!(err, AuthError::InvalidToken(_)),
        "expected a rejection, got {err:?}"
    );
}

#[tokio::test]
async fn rejects_one_trusted_issuers_key_bearing_anothers_name() {
    // Two real issuers, both trusted. A token signed by A that claims to
    // come from B must fail twice over. B's keys cannot verify A's
    // signature, and the verified `iss` does not match the selected bundle.
    let key_a = TestKey::generate("kid-a");
    let key_b = TestKey::generate("kid-b");

    let stub_a = StubIssuer::start_local(std::slice::from_ref(&key_a)).await;
    let stub_b = StubIssuer::start_local(std::slice::from_ref(&key_b)).await;
    let (iss_a, iss_b) = (stub_a.iss(), stub_b.iss());

    let auth = Authenticator::start(config(vec![iss_a.clone(), iss_b.clone()], None))
        .await
        .expect("start against both issuers");

    // Each issuer's own tokens work.
    auth.authenticate(&key_a.sign(&key_a.claims(&iss_a, AUDIENCE)))
        .await
        .expect("issuer A's own token is accepted");
    auth.authenticate(&key_b.sign(&key_b.claims(&iss_b, AUDIENCE)))
        .await
        .expect("issuer B's own token is accepted");

    // A's signature under B's name: refused.
    let forged = key_a.sign(&key_a.claims(&iss_b, AUDIENCE));
    assert!(
        auth.authenticate(&forged).await.is_err(),
        "A's key must not be able to speak for B"
    );

    // And A's signature naming B's `kid`, which forces the wrong key lookup.
    let forged_kid = key_a.sign(&key_a.claims(&iss_b, AUDIENCE));
    assert!(auth.authenticate(&forged_kid).await.is_err());

    // A valid token from a *third* issuer that is not configured at all.
    let stub_c = StubIssuer::start_local(std::slice::from_ref(&key_a)).await;
    let iss_c = stub_c.iss();
    assert!(
        auth.authenticate(&key_a.sign(&key_a.claims(&iss_c, AUDIENCE)))
            .await
            .is_err(),
        "an issuer that was never configured is refused"
    );
}

#[tokio::test]
async fn rejects_a_trailing_slash_difference_in_the_issuer() {
    // The middleware compares `iss` values exactly. A trailing slash makes a
    // different issuer. Quietly normalising that slash would let a neighbour
    // realm's tokens through.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    assert!(
        h.auth
            .authenticate(&key.sign(&key.claims(&format!("{}/", h.iss), AUDIENCE)))
            .await
            .is_err(),
        "`iss` with a trailing slash is a different issuer"
    );
}

#[tokio::test]
async fn discovery_naming_a_different_issuer_fails_at_startup() {
    // Configure one issuer, then have the document answer with another's
    // identity. Accepting it would trust the neighbour's keys silently. The
    // failure has to be at startup, not on the first request from a user.
    let key = TestKey::generate("k1");
    let stub = StubIssuer::start("https://victim.example/realms/other", &[key]).await;

    let err = Authenticator::start(config(vec![stub.base_url().to_owned()], None))
        .await
        .expect_err("a mismatched discovery document must not start");

    assert!(
        matches!(err, AuthError::Configuration(_)),
        "expected a configuration failure, got {err:?}"
    );
}

// ── Audience ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rejects_a_token_minted_for_another_client() {
    // Same issuer, same key, different audience: this is the token another
    // client of the same IdP legitimately holds. It is not ours.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let err = h
        .auth
        .authenticate(&key.sign(&key.claims(&h.iss, "some-other-service")))
        .await
        .expect_err("another client's token is refused");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn rejects_a_token_with_no_audience_at_all() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let mut claims = key.claims(&h.iss, AUDIENCE);
    claims.as_object_mut().expect("claims object").remove("aud");

    assert!(
        h.auth.authenticate(&key.sign(&claims)).await.is_err(),
        "a token that names no audience cannot be ours"
    );
}

#[test]
fn refusing_to_name_an_audience_is_a_configuration_error() {
    // The default must never turn audience verification off. An issuer that
    // names no audience is refused where it is built: there is no
    // deployment-wide list for it to inherit, so an empty set has no reading
    // other than "anything".
    let err = Issuer::discover("https://identity.example", Vec::<String>::new())
        .expect_err("no audience is not a valid configuration");
    assert!(matches!(err, AuthError::Configuration(_)), "{err:?}");
    assert!(
        err.to_string().contains("https://identity.example"),
        "the message must name the issuer that said nothing, not just say that \
         some audience is missing: {err}"
    );

    // An empty string is not an audience either, and that one is only visible
    // to `validate`: the set is non-empty, so the constructor has nothing to
    // object to.
    let blank = AuthConfig::empty()
        .with_issuer(Issuer::discover("https://identity.example", [""]).expect("valid issuer"))
        .with_insecure_http(false);
    assert!(blank.validate().is_err(), "an empty audience is rejected");
}

#[test]
fn a_lone_issuer_naming_no_audience_is_a_configuration_error() {
    // Used to be legal: with one issuer, an unspecified audience list meant
    // "whatever the deployment served". There is no deployment list to mean
    // that, so an empty list here has no reading except "anything", which is
    // the one thing this crate refuses to accept. It is refused for the only
    // issuer exactly as it is for the second one, and now at the same place: a
    // lone issuer naming nothing is a failed constructor, not a failed boot.
    let err = Issuer::discover("https://identity.example/realms/solo", Vec::<String>::new())
        .expect_err("naming no audience is not an issuer");

    assert!(
        matches!(
            err,
            AuthError::Configuration(ref reason)
                if reason.contains("names no audiences")
                    && reason.contains("https://identity.example/realms/solo")
        ),
        "{err:?}"
    );
}

// ── Algorithms ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn rejects_alg_none() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let unsigned = raw_token(
        &serde_json::json!({ "alg": "none", "typ": "JWT", "kid": "k1" }),
        &key.claims(&h.iss, AUDIENCE),
        "",
    );

    let err = h
        .auth
        .authenticate(&unsigned)
        .await
        .expect_err("an unsecured token is never accepted");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn rejects_hmac_confusion_forgery() {
    // The classic: re-sign as HS256 using the issuer's public key as the
    // secret. A verifier that accepts both families honours it, because the
    // "secret" is public. HMAC is unreachable here, so it cannot even be tried.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;
    let claims = key.claims(&h.iss, AUDIENCE);

    let forged = key.forge_hs256_with_public_key(&claims);
    let err = h
        .auth
        .authenticate(&forged)
        .await
        .expect_err("HS256 keyed with the public key is refused");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");

    // Same forgery keyed with the private key, to prove the rejection is the
    // algorithm and not merely a bad secret.
    assert!(
        h.auth
            .authenticate(&key.sign_with_alg(&claims, jsonwebtoken::Algorithm::HS256))
            .await
            .is_err(),
        "no HMAC token passes, whatever secret signed it"
    );
}

#[tokio::test]
async fn rejects_an_algorithm_outside_the_accepted_set() {
    // RS512 is a sound algorithm, but the config does not list it. The
    // middleware rejects the token. The middleware accepts an algorithm only
    // because the config lists it, not because it is asymmetric.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    assert!(
        h.auth
            .authenticate(&key.sign_with_alg(
                &key.claims(&h.iss, AUDIENCE),
                jsonwebtoken::Algorithm::RS512
            ))
            .await
            .is_err(),
        "an unconfigured algorithm is refused"
    );
}

#[tokio::test]
async fn every_algorithm_in_the_rsa_family_verifies_when_it_is_configured() {
    // The four `RS*`/`PS*` variants exist because `jsonwebtoken` can verify
    // them against an RSA JWK. Each one must reach the verifier as its own
    // algorithm, not as `RS256` by coincidence. A realm that moves from
    // PKCS#1 to PSS mid-flight must keep working, so the config trusts both
    // spellings at once. Each one verifies its own token here.
    let key = TestKey::generate("k1");
    let stub = StubIssuer::start_local(std::slice::from_ref(&key)).await;
    let iss = stub.iss();

    let auth = Authenticator::start(config(vec![iss.clone()], None).with_algorithms([
        SignatureAlgorithm::Rs256,
        SignatureAlgorithm::Rs384,
        SignatureAlgorithm::Rs512,
        SignatureAlgorithm::Ps256,
    ]))
    .await
    .expect("start with the whole RSA family");

    for algorithm in [
        jsonwebtoken::Algorithm::RS256,
        jsonwebtoken::Algorithm::RS384,
        jsonwebtoken::Algorithm::RS512,
        jsonwebtoken::Algorithm::PS256,
    ] {
        let token = key.sign_with_alg(&key.claims(&iss, AUDIENCE), algorithm);
        // Asserted, then read, so the only way this test can fail is the
        // assertion — which still carries the `AuthError` that refused.
        let outcome = auth.authenticate(&token).await;
        assert!(
            outcome.is_ok(),
            "{algorithm:?} is configured, so it must verify: {:?}",
            outcome.as_ref().err()
        );
        let claims = outcome.expect("asserted above");
        assert_eq!(claims.sub, "user-123", "{algorithm:?}");
    }

    // Widening inside a family does not widen past it: an EC token is still
    // refused, because no accepted algorithm names the EC family.
    let es256 = TestKey::generate_es256("ec1");
    assert!(
        auth.authenticate(&es256.sign(&es256.claims(&iss, AUDIENCE)))
            .await
            .is_err(),
        "the RSA family is not the EC family"
    );
}

#[test]
fn hmac_is_inexpressible_in_the_configuration() {
    // Not "discouraged" — there is no variant to select. This is the compile-time
    // half of the confusion defence.
    assert_eq!(
        SignatureAlgorithm::parse("HS256"),
        None,
        "HS256 cannot be configured"
    );
    assert_eq!(SignatureAlgorithm::parse("none"), None);
    assert_eq!(
        SignatureAlgorithm::parse("rs256"),
        None,
        "alg is case sensitive"
    );
    assert_eq!(
        SignatureAlgorithm::parse("RS256"),
        Some(SignatureAlgorithm::Rs256)
    );
}

// ── Signature and expiry ─────────────────────────────────────────────────────

#[tokio::test]
async fn rejects_a_tampered_payload() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let honest = key.sign(&key.claims(&h.iss, AUDIENCE));
    assert!(
        h.auth.authenticate(&honest).await.is_ok(),
        "the unmodified token must work, or this proves nothing"
    );

    let signature = honest.split('.').nth(2).expect("signature segment");

    // Same header, same signature — only the payload now claims a different
    // subject. The signature covered the *original* payload, so it cannot
    // match this one.
    let mut stolen = key.claims(&h.iss, AUDIENCE);
    stolen["sub"] = serde_json::json!("admin");

    let tampered = raw_token(
        // Rebuilt from what `TestKey::sign` puts in the header, rather than
        // round-tripping the base64url segment through a JSON parser.
        &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "k1" }),
        &stolen,
        signature,
    );

    let err = h
        .auth
        .authenticate(&tampered)
        .await
        .expect_err("a payload edited under a valid signature is refused");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn rejects_an_expired_token() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let mut expired = key.claims(&h.iss, AUDIENCE);
    // Well beyond the 30s leeway.
    expired["exp"] = serde_json::json!(now() - 60);

    let err = h
        .auth
        .authenticate(&key.sign(&expired))
        .await
        .expect_err("an expired token is refused even correctly signed");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

/// An `exp` that is present but not a number of seconds fails, and the
/// error names the claim.
///
/// The shape is `exp: -1`. That is a genuinely interesting boundary, not a
/// fuzzing artifact. `Claims.exp` is an `i64`, so *this* crate reads `-1`
/// happily and hands the token to `jsonwebtoken`. `jsonwebtoken` holds its
/// own copy of the claims, where `exp` is a `u64`, so it reports a value it
/// cannot represent as `MissingRequiredClaim`. That error kind covers
/// "absent" and "unreadable" at once. So the middleware rejects the token
/// and says the claim is missing, when in fact it is present. That is worth
/// pinning either way. The caller's fix is identical (your `exp` is not a
/// timestamp we can use). Also, the token must not reach the expiry step,
/// where `-1` would look like a token that expired in 1970.
///
/// This test rules out the failure a caller would not forgive. It makes no
/// sense to answer a broken `exp` with `ExpiredSignature`, because that
/// tells a client to refresh a token whose encoder is simply broken. Worse,
/// the middleware could accept the token, because a comparison of a signed
/// value against an unsigned epoch went the other way.
#[tokio::test]
async fn rejects_a_token_whose_expiry_is_not_a_number_of_seconds() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let mut claims = key.claims(&h.iss, AUDIENCE);
    claims["exp"] = serde_json::json!(-1_i64);

    let err = h
        .auth
        .authenticate(&key.sign(&claims))
        .await
        .expect_err("an `exp` of -1 is not a validity period");

    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    assert!(
        err.to_string().contains("exp"),
        "the refusal should name the claim, since that is the field the caller has \
         to fix: {err}"
    );
    assert!(
        !err.to_string().contains("expired"),
        "this token did not expire; its `exp` is unreadable, and the two answers ask \
         a caller for different things: {err}"
    );
}

#[tokio::test]
async fn rejects_a_token_outside_its_clock_skew() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let mut future = key.claims(&h.iss, AUDIENCE);
    future["nbf"] = serde_json::json!(now() + 3600);

    assert!(
        h.auth.authenticate(&key.sign(&future)).await.is_err(),
        "a token not yet valid is refused"
    );
}

// ── Keys ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rejects_an_unknown_kid_and_recovers_after_rotation() {
    let original = TestKey::generate("kid-1");
    let h = Harness::start(std::slice::from_ref(&original)).await;

    // A token naming a key the issuer has never published. The signature is
    // never even reached: key selection fails first, and there is no fallback
    // to "just try the one key we have".
    let unknown_kid = raw_token(
        &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "kid-does-not-exist" }),
        &original.claims(&h.iss, AUDIENCE),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    );
    assert!(
        h.auth.authenticate(&unknown_kid).await.is_err(),
        "a `kid` the issuer never published is refused"
    );

    // Now rotate for real: the old key is withdrawn and a new one appears. The
    // unknown `kid` triggers one refresh, after which the new key verifies.
    let rotated = TestKey::generate("kid-2");
    h.stub.rotate(std::slice::from_ref(&rotated));
    // Past `min_fetch_gap`, so the middleware lets the refresh reach the
    // network.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let claims = h
        .auth
        .authenticate(&rotated.sign(&rotated.claims(&h.iss, AUDIENCE)))
        .await
        .expect("the rotated key is picked up automatically");
    assert_eq!(claims.sub, "user-123");

    // The withdrawn key no longer verifies.
    assert!(
        h.auth
            .authenticate(&original.sign(&original.claims(&h.iss, AUDIENCE)))
            .await
            .is_err(),
        "a withdrawn key stops verifying once it leaves the published set"
    );
}

#[tokio::test]
async fn rejects_a_token_with_no_kid() {
    // Selecting a key requires `kid`. Trying every key instead is the fallback
    // this crate refuses to implement.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let token = key.sign(&key.claims(&h.iss, AUDIENCE));
    let signature = token.split('.').nth(2).expect("signature segment");

    let no_kid = raw_token(
        &serde_json::json!({ "alg": "RS256", "typ": "JWT" }),
        &key.claims(&h.iss, AUDIENCE),
        signature,
    );

    assert!(
        h.auth.authenticate(&no_kid).await.is_err(),
        "without a `kid` there is no key to check against"
    );
}

#[tokio::test]
async fn ignores_unusable_key_types_but_keeps_the_usable_ones() {
    // A `use: enc` key and a symmetric `oct` key published alongside the real
    // signing key must not break verification, and must never be used for it.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let mut encryption = key.jwk();
    encryption["use"] = serde_json::json!("enc");
    encryption["kid"] = serde_json::json!("kid-enc");

    h.stub.publish(vec![
        encryption,
        serde_json::json!({"kty": "oct", "kid": "kid-oct", "k": "c2VjcmV0"}),
        key.jwk(),
    ]);

    let tok = key.sign(&key.claims(&h.iss, AUDIENCE));
    assert!(
        h.auth.authenticate(&tok).await.is_ok(),
        "one good key among junk keys still authenticates"
    );
}

#[tokio::test]
async fn an_issuer_publishing_only_unusable_keys_refuses_to_start() {
    let key = TestKey::generate("k1");
    let stub = StubIssuer::start("https://identity.example", std::slice::from_ref(&key)).await;

    let mut cfg = config(vec![stub.iss()], Some(stub.jwks_url()));
    cfg.issuers = vec![
        Issuer::with_jwks_url(stub.iss(), stub.jwks_url(), [AUDIENCE]).expect("build an issuer"),
    ];

    stub.publish(vec![key.jwk_with_kty("EC")]);

    let err = Authenticator::start(cfg)
        .await
        .expect_err("an issuer with no RSA keys cannot authenticate anyone");
    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "expected no usable keys, got {err:?}"
    );
}

// ── Provider availability ────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreachable_issuer_at_startup_is_not_a_token_failure() {
    // A live issuer answers 500. The middleware reaches discovery, and
    // discovery fails.
    let stub = StubIssuer::start_local(&[]).await;
    stub.set_failing(true);

    let err = Authenticator::start(config(vec![stub.base_url().to_owned()], None))
        .await
        .expect_err("start-up must not succeed with no keys");

    // Distinct from InvalidToken: nobody sent a bad token, we could not do our
    // job. Conflating them would let an outage read as an attack in the logs.
    assert!(matches!(err, AuthError::ProviderUnavailable(_)), "{err:?}");
}

#[tokio::test]
async fn serves_cached_keys_through_an_outage() {
    // Warm the cache, then take the issuer down. Already-valid tokens keep
    // working. The keys we hold are still valid public keys. Also, logging
    // every signed-in user out during a Keycloak blip is the worse failure.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;
    let token = key.sign(&key.claims(&h.iss, AUDIENCE));

    assert!(h.auth.authenticate(&token).await.is_ok(), "warm");

    h.stub.set_failing(true);
    // Past `min_fetch_gap` so a refresh is actually attempted and fails.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    assert!(
        h.auth.authenticate(&token).await.is_ok(),
        "an issuer outage must not reject tokens verified by cached keys"
    );

    h.stub.set_failing(false);
    assert!(h.auth.authenticate(&token).await.is_ok(), "recovery");
}

#[tokio::test]
async fn rejects_a_malformed_token_without_panicking() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    for junk in [
        "",
        "   ",
        "not-a-jwt",
        "a.b",
        "a.b.c.d",
        "!!!.###.$$$",
        &base64_invalid(),
    ] {
        let result = h.auth.authenticate(junk).await;
        assert!(
            matches!(
                result,
                Err(AuthError::InvalidToken(_) | AuthError::MissingToken)
            ),
            "`{junk}` should be refused cleanly, got {result:?}"
        );
    }
}

/// Three segments, none of which is valid base64url.
fn base64_invalid() -> String {
    "@@@@.####.$@@@".to_owned()
}

/// A token that parses as a JWS and carries an accepted `alg`, but whose
/// payload is not JSON — base64url-decodes to bytes that no parser can read.
fn unparseable_payload(iss: &str) -> String {
    use base64::Engine as _;
    let encode = |bytes: &[u8]| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(bytes)
            .to_owned()
    };

    let header = encode(
        &serde_json::to_vec(&serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "k1" }))
            .expect("serialise a header"),
    );
    // Decodes cleanly as base64url, but is nothing a payload can be. `iss` is
    // present in the text so a client reading the refusal can tell which
    // issuer they aimed at.
    let _ = iss;
    let payload = encode(b"issuer=https://x.example:not-json");

    format!("{header}.{payload}.AAAA")
}

#[tokio::test]
async fn rejects_a_token_that_names_no_issuer_before_choosing_a_trust_bundle() {
    // Gate 2 selects which issuer's keys to try, from the unverified `iss`.
    // Gate 2 cannot route a token that carries no `iss`. That answer also
    // differs from "untrusted issuer". The first means the token identifies
    // nobody. The second means it identifies someone this server does not
    // trust.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let mut claims = key.claims(&h.iss, AUDIENCE);
    claims.as_object_mut().expect("claims object").remove("iss");

    let err = h
        .auth
        .authenticate(&key.sign(&claims))
        .await
        .expect_err("a token that names no issuer cannot be routed to a key");

    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    assert!(
        err.to_string().contains("no `iss` claim"),
        "the refusal should say the claim is absent, not that it is wrong: {err}"
    );
}

#[tokio::test]
async fn rejects_a_payload_that_is_not_json_as_unreadable() {
    // The middleware must read the payload unverified, to pick a trust
    // bundle. A parser that accepts anything, or no parser at all, hides
    // what a garbage segment is. It reports a mysterious signature failure
    // instead.
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let err = h
        .auth
        .authenticate(&unparseable_payload(&h.iss))
        .await
        .expect_err("a payload that is not JSON verifies nothing");

    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    assert!(
        err.to_string().contains("unreadable JWT payload"),
        "say the payload could not be read, rather than failing later and more \
         mysteriously: {err}"
    );
}

/// A token signed by the trusted key and missing one of the claims this API
/// cannot decide without.
///
/// The middleware needs those fields to reach `Claims` at all, so a missing
/// claim surfaces as a read failure. That is worth pinning. The other
/// reading of "the payload was unreadable" is "the issuer is broken". But
/// the caller's token is the thing that is short.
#[tokio::test]
async fn rejects_a_validly_signed_token_that_omits_a_required_claim() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    for claim in ["aud", "exp"] {
        let mut claims = key.claims(&h.iss, AUDIENCE);
        claims.as_object_mut().expect("claims object").remove(claim);

        let err = h
            .auth
            .authenticate(&key.sign(&claims))
            .await
            .expect_err("`{claim}` is not optional here");

        assert!(
            matches!(err, AuthError::InvalidToken(_)),
            "{claim}: {err:?}"
        );
        assert!(
            err.to_string().contains(claim),
            "the refusal should name the claim that is missing, got: {err}"
        );
    }
}

#[tokio::test]
async fn reports_the_issuers_it_will_accept() {
    // When the middleware rejects a token from an issuer, the operator asks
    // this accessor one question: is this issuer even configured? So an
    // empty or wrong list here reports a configuration problem. The list
    // must reflect the config. It must not name only the issuers whose keys
    // the middleware happened to use.
    let first = TestKey::generate("k1");
    let second = TestKey::generate("k2");
    let h = Harness::start(&[first.clone(), second.clone()]).await;

    let issuers: Vec<&str> = h.auth.issuers().collect();
    assert_eq!(
        issuers,
        vec![h.iss.as_str()],
        "one configured issuer, reported once, whatever its keys were used for"
    );

    // And a two-issuer deployment reports both — the accessor is worth nothing
    // if it quietly drops one.
    let one = StubIssuer::start_local(std::slice::from_ref(&first)).await;
    let two = StubIssuer::start_local(std::slice::from_ref(&second)).await;
    let both = Authenticator::start(config(vec![one.iss(), two.iss()], None))
        .await
        .expect("start with two issuers");

    let mut reported: Vec<String> = both.issuers().map(str::to_owned).collect();
    reported.sort();
    assert_eq!(reported, {
        let mut expected = vec![one.iss(), two.iss()];
        expected.sort();
        expected
    });
}

// ── Critical header parameters (RFC 7515 §4.1.11) ───────────────────────────

/// The middleware enforces `crit` *before* the signature. That is the only
/// order that satisfies RFC 7515 §4.1.11.
///
/// The signature here is deliberately **not** valid for this header.
/// `raw_token` splices a fresh header onto a signature taken from a token
/// whose header had no `crit`, and a JWS signature covers the header too.
/// That is not sloppiness, it is the point. The two assertions only hold if
/// the middleware consults `crit` first. A verifier that ignores `crit`
/// reports `InvalidSignature`. Only a gate ahead of `decode` can produce a
/// reason naming "critical". So this test cannot go green by accident of a
/// bad signature, which is what a bare `matches!(err, InvalidToken(_))`
/// assertion would have done.
///
/// `crit_is_refused_even_over_a_valid_signature` covers the converse: a
/// token that is valid in every other respect. Both orders and both
/// signature states need pinning. §4.1.11 forbids honouring the extension
/// either way, and only the second case is what a real IdP adding `crit`
/// would send.
#[tokio::test]
async fn a_token_requiring_an_unhandled_critical_header_is_refused() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let honest = key.sign(&key.claims(&h.iss, AUDIENCE));
    let signature = honest.split('.').nth(2).expect("signature segment");

    let demanding = raw_token(
        &serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": "k1",
            "crit": ["https://example.invalid/tenant-binding"],
        }),
        &key.claims(&h.iss, AUDIENCE),
        signature,
    );

    let err = h
        .auth
        .authenticate(&demanding)
        .await
        .expect_err("a critical extension nothing implements cannot be honoured");
    assert!(
        matches!(err, AuthError::InvalidToken(_)),
        "refusing to honour a critical extension is about this token, not the \
         provider: {err:?}"
    );
    assert!(
        err.to_string().contains("critical"),
        "the refusal must say why, or an operator debugs a perfectly valid \
         signature with no clue: {err:?}"
    );
}

/// The ordering test cannot make this case. The token is **valid in every
/// other respect**, genuinely signed by a trusted key, and it merely demands
/// an extension nothing here implements.
///
/// This is the shape that reaches a running server in anger or in earnest. An
/// IdP that starts emitting `crit` after an upgrade produces it. So does an
/// attacker who holds a valid signature and wants to know whether this crate
/// honours a critical demand. The signature cannot save us here, because
/// nothing is wrong with the signature. Only the gate at 1b rejects it, and
/// only this test would notice if that gate ever stopped firing.
#[tokio::test]
async fn crit_is_refused_even_over_a_valid_signature() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    // Signed *with* `crit` in the header, so the signature covers it and the
    // token verifies cleanly up to the critical gate.
    let demanding = key.sign_with_header(
        &key.claims(&h.iss, AUDIENCE),
        serde_json::json!({
            "crit": ["https://example.invalid/tenant-binding"],
            "https://example.invalid/tenant-binding": "tenant-7",
        }),
    );

    // Verify the premise first, because the test is worthless if it goes green
    // for the same accidental reason the reviewer suspected. The header must
    // differ from the honest one, so the signatures differ. The payload must
    // not.
    let honest = key.sign(&key.claims(&h.iss, AUDIENCE));
    assert_ne!(
        honest.split('.').next().expect("header segment"),
        demanding.split('.').next().expect("header segment"),
        "identical headers would make these the same token and the test vacuous"
    );

    let err = h
        .auth
        .authenticate(&demanding)
        .await
        .expect_err("a valid signature does not licence an unhandled critical demand");
    assert!(
        matches!(err, AuthError::InvalidToken(_)),
        "this is about the token, not the provider: {err:?}"
    );
    assert!(
        err.to_string().contains("critical"),
        "must refuse *because of* `crit`; anything else means the signature or \
         some other gate answered first, and this test would be measuring that \
         instead: {err:?}"
    );
}

/// This is the other half of §4. It is also why the gate keys on `crit`
/// rather than on an allowlist of header members. Unknown members that are
/// *not* marked critical MUST be ignored. Rejecting those would break every
/// IdP that adds a private parameter, and Keycloak and several proxies do.
/// That would make this crate unusable rather than strict.
#[tokio::test]
async fn an_unknown_but_non_critical_header_parameter_is_still_accepted() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let with_private = key.sign_with_header(
        &key.claims(&h.iss, AUDIENCE),
        serde_json::json!({
            "keyid": "an-idp-private-member",
            "https://example.invalid/scope-version": 3,
        }),
    );

    let claims = h
        .auth
        .authenticate(&with_private)
        .await
        .expect("unrecognised members not listed in `crit` MUST be ignored");
    assert_eq!(claims.sub, "user-123");
}

/// An empty `crit` array declares a critical demand and names no header to
/// honour it. `jsonwebtoken` 12 refuses it inside `decode`. This crate refuses
/// it one step earlier, so the reason names `crit` instead of reporting a bare
/// validation failure.
#[tokio::test]
async fn an_empty_crit_array_is_refused_by_name() {
    let key = TestKey::generate("k1");
    let h = Harness::start(std::slice::from_ref(&key)).await;

    let empty_crit = key.sign_with_header(
        &key.claims(&h.iss, AUDIENCE),
        serde_json::json!({ "crit": [] }),
    );

    let err = h
        .auth
        .authenticate(&empty_crit)
        .await
        .expect_err("a `crit` that names nothing is a malformed critical header");
    assert!(
        err.to_string().contains("empty `crit`"),
        "the refusal must name the header that caused it: {err}"
    );
}

// Malformed `crit` shapes are deliberately NOT tested, and the reason is worth
// recording so the gap does not read as an oversight.
//
// A non-array `crit` cannot be minted at all. `Header` deserialises `crit` as
// `Option<Vec<String>>`, so `{"crit": "alg"}` fails to parse. My first attempt
// at this test died inside the test helper, on exactly the `Deserialize` impl
// `decode_header` uses. The fail-closed behaviour is therefore structural,
// not behavioural. The same code path that reads `crit` will not invent a
// value for a malformed one, and Gate 1 swallows that error into
// `InvalidToken`.
//
// To test it meaningfully, the token would need a *valid signature* over a
// header `Header` cannot deserialise. That means hand-signing the signing
// input instead of going through `encode`. It would add a new crypto
// dependency for a case the type system already rules out. A test that merely
// asserted "some error" would be vacuous: `InvalidSignature` answers it too,
// which is precisely the mistake this round exists to avoid.

/// A genuinely signed token can carry a flood of audiences. The middleware
/// must reject it with a short message, not a wall of text in the log and the
/// response header.
///
/// The signature is valid and the middleware trusts the issuer, so this is
/// not the forgery case the earlier dismissal addressed. It is a registered
/// client asking an honest IdP for many RFC 8707 resource indicators, and
/// the IdP signs them happily. `aud.join(", ")` would have allocated the
/// whole list and then handed it to `AuthError`'s `Display`, which logs it in
/// full.
#[tokio::test]
async fn a_flood_of_audiences_produces_a_bounded_refusal() {
    let key = TestKey::generate("k1");
    let stub = StubIssuer::start_local(std::slice::from_ref(&key)).await;
    let iss = stub.iss();

    // Some *other* issuer is trusted for `other-api`, which puts it in the union
    // that `jsonwebtoken` checks. This issuer is trusted for only one audience,
    // so a token bearing the other clears that first gate and lands on the
    // per-issuer set, which is where the refusal and the message come from.
    // Name `other-api` nowhere and the first gate refuses the token instead,
    // and this test measures the wrong refusal.
    let other_key = TestKey::generate("k2");
    let other_stub = StubIssuer::start_local(std::slice::from_ref(&other_key)).await;

    let auth = Authenticator::start(
        AuthConfig::empty()
            .with_issuers([
                Issuer::discover(&iss, ["my-audience"]).expect("issuer"),
                Issuer::discover(other_stub.iss(), ["other-api"]).expect("the other issuer"),
            ])
            .with_policy(fast_policy())
            .with_insecure_http(true),
    )
    .await
    .expect("start");

    // Must *include* `other-api`: that is in the union but not this issuer's own
    // set. That is what carries the token past jsonwebtoken's union rule and onto
    // the per-issuer set where this message is built. A flood of only unknown
    // audiences never reaches that far — jsonwebtoken refuses it first.
    let mut claims = key.claims(&iss, "other-api");
    let mut flooded: Vec<String> = (0..499)
        .map(|n| format!("resource-indicator-{n:0>4}"))
        .collect();
    flooded.insert(0, "other-api".to_owned());
    claims["aud"] = serde_json::json!(flooded);
    let token = key.sign(&claims);

    let err = auth
        .authenticate(&token)
        .await
        .expect_err("the issuer is not trusted for any of these");
    let reason = err.to_string();

    assert!(
        reason.contains("+497 more"),
        "the count is the diagnostic; the list is not: {reason}"
    );
    assert!(
        reason.len() < 400,
        "a 500-audience refusal must not be {} bytes into the log and the \
         response header: {reason}",
        reason.len()
    );
    assert!(
        !reason.contains("resource-indicator-0100"),
        "only the first three may appear: {reason}"
    );
}

/// The `min_fetch_gap` floor is flood control, and until now nothing pinned it.
///
/// A token naming an unknown `kid` is what triggers a JWKS refresh, and the
/// `kid` is attacker-chosen and unsigned. So without a floor on the gap, one
/// forged token per request turns this service into a traffic amplifier aimed at
/// its own identity provider. The damage lands on the IdP. That provider serves
/// every other client, not just this one. That is why the bound is a startup
/// failure rather than something to notice in a dashboard later.
///
/// What made the absence worth closing is how it was discovered. The gap was
/// lowered to 100ms to make this suite faster, and **every test still passed**
/// until the config rule caught it at `Authenticator::start`. Every harness here
/// sets the gap to exactly the floor, so deleting the rule entirely would have
/// left the whole suite green. The change that removes flood control arrives
/// looking like a test-speed tweak. A rate limit whose only protection is a
/// comment in `config.rs` is a rate limit that outlives its comment.
///
/// Tested at the boundary itself, 999ms against 1s. The difference between `<`
/// and `<=` is the entire content of the rule, and the suite's own helpers sit
/// exactly on it. A `<=` typo would take the harnesses down with it, and an
/// off-by-one in the other direction would silently admit sub-second gaps.
#[test]
fn a_refresh_gap_under_the_flood_floor_is_refused() {
    let config = |gap: Duration| {
        AuthConfig::empty()
            .with_issuer(
                Issuer::discover("https://idp.example.com", [AUDIENCE]).expect("valid issuer"),
            )
            .with_policy(CachePolicy {
                min_fetch_gap: gap,
                ..CachePolicy::default()
            })
    };

    // Below the floor: refused, and named, so an operator changing it learns
    // which knob they pushed rather than reading a list of unrelated problems.
    let refused = config(Duration::from_millis(999))
        .validate()
        .expect_err("999ms is under the 1s floor");
    let reason = refused.to_string();
    assert!(
        reason.contains("min_fetch_gap"),
        "the refusal must name the setting, or the fix is guesswork: {reason}"
    );
    assert!(
        matches!(refused, AuthError::Configuration(_)),
        "this is a misconfiguration at start-up, not a runtime fault: {refused:?}"
    );

    // At the floor: accepted. This half is what a `<`/`<=` slip breaks, and it
    // is also what every harness in this suite depends on.
    config(Duration::from_secs(1))
        .validate()
        .expect("the floor itself must be usable");
}
