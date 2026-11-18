//! Elliptic-curve keys: what an EC or Ed25519 issuer needs, and the boundary
//! that keeps accepting them from widening anything else.
//!
//! The outage these tests are written against is mundane. A Keycloak realm
//! rotates its realm key from RSA to EC, every token it issues becomes
//! `ES256`, and an RS256-only verifier rejects the realm in its entirety. That
//! is not a degradation. It is an auth outage. Signing goes through the same
//! RustCrypto implementations `jsonwebtoken` verifies with, so what these tests
//! pin is the part this crate owns: `kty`/`crv`/`x`/`y` becoming the right
//! `DecodingKey`, and `alg`/`iss`/`aud` still being enforced around it. They
//! are not an interoperability suite against other JWT libraries' signature
//! formats.
//!
//! The second half is the half that could have gone wrong quietly. Accepting
//! `kty: EC` means the JWKS reader now walks past key types it was written to
//! refuse. `DecodingKey::try_from` is not a gate: handed an `oct` JWK it
//! returns a working HMAC key, jsonwebtoken doing HMAC too. So the refusals
//! are tested as loudly as the acceptances. Symmetric keys stay out, `alg` is
//! still the only thing that picks an algorithm, EC is still opt-in, and RS256
//! is still the default.
//!
//! The third half is the bug these tests found. `jsonwebtoken` 12 rejects a
//! token unless every algorithm in `Validation::algorithms` belongs to the
//! family of the verifying key. So one `algorithms` list of `[RS256, ES256]`
//! rejected *every* token from a realm publishing both key types. A realm
//! mid-rotation is exactly that realm, and the outage only exists once EC is
//! configurable. That makes it invisible to an EC-only or RSA-only test. The
//! `a_realm_publishing_both_key_types_*` tests below are the regression cover,
//! and the refusals beside them pin that the per-key narrowing only ever
//! shrinks the algorithm set.

mod common;

use std::time::Duration;

use axum_oidc_middleware::{
    AuthConfig, AuthError, Authenticator, CachePolicy, Issuer, SignatureAlgorithm,
};
use common::{StubIssuer, TestKey, raw_token};
use jsonwebtoken::{Algorithm, EncodingKey, Header};

const AUDIENCE: &str = "myaudience";

/// base64url of `SECRET`, for the `oct` JWK and the HMAC token signed with it.
const OCT_K: &str = "c2hhcmVkLXN5bW1ldHJpYy1zZWNyZXQ";
const SECRET: &[u8] = b"shared-symmetric-secret";

struct Harness {
    stub: StubIssuer,
    auth: Authenticator,
    iss: String,
}

/// A stub issuer publishing exactly `published`, trusted with `algorithms`.
///
/// Takes raw JWKs rather than [`TestKey`]s. Most of these tests are about a
/// published JWK that is *not* the key's honest shape: an `oct` key, a `P-521`
/// curve, or an `alg` nobody configured. That document has to be there from the
/// first fetch. Republishing later would test nothing. The bundle from warm-up
/// is served for its whole TTL, so a key doctored after startup would never be
/// read.
async fn harness(published: &[serde_json::Value], algorithms: &[SignatureAlgorithm]) -> Harness {
    let stub = StubIssuer::start_local(&[]).await;
    stub.publish(published.to_vec());

    let iss = stub.iss();
    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(iss.clone(), [AUDIENCE]).expect("valid issuer"))
        .with_algorithms(algorithms.to_vec())
        // `min_fetch_gap` at 1s rather than the 10s default, so a test whose
        // `kid` is unknown waits a second for its refresh instead of ten.
        .with_policy(CachePolicy {
            min_fetch_gap: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            ..CachePolicy::default()
        })
        .with_insecure_http(true);

    let auth = Authenticator::start(config)
        .await
        .expect("start an authenticator against the stub issuer");

    Harness { stub, auth, iss }
}

/// An `oct` JWK with no `alg`.
///
/// The missing `alg` is deliberate. With one, the algorithm gate would refuse
/// this key first, and the test would prove nothing about the `kty` allowlist.
/// That allowlist is the gate that has to hold for a symmetric key.
fn oct_jwk(kid: &str) -> serde_json::Value {
    serde_json::json!({
        "kty": "oct",
        "use": "sig",
        "kid": kid,
        "k": OCT_K,
    })
}

/// A JWK with `alg` removed.
///
/// `alg` is optional on a JWK (RFC 7518 §4.4 / RFC 7515 §4.1.1), and `jwks`
/// only refuses a key whose `alg` is *present* and unconfigured. So stripping it
/// is the way to put a key of an unwanted family into the bundle on purpose,
/// past the JWK-level gate. That leaves the family intersection as the only
/// thing able to refuse it.
fn without_alg(mut jwk: serde_json::Value) -> serde_json::Value {
    if let Some(object) = jwk.as_object_mut() {
        object.remove("alg");
    }
    jwk
}

/// `HS256` keyed with a raw shared secret. This is the token a verifier
/// holding a symmetric key in its bundle would accept.
fn hs256_with_secret(kid: &str, claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_owned());
    header.typ = Some("JWT".to_owned());

    jsonwebtoken::encode(
        &header,
        claims,
        &EncodingKey::from_secret(SECRET).expect("an HMAC key from the shared secret"),
    )
    .expect("encode an HMAC token")
}

/// The signature segment of a compact JWS, to re-attach one to a payload that
/// nobody signed.
fn signature_of(token: &str) -> &str {
    token
        .rsplit('.')
        .next()
        .expect("a compact JWS has at least one segment")
}

// ── The curves work ──────────────────────────────────────────────────────────

#[tokio::test]
async fn an_es256_token_authenticates_when_es256_is_accepted() {
    let key = TestKey::generate_es256("ec-1");
    let h = harness(&[key.jwk()], &[SignatureAlgorithm::Es256]).await;

    let claims = h
        .auth
        .authenticate(&key.sign(&key.claims(&h.iss, AUDIENCE)))
        .await
        .expect("a P-256 JWK verifies an ES256 token");

    assert_eq!(claims.sub, "user-123");
    assert_eq!(claims.iss.as_str(), h.iss);
}

#[tokio::test]
async fn an_es384_token_authenticates_when_es384_is_accepted() {
    let key = TestKey::generate_es384("ec-384");
    let h = harness(&[key.jwk()], &[SignatureAlgorithm::Es384]).await;

    assert!(
        h.auth
            .authenticate(&key.sign(&key.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok(),
        "a P-384 JWK verifies an ES384 token"
    );
}

#[tokio::test]
async fn an_eddsa_token_authenticates_with_a_real_ed25519_signature() {
    // A real Ed25519 signature over the JWS signing input, verified against
    // the OKP JWK's single `x` coordinate. `EdDSA` is supported only because
    // this passes. A variant that could not be proven here would be a trap.
    let key = TestKey::generate_ed25519("ed-1");
    let h = harness(&[key.jwk()], &[SignatureAlgorithm::EdDSA]).await;

    let claims = h
        .auth
        .authenticate(&key.sign(&key.claims(&h.iss, AUDIENCE)))
        .await
        .expect("an OKP/Ed25519 JWK verifies an EdDSA token");

    assert_eq!(claims.sub, "user-123");

    // And a tampered payload still fails, so the accept above shows signature
    // verification working, not a verifier that forgot to look. Same header,
    // same signature, different `sub`.
    let honest = key.sign(&key.claims(&h.iss, AUDIENCE));
    let signature = signature_of(&honest).to_owned();
    let mut stolen = key.claims(&h.iss, AUDIENCE);
    stolen["sub"] = serde_json::json!("admin");
    let tampered = raw_token(
        &serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": "ed-1" }),
        &stolen,
        &signature,
    );
    assert!(
        h.auth.authenticate(&tampered).await.is_err(),
        "that signature is not over this payload"
    );
}

// ── Opt-in, and the families still cannot mix ────────────────────────────────

#[tokio::test]
async fn an_ec_token_is_refused_while_only_rs256_is_accepted() {
    // EC support is opt-in. A deployment that never names `ES256` must keep
    // refusing EC tokens after this support lands, or the change silently
    // widened every existing configuration.
    let rsa = TestKey::generate("rsa-1");
    let ec = TestKey::generate_es256("ec-1");
    let h = harness(&[rsa.jwk(), ec.jwk()], &[SignatureAlgorithm::Rs256]).await;

    assert!(
        h.auth
            .authenticate(&rsa.sign(&rsa.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok(),
        "the RSA half of the realm still works"
    );

    // The `kid` here is real and published. The refusal is the algorithm, and
    // it happens before the key is consulted. The JWK is refused twice over.
    // Its `alg` is `ES256`, which is not in the allowlist, so it never becomes
    // a key at all. That redundancy is the point.
    let err = h
        .auth
        .authenticate(&ec.sign(&ec.claims(&h.iss, AUDIENCE)))
        .await
        .expect_err("an ES256 token is not accepted by an RS256-only issuer");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn an_ec_public_key_is_not_an_hmac_secret() {
    // `rejects_hmac_confusion_forgery`, for the key type this change made
    // possible. An attacker who cannot forge an EC signature hands over an
    // `HS256` token signed with the issuer's *EC public key*. That key is public.
    // A verifier that let HMAC into the ring accepts it. This one has no HMAC key
    // to try and no HMAC algorithm it can be asked for.
    let key = TestKey::generate_es256("ec-1");
    let h = harness(&[key.jwk()], &[SignatureAlgorithm::Es256]).await;

    assert!(
        h.auth
            .authenticate(&key.sign(&key.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok(),
        "the honest token verifies, so the refusal below is a judgement and not an outage"
    );

    let forged = key.forge_hs256_with_public_key(&key.claims(&h.iss, AUDIENCE));
    let err = h
        .auth
        .authenticate(&forged)
        .await
        .expect_err("an EC public key is not a secret");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[test]
fn accepting_curves_did_not_widen_the_default_or_the_families() {
    // The compile-time half. EC and EdDSA are variants now, but the default is
    // still RS256 alone, so no existing deployment accepts an EC token by
    // upgrading this crate.
    let defaults = AuthConfig::empty();
    assert_eq!(
        defaults.algorithms,
        vec![SignatureAlgorithm::Rs256],
        "RS256 remains the only default algorithm"
    );
    assert_eq!(SignatureAlgorithm::default(), SignatureAlgorithm::Rs256);

    // Every accepted name is spelled as its JWS `alg`, in both directions,
    // because the JWKS reader compares these strings against a JWK's `alg`.
    for (name, expected) in [
        ("RS256", SignatureAlgorithm::Rs256),
        ("RS384", SignatureAlgorithm::Rs384),
        ("RS512", SignatureAlgorithm::Rs512),
        ("PS256", SignatureAlgorithm::Ps256),
        ("ES256", SignatureAlgorithm::Es256),
        ("ES384", SignatureAlgorithm::Es384),
        ("EdDSA", SignatureAlgorithm::EdDSA),
    ] {
        assert_eq!(SignatureAlgorithm::parse(name), Some(expected));
        assert_eq!(expected.jws_name(), name);
    }

    // What stays unnamed: the whole HMAC family, `none`, a case change, and
    // `ES512`/`PS384`/`PS512`. These are sound algorithms that have no variant
    // here. `ES512` has none because `jsonwebtoken` does ECDSA on P-256 and
    // P-384 only.
    for name in [
        "HS256", "HS384", "HS512", "none", "ES512", "PS384", "PS512", "es256", "Ed448", "",
    ] {
        assert_eq!(
            SignatureAlgorithm::parse(name),
            None,
            "`{name}` must not be configurable"
        );
    }
}

// ── Keys that must not enter the bundle ──────────────────────────────────────

#[tokio::test]
async fn an_oct_jwk_beside_a_real_key_is_skipped_not_trusted() {
    let key = TestKey::generate("rsa-1");
    // Warm-up reads this document: the symmetric key is refused, the RSA key
    // is kept, and the issuer starts. A strict parse of the whole `JwkSet`
    // would have failed here and taken the working key with it.
    let h = harness(
        &[oct_jwk("kid-oct"), key.jwk()],
        &[SignatureAlgorithm::Rs256],
    )
    .await;

    assert!(
        h.auth
            .authenticate(&key.sign(&key.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok(),
        "one unusable key in the document does not cost the issuer its usable ones"
    );

    // A token signed with the very secret that JWK publishes, naming that
    // JWK's `kid`: refused. There is no path from a JWK in the document to a
    // key this token can be verified against. That is the property the `kty`
    // allowlist exists to hold.
    let claims = key.claims(&h.iss, AUDIENCE);
    let err = h
        .auth
        .authenticate(&hs256_with_secret("kid-oct", &claims))
        .await
        .expect_err("a symmetric key is never a verifier's key");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn an_issuer_publishing_only_a_symmetric_key_refuses_to_start() {
    // The structural proof. `DecodingKey::try_from` turns this JWK into a
    // working HMAC key without complaint. So a JWKS reader that asked it rather
    // than an allowlist would start happily. It would then verify tokens against
    // a secret it could be talked into publishing. "No usable keys" is the only
    // answer that cannot be forged later.
    let stub = StubIssuer::start("https://identity.example", &[]).await;
    stub.publish(vec![oct_jwk("kid-oct")]);

    let config = AuthConfig::empty()
        .with_issuer(
            Issuer::with_jwks_url(stub.iss(), stub.jwks_url(), [AUDIENCE])
                .expect("build an issuer"),
        )
        .with_algorithms([SignatureAlgorithm::Rs256])
        .with_insecure_http(true);

    let err = Authenticator::start(config)
        .await
        .expect_err("an issuer with no asymmetric keys cannot authenticate anyone");
    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "expected no usable keys, got {err:?}"
    );
}

#[tokio::test]
async fn a_jwk_whose_alg_is_not_configured_never_becomes_a_key() {
    // A JWK's `alg` is the issuer's own claim about what a key is for. Here
    // the issuer labels an honest, usable P-256 key as `ES384` while this API
    // accepted `ES256` alone. So the key must not be in the bundle, even though
    // it would verify the token perfectly.
    let warm = TestKey::generate_es256("ec-warm");
    let key = TestKey::generate_es256("ec-1");
    let mut mislabelled = key.jwk();
    mislabelled["alg"] = serde_json::json!("ES384");

    let h = harness(&[warm.jwk(), mislabelled], &[SignatureAlgorithm::Es256]).await;

    // Control: the same algorithm, correctly labelled, works. So the refusal
    // below is the JWK's `alg` and nothing else.
    assert!(
        h.auth
            .authenticate(&warm.sign(&warm.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok(),
        "a correctly labelled ES256 key verifies"
    );

    let err = h
        .auth
        .authenticate(&key.sign(&key.claims(&h.iss, AUDIENCE)))
        .await
        .expect_err("a key labelled for an unconfigured algorithm is not trusted");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn an_ec_key_on_a_curve_no_accepted_algorithm_can_use_is_skipped() {
    // `jsonwebtoken` does ECDSA on P-256 and P-384, so there is no `ES512` to
    // name and a P-521 key could never verify anything. Refusing it by curve is
    // what makes a realm that rotated to P-521 log "unusable key type". The
    // alternative is a flood of bad signatures.
    let warm = TestKey::generate_es256("ec-warm");
    let p521 = TestKey::generate_es256("ec-p521");

    let h = harness(
        &[warm.jwk(), p521.jwk_with_crv("P-521")],
        &[SignatureAlgorithm::Es256],
    )
    .await;

    let err = h
        .auth
        .authenticate(&p521.sign(&p521.claims(&h.iss, AUDIENCE)))
        .await
        .expect_err("a P-521 key is not a key this crate can use");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn a_short_ed25519_jwk_is_refused_instead_of_crashing() {
    // jsonwebtoken 12's EdDSA verifier reads the key as `&bytes[..32]`, which
    // panics on a short slice. Remove the length gate from `convert_key` and
    // this test does not fail softly. It panics on the request path, inside
    // `decode`, for whichever token names that `kid`. A provider bug must not
    // become a crash in the authentication layer.
    let good = TestKey::generate_ed25519("ed-1");
    let truncated = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "kid": "ed-broken",
        "x": "c2hvcnQ", // base64url of `short`. Five bytes, not 32
    });

    let h = harness(&[truncated, good.jwk()], &[SignatureAlgorithm::EdDSA]).await;

    assert!(
        h.auth
            .authenticate(&good.sign(&good.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok(),
        "a malformed key next door does not break the working one"
    );

    let unsigned = raw_token(
        &serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": "ed-broken" }),
        &good.claims(&h.iss, AUDIENCE),
        "c2hvcnQ",
    );
    let err = h
        .auth
        .authenticate(&unsigned)
        .await
        .expect_err("a truncated OKP key is refused, not reached");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn a_realm_rotating_from_rsa_to_ec_keeps_working() {
    // This is the rotation the whole change exists for, end to end, in a
    // deployment that asked for both algorithms. The realm withdraws its RSA key
    // and publishes an EC one under a new `kid`. The old token stops working
    // because its key left the published set. Nothing stopped verifying. Before
    // EC support, the second half of this was an outage. The new key was skipped
    // with a debug line, and every token after it was a 401.
    let rsa = TestKey::generate("kid-rsa");
    let ec = TestKey::generate_es256("kid-ec");
    let h = harness(
        &[rsa.jwk()],
        &[SignatureAlgorithm::Rs256, SignatureAlgorithm::Es256],
    )
    .await;

    let old = rsa.sign(&rsa.claims(&h.iss, AUDIENCE));
    assert!(
        h.auth.authenticate(&old).await.is_ok(),
        "the RSA key works before the rotation"
    );

    // `min_fetch_gap` first: the unknown `kid` below must be allowed to fetch.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    // One swap. The RSA key is gone from the document, the EC key is in it.
    h.stub.rotate(std::slice::from_ref(&ec));

    let claims = h
        .auth
        .authenticate(&ec.sign(&ec.claims(&h.iss, AUDIENCE)))
        .await
        .expect("the EC key is picked up by the rotation refresh");
    assert_eq!(claims.sub, "user-123");

    assert!(
        h.auth.authenticate(&old).await.is_err(),
        "a withdrawn RSA key stops verifying once it leaves the set"
    );

    // `kid-ec` is now a trusted key, and it is still not a key that can answer
    // for `RS256`. Admitting EC keys did not make a `kid` stand in for any
    // algorithm it was not signed with.
    let wrong_family = raw_token(
        &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "kid-ec" }),
        &ec.claims(&h.iss, AUDIENCE),
        signature_of(&ec.sign(&ec.claims(&h.iss, AUDIENCE))),
    );
    assert!(
        h.auth.authenticate(&wrong_family).await.is_err(),
        "an EC key is not an RSA key wearing a different header"
    );
}

// ── One realm, several key families ──────────────────────────────────────────
//
// `jsonwebtoken` 12 requires every entry of `Validation::algorithms` to belong
// to the family of the key doing the verifying. So an issuer with both an RSA
// and an EC key cannot be served by one algorithm list. The verifier hands
// `decode` `configured ∩ family(selected key)`. These are the tests for both
// halves of that sentence. The intersection must open the realm back up, and it
// must not open anything else.

#[tokio::test]
async fn a_realm_publishing_both_key_types_verifies_both_token_types() {
    // The regression itself. Before the fix this rejected *both* tokens: the
    // RSA one because `ES256` sat in the algorithm list next to `RS256`, the
    // EC one because `RS256` sat next to `ES256`. A provider that publishes an
    // RSA and an EC JWK together was simply unreachable, and every request
    // failed with `InvalidAlgorithm`. Keycloak during a realm-key rotation is
    // such a provider, and plenty of providers are one permanently.
    let rsa = TestKey::generate("kid-rsa");
    let ec = TestKey::generate_es256("kid-ec");
    let h = harness(
        &[rsa.jwk(), ec.jwk()],
        &[SignatureAlgorithm::Rs256, SignatureAlgorithm::Es256],
    )
    .await;

    let rsa_claims = h
        .auth
        .authenticate(&rsa.sign(&rsa.claims(&h.iss, AUDIENCE)))
        .await
        .expect("an RS256 token verifies against the RSA key");
    assert_eq!(rsa_claims.sub, "user-123");

    let ec_claims = h
        .auth
        .authenticate(&ec.sign(&ec.claims(&h.iss, AUDIENCE)))
        .await
        .expect("an ES256 token verifies against the EC key, in the same process");
    assert_eq!(ec_claims.sub, "user-123");

    // Both still named the audience they had to name. Narrowing the algorithm
    // list per key must not have taken the rest of the rules with it.
    for claims in [rsa_claims, ec_claims] {
        assert_eq!(claims.iss.as_str(), h.iss);
    }
    let wrong_audience = h
        .auth
        .authenticate(&ec.sign(&ec.claims(&h.iss, "some-other-api")))
        .await;
    assert!(
        wrong_audience.is_err(),
        "a per-family algorithm list is still a full `Validation`"
    );
}

#[tokio::test]
async fn spanning_families_does_not_make_either_public_key_an_hmac_secret() {
    // The intersection is allowed to remove algorithms, never add them. The
    // forgery that would benefit is `HS256` keyed with a public key. With both
    // families configured, a verifier that narrowed wrongly has an RSA key *and*
    // an EC key in reach. Either would do the job.
    let rsa = TestKey::generate("kid-rsa");
    let ec = TestKey::generate_es256("kid-ec");
    let h = harness(
        &[rsa.jwk(), ec.jwk()],
        &[SignatureAlgorithm::Rs256, SignatureAlgorithm::Es256],
    )
    .await;

    // Both honest tokens first, so the refusals below are judgements about the
    // forged ones rather than a realm that never worked.
    assert!(
        h.auth
            .authenticate(&rsa.sign(&rsa.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok()
    );
    assert!(
        h.auth
            .authenticate(&ec.sign(&ec.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok()
    );

    let claims = rsa.claims(&h.iss, AUDIENCE);
    for forged in [
        rsa.forge_hs256_with_public_key(&claims),
        ec.forge_hs256_with_public_key(&claims),
    ] {
        let err = h
            .auth
            .authenticate(&forged)
            .await
            .expect_err("a public key is not a secret, whichever family it is from");
        assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    }
}

#[tokio::test]
async fn an_unconfigured_family_fails_closed_rather_than_verifying_anything() {
    // Two things have to hold when a token reaches a key whose family has
    // nothing configured. The request must be refused, and the refusal must say
    // *why*. The empty `algorithms` list that would otherwise reach
    // `jsonwebtoken` comes back as `MissingAlgorithm`, which reads like a hole
    // in the verifier's own configuration.
    //
    // `without_alg` is what makes this reachable at all. An `alg`-labelled EC
    // JWK is refused by `jwks` before it can be selected. So the only EC key in
    // an RS256-only bundle is one the issuer declined to label. That is legal,
    // and common enough in hand-rolled JWKS documents.
    let rsa = TestKey::generate("kid-rsa");
    let ec = TestKey::generate_es256("kid-ec");
    let h = harness(
        &[rsa.jwk(), without_alg(ec.jwk())],
        &[SignatureAlgorithm::Rs256],
    )
    .await;

    assert!(
        h.auth
            .authenticate(&rsa.sign(&rsa.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok(),
        "the RS256 half of the realm works, so the refusal below is a judgement"
    );

    // An `RS256` header naming the unlabelled EC key. The `alg` is configured,
    // so the pre-key gate passes and the key is really in the bundle. The
    // intersection is what has to stop it. `sign_with_alg` cannot build this,
    // since a P-256 key cannot sign `RS256`. So the token is assembled by hand
    // from the EC key's own signature, under a header that lies about it.
    let honest = ec.sign(&ec.claims(&h.iss, AUDIENCE));
    let mismatched = raw_token(
        &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "kid-ec" }),
        &ec.claims(&h.iss, AUDIENCE),
        signature_of(&honest),
    );
    let err = h
        .auth
        .authenticate(&mismatched)
        .await
        .expect_err("a key with nothing configured for its family verifies nothing");
    let reason = err.to_string();
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    assert!(
        reason.contains("cannot be used for any algorithm"),
        "the refusal must name the unusable key, not a validation accident: {reason}"
    );
    assert!(
        !reason.contains("MissingAlgorithm"),
        "an empty algorithm list must never reach `jsonwebtoken`: {reason}"
    );

    // And an ES256 token is refused too, one gate earlier. Opt-in did not
    // become implicit just because the key is now sitting in the bundle.
    let err = h
        .auth
        .authenticate(&ec.sign(&ec.claims(&h.iss, AUDIENCE)))
        .await
        .expect_err("ES256 is not accepted while only RS256 is configured");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[tokio::test]
async fn a_third_family_narrows_the_same_way() {
    // Three families, not two. An intersection written as an RSA/EC special
    // case fails in one of two ways. Either `EdDSA` is refused outright, or
    // `EdDSA` shares a list with an algorithm it cannot verify. Both are proven
    // false here, in both directions, with `RS256` still working beside it.
    let rsa = TestKey::generate("kid-rsa");
    let ed = TestKey::generate_ed25519("kid-ed");
    let h = harness(
        &[rsa.jwk(), ed.jwk()],
        &[SignatureAlgorithm::Rs256, SignatureAlgorithm::EdDSA],
    )
    .await;

    assert!(
        h.auth
            .authenticate(&rsa.sign(&rsa.claims(&h.iss, AUDIENCE)))
            .await
            .is_ok(),
        "RS256 still works once EdDSA is configured next to it"
    );

    let claims = h
        .auth
        .authenticate(&ed.sign(&ed.claims(&h.iss, AUDIENCE)))
        .await
        .expect("EdDSA verifies against the OKP key");
    assert_eq!(claims.sub, "user-123");

    // And the Ed key is not a general-purpose key now that three families are
    // configured. Same `kid`, same signature, a header for a family it does not
    // belong to.
    let honest = ed.sign(&ed.claims(&h.iss, AUDIENCE));
    let borrowed = raw_token(
        &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "kid-ed" }),
        &ed.claims(&h.iss, AUDIENCE),
        signature_of(&honest),
    );
    assert!(
        h.auth.authenticate(&borrowed).await.is_err(),
        "an Ed25519 key is not an RSA key"
    );
}
