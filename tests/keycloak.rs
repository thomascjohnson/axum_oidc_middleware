//! Keycloak-shaped tokens: `aud: ["account"]`, client identified by `azp`.
//!
//! A stock Keycloak realm fills `aud` from the built-in `roles` client scope's
//! Audience Resolve mapper, which collects the clients the user holds client
//! roles on. For most realms that is just `account` — so `aud` is present and
//! mandatory-checkable, but identifies nothing about *this* API. The client
//! that actually asked for the token is in `azp`, which Keycloak always sets.
//!
//! The point of these tests is that `azp` narrows acceptance and never widens
//! it: a token can never get in by naming a trusted `azp` while failing `aud`.

mod common;

use std::time::Duration;

use axum_oidc_middleware::{AuthConfig, AuthError, Authenticator, CachePolicy, Issuer};
use common::{StubIssuer, TestKey};

const API_AUDIENCE: &str = "myaudience";
/// What a stock realm actually puts in `aud`.
const KEYCLOAK_DEFAULT_AUD: &str = "account";
const CLIENT: &str = "my-client";

/// Issuer, audiences, and authorised parties, all configurable.
async fn verifier(
    key: &TestKey,
    audiences: &[&str],
    authorized_parties: &[&str],
) -> (StubIssuer, Authenticator) {
    let stub = StubIssuer::start_local(std::slice::from_ref(key)).await;

    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(stub.iss()).expect("valid issuer"))
        .with_authorized_parties(authorized_parties.iter().copied())
        .with_insecure_http(true)
        .with_policy(CachePolicy {
            min_fetch_gap: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            ..CachePolicy::default()
        });
    // `fold` rather than a literal list: the ceiling is the one flat audience
    // set, and this suite varies it per test. One issuer, so it inherits that
    // whole ceiling — `azp`, not the audience layer, is what is under test.
    let config = audiences
        .iter()
        .fold(config, |config, aud| config.with_audience(*aud));

    let auth = Authenticator::start(config)
        .await
        .expect("start against the stub");
    (stub, auth)
}

/// A token shaped the way Keycloak shapes one: `aud` is the realm default,
/// `azp` names the client.
fn keycloak_token(key: &TestKey, iss: &str, aud: &str, azp: Option<&str>) -> String {
    let now = common::now();
    let mut claims = serde_json::json!({
        "exp": now + 3600,
        "iat": now,
        "jti": "8f2a6b0e-0d0d-4b1c-9b6a-1f2e3d4c5b6a",
        "iss": iss,
        "aud": [aud],
        "typ": "Bearer",
        "azp": azp,
        "sub": "kc-user-1",
        "realm_access": {"roles": ["user"]},
        "scope": "profile email",
        "email": "user@example.com",
        "email_verified": true,
    });

    // Keycloak omits `azp` for some grant types. Model that faithfully rather
    // than sending an explicit null.
    if azp.is_none() {
        claims.as_object_mut().expect("claims").remove("azp");
    }

    key.sign(&claims)
}

// ── The trap this option exists for ──────────────────────────────────────────

#[tokio::test]
async fn naming_the_api_as_the_audience_locks_out_a_stock_keycloak() {
    // Not a bug — the reason the option exists. The crate requires `aud` and
    // enforces it, and a stock realm never puts the API's name in it. So the
    // correct-looking configuration rejects every caller. This test shows the
    // failure before production does, which is what the `azp` option is for.
    let key = TestKey::generate("kc1");
    let (_stub, auth) = verifier(&key, &[API_AUDIENCE], &[]).await;
    let iss = _stub.iss();

    let err = auth
        .authenticate(&keycloak_token(
            &key,
            &iss,
            KEYCLOAK_DEFAULT_AUD,
            Some(CLIENT),
        ))
        .await
        .expect_err(&format!("aud=account does not name {}", API_AUDIENCE));

    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    assert!(
        auth.authorized_parties().is_empty(),
        "azp is not checked unless configured"
    );
}

// ── The supported configuration ──────────────────────────────────────────────

#[tokio::test]
async fn audience_account_plus_azp_admits_the_right_client() {
    // "This realm's default resource, requested by our client." Both claims
    // must hold, which is strictly narrower than either alone.
    let key = TestKey::generate("kc1");
    let (stub, auth) = verifier(&key, &[KEYCLOAK_DEFAULT_AUD], &[CLIENT]).await;
    let iss = stub.iss();

    let claims = auth
        .authenticate(&keycloak_token(
            &key,
            &iss,
            KEYCLOAK_DEFAULT_AUD,
            Some(CLIENT),
        ))
        .await
        .expect("the configured client is admitted");

    assert_eq!(claims.sub, "kc-user-1");
    assert_eq!(claims.azp.as_deref(), Some(CLIENT));
    assert_eq!(claims.aud, vec![KEYCLOAK_DEFAULT_AUD]);
}

#[tokio::test]
async fn another_client_with_the_same_audience_is_refused() {
    // The whole value of the check: `aud: ["account"]` is identical for both
    // clients, so `aud` alone cannot tell them apart at all.
    let key = TestKey::generate("kc1");
    let (stub, auth) = verifier(&key, &[KEYCLOAK_DEFAULT_AUD], &[CLIENT]).await;
    let iss = stub.iss();

    let intruder = keycloak_token(&key, &iss, KEYCLOAK_DEFAULT_AUD, Some("some-other-client"));
    let err = auth
        .authenticate(&intruder)
        .await
        .expect_err("another client's token must not open this API");

    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    let reason = err.to_string();
    assert!(
        reason.contains("azp"),
        "the refusal should say why: {reason}"
    );
}

#[tokio::test]
async fn azp_never_substitutes_for_the_audience() {
    // The invariant. Here the *right* client presents a token whose `aud` is
    // not the configured one. It must still fail. An implementation that
    // accepted "aud matches OR azp matches" would let this through. It would
    // then accept any token carrying a trusted name in either field.
    let key = TestKey::generate("kc1");
    let (stub, auth) = verifier(&key, &["a-different-api"], &[CLIENT]).await;
    let iss = stub.iss();

    let token = keycloak_token(&key, &iss, KEYCLOAK_DEFAULT_AUD, Some(CLIENT));
    let err = auth
        .authenticate(&token)
        .await
        .expect_err("a trusted azp cannot rescue a wrong aud");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");

    // And the converse: right audience, unconfigured client.
    let other = keycloak_token(&key, &iss, "a-different-api", Some("not-our-client"));
    assert!(
        auth.authenticate(&other).await.is_err(),
        "right aud, wrong azp: still refused"
    );
}

#[tokio::test]
async fn a_token_without_azp_is_refused_when_azp_is_configured() {
    // If absence skipped the check, a client whose tokens carry no `azp` would
    // be admitted by a control meant to constrain clients. Configuring a check
    // and having it bypassed by a missing claim is not a check.
    let key = TestKey::generate("kc1");
    let (stub, auth) = verifier(&key, &[KEYCLOAK_DEFAULT_AUD], &[CLIENT]).await;
    let iss = stub.iss();

    let err = auth
        .authenticate(&keycloak_token(&key, &iss, KEYCLOAK_DEFAULT_AUD, None))
        .await
        .expect_err("no `azp` must not slip past a configured `azp` check");

    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
    assert!(
        err.to_string().contains("no `azp`"),
        "the refusal should name the missing claim: {err}"
    );
}

#[tokio::test]
async fn unconfigured_azp_leaves_the_token_judged_on_aud_alone() {
    // The default, stated explicitly: with no `authorized_parties`, any client
    // whose token names the right audience is admitted.
    let key = TestKey::generate("kc1");
    let (stub, auth) = verifier(&key, &[KEYCLOAK_DEFAULT_AUD], &[]).await;
    let iss = stub.iss();

    for client in [CLIENT, "unrelated-client"] {
        assert!(
            auth.authenticate(&keycloak_token(
                &key,
                &iss,
                KEYCLOAK_DEFAULT_AUD,
                Some(client)
            ))
            .await
            .is_ok(),
            "`{client}` is admitted when azp is not constrained"
        );
    }
}

#[tokio::test]
async fn several_authorised_parties_are_all_accepted() {
    // A web client and a background worker both talking to this API, same
    // realm, same audience.
    let key = TestKey::generate("kc1");
    let (stub, auth) = verifier(&key, &[KEYCLOAK_DEFAULT_AUD], &["web", "worker"]).await;
    let iss = stub.iss();

    for client in ["web", "worker"] {
        assert!(
            auth.authenticate(&keycloak_token(
                &key,
                &iss,
                KEYCLOAK_DEFAULT_AUD,
                Some(client)
            ))
            .await
            .is_ok(),
            "`{client}` should be configured in"
        );
    }
    assert!(
        auth.authenticate(&keycloak_token(
            &key,
            &iss,
            KEYCLOAK_DEFAULT_AUD,
            Some("cron")
        ))
        .await
        .is_err(),
        "an unlisted client is still refused"
    );
}

// ── Interaction with the other checks ────────────────────────────────────────

#[tokio::test]
async fn azp_does_not_weaken_the_issuer_check() {
    // A correctly-shaped Keycloak token, right client, right audience shape,
    // signed by a key from an issuer nobody configured.
    let key = TestKey::generate("kc1");
    let (stub, auth) = verifier(&key, &[KEYCLOAK_DEFAULT_AUD], &[CLIENT]).await;

    let foreign = StubIssuer::start_local(std::slice::from_ref(&key)).await;
    let token = keycloak_token(&key, &foreign.iss(), KEYCLOAK_DEFAULT_AUD, Some(CLIENT));

    assert!(
        auth.authenticate(&token).await.is_err(),
        "a foreign issuer is refused regardless of a valid azp"
    );
    assert_eq!(auth.audiences(), vec![KEYCLOAK_DEFAULT_AUD.to_owned()]);
    drop(stub);
}

#[tokio::test]
async fn an_empty_authorised_party_is_a_configuration_error() {
    // `--azp ""` would be a check that can never pass: an outage dressed up as
    // a security control, and quiet about it.
    let bad = AuthConfig::empty()
        .with_issuer(Issuer::discover("https://identity.example").expect("valid issuer"))
        .with_authorized_parties([String::new()])
        .with_audience(API_AUDIENCE);

    assert!(
        matches!(
            bad.validate(),
            Err(AuthError::Configuration(reason)) if reason.contains("azp")
        ),
        "an empty azp must be rejected at startup"
    );

    // And an empty *list* means "not configured", which is valid. The test
    // spells it as an explicit empty builder call rather than omitting it,
    // because this test is about the empty state itself. The default from
    // `empty()` and an operator's "no clients restricted" must be the same
    // config.
    let fine = AuthConfig::empty()
        .with_issuer(Issuer::discover("https://identity.example").expect("valid issuer"))
        .with_authorized_parties(Vec::<String>::new())
        .with_audience(API_AUDIENCE);
    assert!(fine.validate().is_ok(), "no azp configured is fine");
}
