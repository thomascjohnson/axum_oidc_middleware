//! Per-issuer audiences: which issuer is allowed to vouch for which audience.
//!
//! Before audiences were per issuer, [`AuthConfig::with_audience`] built one
//! flat list handed to `Validation::set_audience` for every issuer at once. In
//! a two-issuer deployment that made the audience set a property of the
//! *verifier* rather than of the issuer that signed the token. So any trusted
//! issuer could vouch for any audience this verifier served: issuer A's key,
//! issuer B's `aud`, accepted. Multi-tenant, that is a token minted for one
//! customer's tool authenticating as another customer's. It is not a
//! degradation and it does not log. The signature is real, the audience is
//! real, only the pairing is one nobody chose.
//!
//! So `aud` is now decided in two gates in series. These tests prove that both
//! gates are necessary and that neither one stands in for the other:
//!
//! * the **ceiling** (`AuthConfig::audiences`), verified inside `decode` by
//!   `jsonwebtoken`, over every token from any issuer.
//! * the **per-issuer layer** (`Issuer::audience`), verified by
//!   [`Authenticator::authenticate`] *after* the signature, once the issuer
//!   that actually signed is a verified fact rather than an unverified claim.
//!
//! A token has to clear both, so what is accepted is `ceiling ∩ layer`. The
//! headline test therefore names an audience that *is* in the ceiling. The
//! ceiling says yes, and only the per-issuer layer is left standing between
//! issuer A's key and issuer B's API. Its refusal wording is asserted as well,
//! because "refused" is not the finding. "Refused by the gate under test" is.
//! Both gates answer `AuthError::InvalidToken`, so the variant alone cannot
//! tell them apart, and a test that only verified the variant would pass with
//! the hole wide open.
//!
//! The other half is that none of this moved. A lone issuer with no per-issuer
//! list still boots and authenticates exactly as before. The layer is keyed
//! by the *verified* issuer rather than the claimed one, so a key cannot be
//! pointed at another issuer's narrower set by naming it.

mod common;

use std::time::Duration;

use axum_oidc_middleware::{AuthConfig, AuthError, Authenticator, CachePolicy, Issuer};
use common::{StubIssuer, TestKey};

/// What issuer A is trusted for.
const AUD_A: &str = "my-api";
/// What issuer B is trusted for. This is also the point of the headline test.
/// It is in the ceiling, so a token naming it clears the global gate from
/// *any* issuer. Only A's own list can refuse it.
const AUD_B: &str = "billing-api";
/// In no ceiling and in no issuer's list: refused by the global gate.
const AUD_OUTSIDE: &str = "someone-elses-api";

/// The client an `azp` names, and a second one that must not be admitted by it.
const CLIENT: &str = "my-client";
const OTHER_CLIENT: &str = "reporting-client";

/// The wording of the per-issuer layer's refusal, inside
/// [`Authenticator::authenticate`].
///
/// Matched as a string because *which gate refused* is the finding here. Both
/// audience gates answer `InvalidToken`. Only the layer says "is not an
/// audience issuer `…` is trusted for". So without this, the headline tests
/// would pass on a refusal by the ceiling. That is a different gate, and the
/// hole still open underneath.
const PER_ISSUER_REFUSAL: &str = "is not an audience issuer";

/// Two trusted issuers, each with its own key and its own audience, behind one
/// `Authenticator`.
struct TwoIssuers {
    /// Kept alive so both JWKS endpoints answer for as long as the verifier
    /// does. The verifier holds only URLs.
    _stub_a: StubIssuer,
    _stub_b: StubIssuer,
    key_a: TestKey,
    key_b: TestKey,
    iss_a: String,
    iss_b: String,
    auth: Authenticator,
}

/// The standard topology: ceiling `[AUD_A, AUD_B]`, A naming only `AUD_A`, B
/// naming only `AUD_B`, `azp` unchecked.
async fn two_issuers() -> TwoIssuers {
    let key_a = TestKey::generate("kid-a");
    let key_b = TestKey::generate("kid-b");
    issuers(key_a, key_b, &[AUD_A, AUD_B], &[AUD_A], &[AUD_B], &[]).await
}

/// The same topology with both issuers publishing the *same* `kid`.
///
/// Providers reuse key ids. `key-1` is the commonest one there is, so this is
/// the normal case, not an exotic one. It is also what proves key selection is
/// per issuer. See [`a_shared_kid_does_not_make_one_issuers_key_another_s`].
async fn two_issuers_sharing_a_kid() -> TwoIssuers {
    let key_a = TestKey::generate("key-1");
    let key_b = TestKey::generate("key-1");
    issuers(key_a, key_b, &[AUD_A, AUD_B], &[AUD_A], &[AUD_B], &[]).await
}

/// Two issuers over an explicit ceiling, per-issuer audience lists, and `azp`s.
///
/// Every axis is a parameter because each test below differs from the standard
/// topology on exactly one of them. A harness that differs in two no longer
/// isolates the thing its test claims to verify. The keys are parameters too,
/// since which `kid` each issuer publishes is itself under test in one case.
async fn issuers(
    key_a: TestKey,
    key_b: TestKey,
    ceiling: &[&str],
    audiences_a: &[&str],
    audiences_b: &[&str],
    authorized_parties: &[&str],
) -> TwoIssuers {
    // Two stubs on two loopback ports: two genuinely distinct `iss` values,
    // each with its own discovery document and its own key. Sharing one stub
    // and spoofing `iss` would exercise the claim gate, not the key boundary,
    // and the question here is which *key* may carry which audience.
    let stub_a = StubIssuer::start_local(std::slice::from_ref(&key_a)).await;
    let stub_b = StubIssuer::start_local(std::slice::from_ref(&key_b)).await;
    let (iss_a, iss_b) = (stub_a.iss(), stub_b.iss());

    let config = ceiling
        .iter()
        .fold(AuthConfig::empty(), |config, aud| {
            config.with_audience(*aud)
        })
        .with_issuers([
            issuer_with_audiences(&iss_a, audiences_a),
            issuer_with_audiences(&iss_b, audiences_b),
        ])
        .with_authorized_parties(authorized_parties.iter().copied())
        // 1s rather than the 10s default, so a token naming an unknown `kid`
        // waits a second for its refresh instead of ten.
        .with_policy(CachePolicy {
            min_fetch_gap: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            ..CachePolicy::default()
        })
        .with_insecure_http(true);

    let auth = Authenticator::start(config)
        .await
        .expect("start an authenticator against both stub issuers");

    TwoIssuers {
        _stub_a: stub_a,
        _stub_b: stub_b,
        key_a,
        key_b,
        iss_a,
        iss_b,
        auth,
    }
}

/// A discovered issuer naming exactly these audiences — none, if empty, which
/// means the whole ceiling and is only legal while it is the only issuer.
fn issuer_with_audiences(iss: &str, audiences: &[&str]) -> Issuer {
    let issuer = Issuer::discover(iss).expect("valid issuer");
    audiences
        .iter()
        .fold(issuer, |issuer, aud| issuer.audience(*aud))
}

/// Claims for `iss`/`aud`, with `azp` present only when `party` names one.
///
/// `azp` is *absent* rather than null for `None`. Keycloak omits the claim for
/// some grant types, and an explicit null is a different document from no claim
/// at all.
fn token_claims(iss: &str, aud: &str, party: Option<&str>) -> serde_json::Value {
    let now = common::now();
    let mut claims = serde_json::json!({
        "iss": iss,
        "sub": "user-123",
        "aud": aud,
        "exp": now + 3600,
        "iat": now,
        "email": "user@example.com",
        "email_verified": true,
    });
    if let Some(party) = party {
        claims["azp"] = serde_json::json!(party);
    }
    claims
}

/// The refusal `token` earns, already shown to be an untrustworthy-token
/// refusal rather than some other failure.
///
/// Every refusal test here needs both the variant and the message. `expect_err`
/// alone gives neither. An expired token, an unreachable issuer and a
/// wrong-issuer token all "fail", and only some of those are the property under
/// test.
async fn refusal(auth: &Authenticator, token: &str) -> AuthError {
    let err = auth
        .authenticate(token)
        .await
        .expect_err("expected this token to be refused");
    assert!(
        matches!(err, AuthError::InvalidToken(_)),
        "expected an untrustworthy token, got {err:?}"
    );
    err
}

// ── The hole: one issuer cannot vouch for another's audience ─────────────────

#[tokio::test]
async fn a_token_signed_by_issuer_a_is_refused_for_issuer_bs_audience() {
    // The regression this change exists to close. Issuer A's own key signs the
    // token, correctly trusted, and names issuer B's audience. `AUD_B` *is* in
    // the ceiling, so the global audience gate passes. Before the per-issuer
    // layer this authenticated: the ceiling was one flat set shared by both
    // issuers, so A's key vouched for B's API. The layer built from A's own list
    // is the only thing standing between them now. The refusal has to say so. A
    // refusal from the ceiling would mean this token never reached the gate
    // under test, and the hole would still be open.
    let h = two_issuers().await;

    // Control: A's key works, so what follows is a judgement about the audience
    // and not an issuer that never came up.
    h.auth
        .authenticate(&h.key_a.sign(&h.key_a.claims(&h.iss_a, AUD_A)))
        .await
        .expect("issuer A's own token at issuer A's audience is accepted");

    let err = refusal(
        &h.auth,
        &h.key_a.sign(&token_claims(&h.iss_a, AUD_B, Some(CLIENT))),
    )
    .await;
    let reason = err.to_string();

    assert!(
        reason.contains(PER_ISSUER_REFUSAL),
        "must be refused by the per-issuer layer, not by the ceiling gate — a \
         ceiling refusal would mean the layer is the only thing working and this \
         test proves nothing about the hole: {reason}"
    );
    assert!(
        reason.contains(AUD_B),
        "the refusal must name the audience it refused: {reason}"
    );
    assert!(
        reason.contains(&h.iss_a),
        "the refusal must name the issuer whose key signed it, since that is \
         whose list was consulted: {reason}"
    );

    // And the same signature shape at B's own issuer is accepted: `AUD_B` really
    // is servable, so the refusal above is about *which issuer* served it.
    h.auth
        .authenticate(&h.key_b.sign(&token_claims(&h.iss_b, AUD_B, Some(CLIENT))))
        .await
        .expect("the same audience is accepted from the issuer that named it");
}

#[tokio::test]
async fn a_token_outside_every_audience_is_refused_by_the_ceiling_not_the_layer() {
    // Two refusals for two different reasons, told apart by wording.
    // `AUD_OUTSIDE` is in no ceiling, so the global gate inside `decode` answers
    // it and the layer is never reached. `AUD_B` from A is in the ceiling, so
    // the layer answers it. Both are `InvalidToken`. A deployment debugging a
    // 401 needs to know which setting it set wrong: the ceiling, or what it
    // told the issuer it serves.
    let h = two_issuers().await;

    let outside = refusal(
        &h.auth,
        &h.key_a.sign(&h.key_a.claims(&h.iss_a, AUD_OUTSIDE)),
    )
    .await;
    let reason = outside.to_string();
    assert!(
        !reason.contains(PER_ISSUER_REFUSAL),
        "an audience outside the ceiling must die at the global gate: {reason}"
    );

    let cross_issuer = refusal(&h.auth, &h.key_a.sign(&h.key_a.claims(&h.iss_a, AUD_B))).await;
    assert!(
        cross_issuer.to_string().contains(PER_ISSUER_REFUSAL),
        "and an audience inside the ceiling must reach the per-issuer layer: {cross_issuer}"
    );
}

// ── The boundary is the key, not the name ───────────────────────────────────

#[tokio::test]
async fn a_token_signed_by_issuer_bs_key_is_refused_under_issuer_as_name() {
    // B's key claiming `iss` = A. Selecting on the claimed `iss` hands over A's
    // bundle, which has no `kid-b`. So the lookup refuses it twice over: a
    // bundle holding that `kid` still could not verify a signature made by a
    // different key.
    //
    // Tripwire: if this passes, the per-issuer refactor broke the binding of
    // the verified `iss` to the issuer that verified it. See
    // `claims.iss != claimed_iss` in `validator.rs`. This is not a test to
    // adjust. It would mean any trusted key could reach any other issuer's
    // audience set by naming that issuer. That puts the whole per-issuer layer
    // back where it started.
    let h = two_issuers().await;

    let impersonation = h.key_b.sign(&h.key_b.claims(&h.iss_a, AUD_A));
    refusal(&h.auth, &impersonation).await;

    // Same key, same signature, its own name: accepted. So the refusal above is
    // a judgement about which issuer the key belongs to, and B's path through
    // the verifier works.
    h.auth
        .authenticate(&h.key_b.sign(&h.key_b.claims(&h.iss_b, AUD_B)))
        .await
        .expect("issuer B's own token is accepted");

    // And this is the direction the audience layer exists for. A's key presents
    // itself as B, at B's audience. Both the `iss` and the `aud` would be
    // acceptable *if the key were B's*. It is refused at the signature. The
    // layer is the backstop there, not the only gate.
    let reversed = h.key_a.sign(&h.key_a.claims(&h.iss_b, AUD_B));
    refusal(&h.auth, &reversed).await;
}

#[tokio::test]
async fn a_shared_kid_does_not_make_one_issuers_key_another_s() {
    // Two trusted issuers publishing the *same* `kid` is ordinary. The lookup
    // for (`iss_a`, `key-1`) succeeds, so nothing refuses this on the key's
    // face. Selection has to be per issuer, and the signature has to be what
    // answers. A lookup keyed by `kid` alone across the configured issuers is
    // the shape a `kid`-shaped trust decision takes. That lookup would accept
    // B's signature at A's audience here, which is the same hole one step
    // earlier.
    let h = two_issuers_sharing_a_kid().await;

    assert_eq!(
        h.key_a.kid, h.key_b.kid,
        "this test is only worth running if both issuers name the same `kid`"
    );

    h.auth
        .authenticate(&h.key_a.sign(&h.key_a.claims(&h.iss_a, AUD_A)))
        .await
        .expect("A's `key-1` verifies A's token");
    h.auth
        .authenticate(&h.key_b.sign(&h.key_b.claims(&h.iss_b, AUD_B)))
        .await
        .expect("B's `key-1` verifies B's token, same id, different key");

    // B's signature, A's name, and the `kid` A really does hold. The key lookup
    // succeeds and the signature is what refuses it. That is only possible
    // because the key found was A's, not B's under the same name.
    let stolen = h.key_b.sign(&h.key_b.claims(&h.iss_a, AUD_A));
    let reason = refusal(&h.auth, &stolen).await.to_string();
    assert!(
        reason.contains("signature"),
        "the signature must be what refuses a `kid` that resolves to the wrong \
         issuer's key: {reason}"
    );
    assert!(
        !reason.contains(PER_ISSUER_REFUSAL),
        "and not the audience layer, which would mean the audience gate is doing \
         work that key selection should have done: {reason}"
    );

    // B's signature at A's name with A's audience is refused too. So no
    // reordering of the two gates lets a borrowed key serve a name it was not
    // issued under.
    refusal(&h.auth, &h.key_b.sign(&h.key_b.claims(&h.iss_a, AUD_B))).await;
}

// ── Both issuers work, and each one's own key is what works. ───────────

#[tokio::test]
async fn both_issuers_are_verified_by_their_own_keys_at_the_same_time() {
    // The issuer whose key verified the signature picks its own audience layer.
    // So a two-issuer configuration must not collapse onto whichever layer was
    // built first. A suite of only refusals would be satisfied by a verifier
    // that accepted nothing at all. This is the half that says the two-issuer
    // topology actually serves both issuers.
    let h = two_issuers().await;

    let from_a = h
        .auth
        .authenticate(&h.key_a.sign(&h.key_a.claims(&h.iss_a, AUD_A)))
        .await
        .expect("issuer A authenticates against its own key");
    let from_b = h
        .auth
        .authenticate(&h.key_b.sign(&h.key_b.claims(&h.iss_b, AUD_B)))
        .await
        .expect("issuer B authenticates against its own key, in the same process");

    assert_eq!(from_a.iss, h.iss_a, "A's verified claims carry A's issuer");
    assert_eq!(from_b.iss, h.iss_b, "B's verified claims carry B's issuer");
    assert_ne!(from_a.iss, from_b.iss, "and they are different issuers");
    assert_eq!(from_a.sub, "user-123", "A's subject survives the verifier");
    assert_eq!(from_b.sub, "user-123", "and so does B's");

    // Each layer holds only its own audience: not one shared set both happen to
    // satisfy, which is what the ceiling used to be.
    refusal(&h.auth, &h.key_a.sign(&h.key_a.claims(&h.iss_a, AUD_B))).await;
    refusal(&h.auth, &h.key_b.sign(&h.key_b.claims(&h.iss_b, AUD_A))).await;
}

// ── `azp` narrows the same token further, and only that token ────────────────

#[tokio::test]
async fn a_configured_azp_admits_one_client_and_refuses_the_rest() {
    // `decode` verifies `azp` after `aud`, on top of it, never instead of it.
    // Issuer A here names its own audience and one allowed client. So a token
    // passes only by naming both correctly. An OR over the two would be
    // satisfied by whichever claim the attacker's token happened to carry.
    let h = two_issuers_with_parties(&[CLIENT]).await;

    h.auth
        .authenticate(&h.key_a.sign(&token_claims(&h.iss_a, AUD_A, Some(CLIENT))))
        .await
        .expect("the named client at the named audience is accepted");

    let missing = refusal(&h.auth, &h.key_a.sign(&token_claims(&h.iss_a, AUD_A, None))).await;
    assert!(
        missing.to_string().contains("no `azp`"),
        "a missing `azp` must be refused, not skipped — a check that absence
         bypasses is not a check: {missing}"
    );

    let wrong = refusal(
        &h.auth,
        &h.key_a
            .sign(&token_claims(&h.iss_a, AUD_A, Some(OTHER_CLIENT))),
    )
    .await;
    assert!(
        wrong.to_string().contains(OTHER_CLIENT),
        "the refusal must name the client it refused: {wrong}"
    );

    // And B's audience stays out of reach for A's key, whether or not the
    // client is the trusted one. So configuring `azp` did not open a second way
    // in.
    let cross = refusal(
        &h.auth,
        &h.key_a.sign(&token_claims(&h.iss_a, AUD_B, Some(CLIENT))),
    )
    .await;
    assert!(
        cross.to_string().contains(PER_ISSUER_REFUSAL),
        "the audience layer must answer before `azp` is consulted, so a trusted \
         client cannot carry another issuer's audience: {cross}"
    );
}

/// The standard topology with `azp` restricted to these clients.
async fn two_issuers_with_parties(authorized_parties: &[&str]) -> TwoIssuers {
    let key_a = TestKey::generate("kid-a");
    let key_b = TestKey::generate("kid-b");
    issuers(
        key_a,
        key_b,
        &[AUD_A, AUD_B],
        &[AUD_A],
        &[AUD_B],
        authorized_parties,
    )
    .await
}

#[tokio::test]
async fn a_token_without_azp_is_accepted_while_azp_is_unconfigured() {
    // The default, stated so this release is not silently breaking. A
    // deployment that never named a client keeps accepting what it accepts
    // today, including tokens with no `azp` at all. Google ID tokens routinely
    // have none. An `azp` enforced by default would be an outage shipped as a
    // hardening.
    let h = two_issuers().await;

    assert!(
        h.auth.authorized_parties().is_empty(),
        "`azp` is unchecked unless it is configured"
    );

    h.auth
        .authenticate(&h.key_a.sign(&token_claims(&h.iss_a, AUD_A, None)))
        .await
        .expect("a token with no `azp` claim is accepted when nothing is configured");

    // An arbitrary client is admitted too, which is the same fact from the other
    // side: the claim is read, not enforced.
    let verified = h
        .auth
        .authenticate(
            &h.key_a
                .sign(&token_claims(&h.iss_a, AUD_A, Some(OTHER_CLIENT))),
        )
        .await
        .expect("an unconfigured `azp` admits any client");
    assert_eq!(
        verified.azp.as_deref(),
        Some(OTHER_CLIENT),
        "the claim survives into the verified claims even when it is not enforced"
    );
}

// ── Topologies that must not boot ────────────────────────────────────────────

#[tokio::test]
async fn an_issuer_that_names_no_audiences_refuses_to_boot_beside_a_second_issuer() {
    // With one issuer the ceiling *is* its audience set, so naming nothing is
    // harmless. With two, an unspecified issuer silently accepts the whole
    // ceiling. That is the cross-issuer confusion this suite exists to close,
    // reached by forgetting a flag rather than by choosing it. The message also
    // has to name *which* issuer is under-specified. Six realms and one line
    // that does not say which is a bisect, not a diagnosis.
    let config = AuthConfig::empty()
        .with_audience(AUD_A)
        .with_audience(AUD_B)
        .with_issuer(
            Issuer::discover("https://identity.example/realms/a")
                .expect("valid issuer")
                .audience(AUD_A),
        )
        .with_issuer(Issuer::discover("https://identity.example/realms/b").expect("valid issuer"));

    // No network anywhere in this test: `validate` is the first statement of
    // `start`, so a bad audience topology cannot reach discovery or open a
    // socket. The realms are notional for exactly that reason.
    let err = Authenticator::start(config)
        .await
        .expect_err("an unspecified issuer in a two-issuer topology is not bootable");
    assert!(matches!(err, AuthError::Configuration(_)), "{err:?}");

    let reason = err.to_string();
    assert!(
        reason.contains("realms/b"),
        "the message must name the under-specified issuer: {reason}"
    );
    assert!(
        !reason.contains("realms/a"),
        "and must not blame the issuer that stated its audiences: {reason}"
    );
}

#[tokio::test]
async fn a_per_issuer_audience_outside_the_ceiling_refuses_to_boot_and_says_which() {
    // A per-issuer audience the ceiling does not contain can never match a
    // token, because the verifier enforces the intersection. Left unrefused it
    // ships a caller who cannot authenticate for any reason they can be told,
    // and an outage nobody can diagnose. So this is a boot failure, naming both
    // the audience and the issuer that named it.
    let config = AuthConfig::empty()
        .with_audience(AUD_A)
        .with_audience(AUD_B)
        .with_issuer(
            Issuer::discover("https://identity.example/realms/a")
                .expect("valid issuer")
                .audience(AUD_A),
        )
        .with_issuer(
            Issuer::discover("https://identity.example/realms/b")
                .expect("valid issuer")
                .audience("tenant-c-api"),
        );

    let err = Authenticator::start(config)
        .await
        .expect_err("an audience outside the ceiling is not bootable");
    assert!(matches!(err, AuthError::Configuration(_)), "{err:?}");

    let reason = err.to_string();
    assert!(
        reason.contains("tenant-c-api"),
        "the message must name the stray audience: {reason}"
    );
    assert!(
        reason.contains("realms/b"),
        "and the issuer that named it, since that is the one to fix: {reason}"
    );
    assert!(
        !reason.contains("realms/a"),
        "issuer A is configured correctly and must not be reported: {reason}"
    );
}

// ── What did not move: the single-issuer deployment. ──────────────────

#[tokio::test]
async fn a_lone_issuer_that_names_no_audiences_still_boots_and_authenticates() {
    // The mandatory-per-issuer rule is scoped to the *second* issuer. That is
    // precisely so this deployment upgrades without a new flag, and this test is
    // the proof rather than the assumption. If it breaks, the change is
    // breaking for every existing user however correct the multi-issuer half
    // is.
    let key = TestKey::generate("kid-lone");
    let stub = StubIssuer::start_local(std::slice::from_ref(&key)).await;
    let iss = stub.iss();

    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(iss.clone()).expect("valid issuer"))
        .with_audience(AUD_A)
        .with_policy(CachePolicy {
            min_fetch_gap: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            ..CachePolicy::default()
        })
        .with_insecure_http(true);

    let auth = Authenticator::start(config)
        .await
        .expect("a lone issuer with no per-issuer audience list must still boot");

    let claims = auth
        .authenticate(&key.sign(&key.claims(&iss, AUD_A)))
        .await
        .expect("and authenticate the tokens it authenticates today");
    assert_eq!(claims.sub, "user-123");
    assert_eq!(claims.iss, iss);

    // Inheriting the ceiling is not the same as ignoring it: an audience the
    // lone issuer never served was never in scope, and still is not.
    let err = auth
        .authenticate(&key.sign(&key.claims(&iss, AUD_OUTSIDE)))
        .await
        .expect_err("an audience outside the ceiling is still refused");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[test]
fn a_lone_issuer_inherits_the_ceiling_it_did_not_restate() {
    // The read side of the same rule, without a server. The accessor answers
    // with the ceiling for an issuer that named nothing, and with its own
    // narrowed list for one that did. Both are subsets of the ceiling by
    // construction. That is the property the request path depends on. Nothing
    // can ask this accessor for an audience the ceiling would have refused.
    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover("https://identity.example").expect("valid issuer"))
        .with_issuer(
            Issuer::discover("https://other.example")
                .expect("valid issuer")
                .audience(AUD_B),
        )
        .with_audience(AUD_A)
        .with_audience(AUD_B);

    assert_eq!(
        config.issuer_audiences(&config.issuers[0]),
        [AUD_A.to_owned(), AUD_B.to_owned()],
        "the issuer that named nothing inherits the whole ceiling"
    );
    assert_eq!(
        config.issuer_audiences(&config.issuers[1]),
        [AUD_B.to_owned()],
        "the issuer that named its own gets only that, and not `AUD_A`"
    );
}
