//! Per-issuer scope: which issuer is allowed to vouch for which audience, and
//! which client.
//!
//! Audiences used to be one flat list handed to `Validation::set_audience` for
//! every issuer at once, from [`AuthConfig`] rather than from the issuers. In a
//! two-issuer deployment that made the audience set a property of the
//! *verifier* rather than of the issuer that signed the token. So any trusted
//! issuer could vouch for any audience this verifier served: issuer A's key,
//! issuer B's `aud`, accepted. Multi-tenant, that is a token minted for one
//! customer's tool authenticating as another customer's. It is not a
//! degradation and it does not log. The signature is real, the audience is
//! real, only the pairing is one nobody chose.
//!
//! So `aud` is decided in two gates in series, and `azp` is scoped the same
//! way. These tests prove that both audience gates are necessary and that
//! neither one stands in for the other:
//!
//! * the **union** ([`AuthConfig::all_audiences`], derived from the issuers rather
//!   than set beside them), verified inside `decode` by `jsonwebtoken`, over
//!   every token from any issuer.
//! * the **issuer gate** ([`Issuer::audiences()`]), verified by
//!   [`Authenticator::authenticate`] *after* the signature, once the issuer
//!   that actually signed is a verified fact rather than an unverified claim.
//!
//! A token has to clear both, so what is accepted is only what the signing
//! issuer itself named. The headline test therefore names an audience that *is*
//! in the union. The union says yes, and only the issuer gate is left standing
//! between issuer A's key and issuer B's API. Its refusal wording is asserted as
//! well, because "refused" is not the finding. "Refused by the gate under test"
//! is. Both gates answer `AuthError::InvalidToken`, so the variant alone cannot
//! tell them apart, and a test that only verified the variant would pass with
//! the hole wide open.
//!
//! `azp` gets the same treatment for a sharper reason. A client id is unique
//! within a realm, not across realms, so two trusted realms can each carry a
//! client called `my-client`. A shared accepted-client list admitted either
//! one's token — and with `aud` reading `"account"` for every API in a stock
//! realm, the audience gates above cannot tell those tokens apart either.
//!
//! What did not move is the single-issuer deployment, except that it now names
//! its audience where it always named its issuer. The issuer gate is keyed by
//! the *verified* issuer rather than the claimed one, so a key cannot be pointed
//! at another issuer's set by naming it.

mod common;

use std::time::Duration;

use axum_oidc_middleware::{
    AuthConfig, AuthError, Authenticator, AuthorizedParty, CachePolicy, Issuer,
};
use common::{StubIssuer, TestKey};

/// What issuer A is trusted for.
const AUD_A: &str = "my-api";
/// What issuer B is trusted for. This is also the point of the headline test.
/// It is in the union, because B named it, so a token naming it clears the
/// first gate from *any* issuer. Only A's own list can refuse it.
const AUD_B: &str = "billing-api";
/// Named by no issuer at all, so it is not in the union: refused by the first
/// gate, without ever reaching an issuer's own list.
const AUD_OUTSIDE: &str = "someone-elses-api";

/// The client an `azp` names, and a second one that must not be admitted by it.
const CLIENT: &str = "my-client";
const OTHER_CLIENT: &str = "reporting-client";

/// The wording of the per-issuer layer's refusal, inside
/// [`Authenticator::authenticate`].
///
/// Matched as a string because *which gate refused* is the finding here. Both
/// audience gates answer `InvalidToken`. Only the issuer gate says "is not an
/// audience issuer `…` is trusted for". So without this, the headline tests
/// would pass on a refusal by the union gate. That is a different gate, and the
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

/// The standard topology: A naming only `AUD_A`, B naming only `AUD_B` (so the
/// union is `[AUD_A, AUD_B]`), `azp` unchecked.
async fn two_issuers() -> TwoIssuers {
    let key_a = TestKey::generate("kid-a");
    let key_b = TestKey::generate("kid-b");
    issuers(key_a, key_b, &[AUD_A], &[AUD_B], &[], &[]).await
}

/// The same topology with both issuers publishing the *same* `kid`.
///
/// Providers reuse key ids. `key-1` is the commonest one there is, so this is
/// the normal case, not an exotic one. It is also what proves key selection is
/// per issuer. See [`a_shared_kid_does_not_make_one_issuers_key_another_s`].
async fn two_issuers_sharing_a_kid() -> TwoIssuers {
    let key_a = TestKey::generate("key-1");
    let key_b = TestKey::generate("key-1");
    issuers(key_a, key_b, &[AUD_A], &[AUD_B], &[], &[]).await
}

/// Two issuers over per-issuer audience lists and per-issuer client lists.
///
/// Every axis is a parameter because each test below differs from the standard
/// topology on exactly one of them. A harness that differs in two no longer
/// isolates the thing its test claims to verify. The keys are parameters too,
/// since which `kid` each issuer publishes is itself under test in one case.
async fn issuers(
    key_a: TestKey,
    key_b: TestKey,
    audiences_a: &[&str],
    audiences_b: &[&str],
    parties_a: &[&str],
    parties_b: &[&str],
) -> TwoIssuers {
    // Two stubs on two loopback ports: two genuinely distinct `iss` values,
    // each with its own discovery document and its own key. Sharing one stub
    // and spoofing `iss` would exercise the claim gate, not the key boundary,
    // and the question here is which *key* may carry which audience.
    let stub_a = StubIssuer::start_local(std::slice::from_ref(&key_a)).await;
    let stub_b = StubIssuer::start_local(std::slice::from_ref(&key_b)).await;
    let (iss_a, iss_b) = (stub_a.iss(), stub_b.iss());

    let config = AuthConfig::empty()
        .with_issuers([
            issuer_scope(&iss_a, audiences_a, parties_a),
            issuer_scope(&iss_b, audiences_b, parties_b),
        ])
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

/// A discovered issuer naming exactly these audiences and these clients.
///
/// Both are per issuer, which is the whole subject of this file: the audience
/// set and the client set are stated on the issuer they describe, and there is
/// no deployment-wide version of either to narrow or to inherit.
fn issuer_scope(iss: &str, audiences: &[&str], parties: &[&str]) -> Issuer {
    let issuer = Issuer::discover(iss, audiences.iter().copied()).expect("valid issuer");
    parties
        .iter()
        .try_fold(issuer, |issuer, party| issuer.authorized_party(*party))
        .expect("every named client is a client")
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
    // the union, because B named it, so the first audience gate passes. Before
    // audiences were per issuer this authenticated: the accepted set was one
    // flat list shared by both issuers, so A's key vouched for B's API. The set
    // built from A's own list is the only thing standing between them now, and
    // the refusal has to say so. A refusal from the union gate would mean this
    // token never reached the gate under test, and the hole would still be open.
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
        "must be refused by the issuer gate, not by the union gate — a union \
         refusal would mean the issuer gate is the only thing working and this \
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
async fn a_token_outside_every_audience_is_refused_at_the_union_not_the_issuer_gate() {
    // Two refusals for two different reasons, told apart by wording.
    // `AUD_OUTSIDE` is named by no issuer, so it is not in the union and the
    // gate inside `decode` answers it; the issuer gate is never reached.
    // `AUD_B` from A *is* in the union, because B named it, so the issuer gate
    // answers it. Both are `InvalidToken`. A deployment debugging a 401 needs to
    // know which of the two it got: an audience nothing serves here at all, or
    // one served by an issuer other than the one that signed the token.
    let h = two_issuers().await;

    let outside = refusal(
        &h.auth,
        &h.key_a.sign(&h.key_a.claims(&h.iss_a, AUD_OUTSIDE)),
    )
    .await;
    let reason = outside.to_string();
    assert!(
        !reason.contains(PER_ISSUER_REFUSAL),
        "an audience no issuer named must die at the union gate: {reason}"
    );

    let cross_issuer = refusal(&h.auth, &h.key_a.sign(&h.key_a.claims(&h.iss_a, AUD_B))).await;
    assert!(
        cross_issuer.to_string().contains(PER_ISSUER_REFUSAL),
        "and an audience some *other* issuer named must reach the issuer gate: \
         {cross_issuer}"
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

    assert_eq!(
        from_a.iss.as_str(),
        h.iss_a,
        "A's verified claims carry A's issuer"
    );
    assert_eq!(
        from_b.iss.as_str(),
        h.iss_b,
        "B's verified claims carry B's issuer"
    );
    assert_ne!(from_a.iss, from_b.iss, "and they are different issuers");
    assert_eq!(from_a.sub, "user-123", "A's subject survives the verifier");
    assert_eq!(from_b.sub, "user-123", "and so does B's");

    // Each issuer holds only its own audience: not one shared set both happen to
    // satisfy, which is what the flat list used to be.
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

#[tokio::test]
async fn a_client_name_gates_the_issuer_that_named_it_and_no_other() {
    // A client id is unique inside a realm, not across realms. Two realms you
    // both trust can each carry a client called `my-client`. While the accepted
    // clients were one deployment-wide list, B's `my-client` authenticated at
    // what A's gate was meant to cover — and in a stock realm `aud` is
    // "account" for every API, so the audience gate reads the same on both
    // tokens and cannot catch the swap either.
    //
    // So A gates on CLIENT and B gates on OTHER_CLIENT. Each name admits only
    // the issuer that named it.
    let key_a = TestKey::generate("kid-a");
    let key_b = TestKey::generate("kid-b");
    let h = issuers(key_a, key_b, &[AUD_A], &[AUD_B], &[CLIENT], &[OTHER_CLIENT]).await;

    // Controls: each issuer accepts its own client at its own audience.
    h.auth
        .authenticate(&h.key_a.sign(&token_claims(&h.iss_a, AUD_A, Some(CLIENT))))
        .await
        .expect("issuer A accepts the client it named itself");
    h.auth
        .authenticate(
            &h.key_b
                .sign(&token_claims(&h.iss_b, AUD_B, Some(OTHER_CLIENT))),
        )
        .await
        .expect("issuer B accepts the client it named itself");

    // The cross. B's key, B's audience, A's client name — everything about this
    // token is honest except which realm the client lives in. Before `azp` was
    // scoped to its issuer, the name was on the shared list and this passed.
    let from_b = refusal(
        &h.auth,
        &h.key_b.sign(&token_claims(&h.iss_b, AUD_B, Some(CLIENT))),
    )
    .await;
    assert!(
        from_b.to_string().contains(CLIENT),
        "the refusal should name the client it refused: {from_b}"
    );
    assert!(
        from_b.to_string().contains(&h.iss_b),
        "and the issuer whose client list it was checked against, since the fix \
         is that issuer's: {from_b}"
    );

    // And the mirror, so the result is not an accident of argument order.
    refusal(
        &h.auth,
        &h.key_a
            .sign(&token_claims(&h.iss_a, AUD_A, Some(OTHER_CLIENT))),
    )
    .await;
}

#[tokio::test]
async fn one_issuer_can_gate_on_azp_while_another_does_not() {
    // The mixed deployment the flat list could not express: a Keycloak realm
    // that always names a client, beside an issuer that never emits `azp` at
    // all. A deployment-wide gate rejects every token from the second issuer
    // for a claim it is incapable of making — an outage shipped as a hardening.
    // Per issuer, the realm is gated and the other issuer is simply not.
    let key_a = TestKey::generate("kid-a");
    let key_b = TestKey::generate("kid-b");
    let h = issuers(key_a, key_b, &[AUD_A], &[AUD_B], &[CLIENT], &[]).await;

    h.auth
        .authenticate(&h.key_b.sign(&token_claims(&h.iss_b, AUD_B, None)))
        .await
        .expect("the ungated issuer's token with no `azp` is accepted");

    let missing = refusal(&h.auth, &h.key_a.sign(&token_claims(&h.iss_a, AUD_A, None))).await;
    assert!(
        missing.to_string().contains("no `azp`"),
        "the gated issuer still refuses an absent `azp`, gate or no gate \
         elsewhere: {missing}"
    );
}

/// The standard topology with `azp` restricted to these clients **on both
/// issuers**.
async fn two_issuers_with_parties(authorized_parties: &[&str]) -> TwoIssuers {
    let key_a = TestKey::generate("kid-a");
    let key_b = TestKey::generate("kid-b");
    issuers(
        key_a,
        key_b,
        &[AUD_A],
        &[AUD_B],
        authorized_parties,
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
        h.auth.all_authorized_parties().is_empty(),
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
        verified.azp.as_ref().map(AuthorizedParty::as_str),
        Some(OTHER_CLIENT),
        "the claim survives into the verified claims even when it is not enforced"
    );
}

// ── Topologies that must not boot ────────────────────────────────────────────

// The refusal happens where the mistake is, not at boot. Arity forces the
// set to be addressed, but `[]` is a value that addresses it with nothing,
// and only the constructor can see inside the iterator. So this needs no
// server, no config, and no two-issuer topology: one call fails.
#[test]
fn an_issuer_that_names_no_audiences_is_refused_and_says_which() {
    // An empty audience list used to be legal for the only issuer, because a
    // deployment-wide list stood in for it. Nothing stands in now, so an empty
    // list reads as "anything", for every issuer, and is refused. The message
    // still has to name *which* issuer is under-specified: six realms and one
    // line that does not say which is a bisect, not a diagnosis.
    let err = Issuer::discover("https://identity.example/realms/b", Vec::<String>::new())
        .expect_err("an issuer that names no audience is not an issuer");

    assert!(matches!(err, AuthError::Configuration(_)), "{err:?}");

    let reason = err.to_string();
    assert!(
        reason.contains("realms/b"),
        "the message must name the under-specified issuer: {reason}"
    );
}

#[tokio::test]
async fn an_issuer_naming_a_blank_authorised_party_is_refused_where_it_is_named() {
    // A blank `azp` could never match a token, so it is an outage dressed as a
    // security control. It used to be refused at boot, from `validate`, with a
    // message naming the issuer whose gate it was.
    //
    // It is now refused at the call that names it, because `AuthorizedParty`
    // will not hold a blank entry. That is strictly more local: the operator
    // reads the error beside the argument they can still see, and the value
    // never reaches a config that looks settled.
    let err = Issuer::discover("https://identity.example/realms/b", [AUD_B])
        .expect("valid issuer")
        .authorized_party("")
        .expect_err("a gate that can never open is not a client");

    assert!(matches!(err, AuthError::Configuration(_)), "{err:?}");

    let reason = err.to_string();
    assert!(
        reason.contains("azp"),
        "the message must name the claim at fault: {reason}"
    );

    // The blank is per entry, so a set with one good client and one blank is
    // refused too — the gate is not saved by the good entry.
    let err = Issuer::discover("https://identity.example/realms/b", [AUD_B])
        .expect("valid issuer")
        .authorized_party(CLIENT)
        .expect("a named client")
        .authorized_party("")
        .expect_err("one blank entry is enough");
    assert!(err.to_string().contains("azp"), "{err}");
}

// ── What still works unchanged: a deployment with one issuer. ──────────────

#[tokio::test]
async fn a_lone_issuer_naming_its_own_audience_boots_and_authenticates() {
    // A single-issuer deployment needs no second list and no inheritance rule:
    // it names its audience where it always named its issuer. What changed is
    // that the name is now required rather than optional — see
    // `refusing_to_name_an_audience_is_a_configuration_error` in `config.rs`.
    let key = TestKey::generate("kid-lone");
    let stub = StubIssuer::start_local(std::slice::from_ref(&key)).await;
    let iss = stub.iss();

    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(iss.clone(), [AUD_A]).expect("valid issuer"))
        .with_policy(CachePolicy {
            min_fetch_gap: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            ..CachePolicy::default()
        })
        .with_insecure_http(true);

    let auth = Authenticator::start(config)
        .await
        .expect("a lone issuer that names its own audience must boot");

    let claims = auth
        .authenticate(&key.sign(&key.claims(&iss, AUD_A)))
        .await
        .expect("and authenticate the tokens it authenticates today");
    assert_eq!(claims.sub, "user-123");
    assert_eq!(claims.iss.as_str(), iss);

    // Naming one audience means naming only that one. An audience this issuer
    // never claimed was never in scope.
    let err = auth
        .authenticate(&key.sign(&key.claims(&iss, AUD_OUTSIDE)))
        .await
        .expect_err("an audience no issuer named is still refused");
    assert!(matches!(err, AuthError::InvalidToken(_)), "{err:?}");
}

#[test]
fn each_issuer_sees_its_own_scope_and_the_deployment_sees_the_union() {
    // The read side, without a server. An issuer answers with the list it was
    // built with, and `AuthConfig` answers with the union of those lists —
    // derived, so it cannot name an audience no issuer asked for, and cannot
    // omit one some issuer did. There is no longer an accessor that hands back
    // "the whole deployment for an issuer that said nothing", because nothing can
    // say nothing.
    let config = AuthConfig::empty()
        .with_issuer(
            Issuer::discover("https://identity.example", [AUD_A])
                .expect("valid issuer")
                .authorized_party(CLIENT)
                .expect("a named client"),
        )
        .with_issuer(
            Issuer::discover("https://other.example", [AUD_B, AUD_A]).expect("valid issuer"),
        );

    assert_eq!(
        config.issuers[0].audiences(),
        [AUD_A],
        "the first issuer serves only what it named"
    );
    assert_eq!(
        config.issuers[1].audiences(),
        [AUD_B, AUD_A],
        "the second serves what it named, in the order it named them"
    );
    assert_eq!(
        config.all_audiences(),
        [AUD_A.to_owned(), AUD_B.to_owned()],
        "the union is derived from the issuers and deduplicated"
    );
    assert_eq!(
        config.issuers[0].authorized_parties(),
        [CLIENT],
        "`azp` is stated per issuer too"
    );
    assert!(
        config.issuers[1].authorized_parties().is_empty(),
        "and an issuer that named none gates on none"
    );
    assert_eq!(
        config.all_authorized_parties(),
        [CLIENT.to_owned()],
        "the derived `azp` union names the one client any issuer asked for"
    );
}
