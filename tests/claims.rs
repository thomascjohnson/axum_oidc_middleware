//! [`Claims`] deserialisation and the two helpers on it.
//!
//! The gap these close is the negative side of each rule: `verified_email`
//! refusing an email the issuer did not vouch for, and `deserialize_audience`
//! refusing an empty `aud` outright.

mod common;

use axum_oidc_middleware::Claims;
use serde_json::json;

/// Fill in the required claims around a few overrides.
fn claims(over: serde_json::Value) -> serde_json::Value {
    let now = common::now();
    let mut base = json!({
        "iss": "https://issuer.example.com",
        "sub": "user-123",
        "aud": ["myaudience"],
        "exp": now + 3600,
    });
    base.as_object_mut()
        .expect("claims object")
        .extend(over.as_object().expect("overrides object").clone());
    base
}

fn decode(over: serde_json::Value) -> Claims {
    serde_json::from_value(claims(over)).expect("deserialize claims")
}

#[test]
fn verified_email_returns_the_email_only_when_the_issuer_vouched_for_it() {
    let claims = decode(json!({
        "email": "user@example.com",
        "email_verified": true,
    }));

    assert_eq!(claims.verified_email(), Some("user@example.com"));
}

/// Each way of *not* vouching for the email yields `None`: the flag asserted
/// false, the flag absent, the address absent, and both absent. The last two
/// matter. Most machine-to-machine tokens carry neither claim. A helper that
/// read "no flag" as "verified" would hand out an unverified address for
/// every service token.
#[test]
fn verified_email_refuses_an_email_the_issuer_did_not_vouch_for() {
    let cases = [
        (
            "flag asserted false",
            json!({ "email": "u@e.com", "email_verified": false }),
        ),
        ("flag absent", json!({ "email": "u@e.com" })),
        ("address absent", json!({ "email_verified": true })),
        ("both absent", json!({})),
    ];

    for (what, over) in cases {
        let claims = decode(over);
        assert_eq!(claims.verified_email(), None, "{what}");
    }
}

/// A token with no audience says who it is *not* for. That is the one thing
/// this API depends on. So `aud: []` is a rejection rather than a pass, and
/// the rejection says why.
#[test]
fn an_empty_audience_list_is_rejected() {
    let err = serde_json::from_value::<Claims>(claims(json!({ "aud": [] })))
        .expect_err("an empty `aud` list must not deserialize");

    assert!(
        err.to_string().contains("must not be empty"),
        "the rejection should name the rule, got: {err}"
    );
}

/// Both wire forms still work: Google's single string and RFC 9068's list. A
/// single-string `aud` is the shape that would silently regress if the
/// untagged enum were reordered or narrowed.
#[test]
fn aud_accepts_a_single_string_or_a_list() {
    let single = decode(json!({ "aud": "myaudience" }));
    assert_eq!(single.aud, vec!["myaudience".to_owned()]);

    let many = decode(json!({ "aud": ["myaudience", "other-api"] }));
    assert_eq!(many.aud, vec!["myaudience", "other-api"]);
}

/// Every claim this crate does not model survives, so authorisation code can
/// read provider-specific ones without a second decode.
#[test]
fn unmodelled_claims_survive_in_extra() {
    let claims = decode(json!({
        "hd": "example.com",
        "realm_access": { "roles": ["admin"] },
    }));

    assert_eq!(claims.extra["hd"], json!("example.com"));
    assert_eq!(claims.extra["realm_access"]["roles"][0], json!("admin"));
}

#[test]
fn optional_claims_default_to_absent_rather_than_failing() {
    let claims = decode(json!({}));

    assert_eq!(claims.azp, None);
    assert_eq!(claims.email, None);
    assert_eq!(claims.email_verified, None);
    assert_eq!(claims.scope, None);
    assert_eq!(claims.jti, None);
    assert_eq!(claims.typ, None);
    assert_eq!(claims.iat, None);
    assert_eq!(claims.nbf, None);
    assert!(claims.extra.is_empty());
}

/// Two providers that both mint `sub = "admin"` must not collide in a log
/// line, which is the whole reason `log_id` exists.
#[test]
fn log_id_qualifies_the_subject_with_the_issuer() {
    let claims = decode(json!({}));

    assert_eq!(claims.log_id(), "user-123@https://issuer.example.com");
}
