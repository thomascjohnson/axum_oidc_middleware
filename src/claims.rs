//! The verified claims of an ID/access token.
//!
//! This module types only the claims this API makes decisions on. Every other
//! claim — Google's `hd`, Keycloak's `realm_access`, and anything an issuer
//! adds later — survives in [`Claims::extra`] rather than being silently
//! dropped. So authorisation code can read provider-specific claims without a
//! second decode.

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};

use crate::types::IssuerUrl;

/// Claims from a token that passed signature verification **and** the
/// issuer/audience/expiry gates in [`Authenticator::authenticate`](crate::Authenticator::authenticate).
///
/// Only that path constructs a `Claims` value, so holding one means the crate
/// trusted that token. Never build one from a token you have not verified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    /// `sub` — the principal. Required: every ID token has one, and an
    /// absent subject means the token is not identifying anyone.
    pub sub: String,

    /// `iss` — the issuer. The crate compares it with the trusted issuer whose
    /// key verified the signature. It rejects a token whose `iss` did not
    /// verify, before it builds this value.
    ///
    /// Typed, so an unparseable `iss` cannot be carried here: a value of this
    /// type always parsed as an absolute URL. That is *shape*, not trust. It
    /// becomes a trusted identifier only because
    /// [`Authenticator::authenticate`](crate::Authenticator::authenticate)
    /// matched it against a configured issuer and that issuer's key verified the
    /// signature.
    pub iss: IssuerUrl,

    /// `aud` — audiences. RFC 9068 §2.2.1 requires a list, but Google's ID
    /// tokens carry a single string, so this accepts both forms. At least one
    /// element must have matched a configured audience.
    #[serde(deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,

    /// `exp` — expiry, seconds since the Unix epoch. Required. The crate
    /// rejects a token without it.
    pub exp: i64,

    /// `iat` — issued at. Optional: present on Google and Keycloak tokens,
    /// not required by the spec.
    #[serde(default)]
    pub iat: Option<i64>,

    /// `nbf` — not before. The crate enforces it when present. `jsonwebtoken`
    /// ignores `nbf` unless `validate_nbf` is explicitly enabled.
    #[serde(default)]
    pub nbf: Option<i64>,

    /// `azp` — authorised party: the client that asked for the token.
    ///
    /// Keycloak always sets this to the requesting `client_id` with no mapper
    /// configuration. That makes it the reliable client identifier there. It is
    /// unlike `aud`, which a stock realm fills with `"account"` for every API.
    ///
    /// When an issuer sets
    /// [`Issuer::authorized_parties()`](crate::Issuer::authorized_parties), the
    /// crate compares this claim with that issuer's list, and only *after* `aud`
    /// has already passed. When an issuer leaves it unset, the crate exposes the
    /// claim and enforces nothing.
    #[serde(default)]
    pub azp: Option<String>,

    /// `email` — convenience for the common "who is the human" question.
    ///
    /// Empty unless the token asserts it, and only trustworthy when
    /// [`Claims::email_verified`] is `Some(true)`.
    #[serde(default)]
    pub email: Option<String>,

    /// `email_verified` — `None` when the issuer does not make the claim,
    /// which is the case for most machine-to-machine tokens.
    #[serde(default)]
    pub email_verified: Option<bool>,

    /// `scope` — space-delimited scopes, as Google and Keycloak both send it.
    #[serde(default)]
    pub scope: Option<String>,

    /// `jti` — token id, for replay logs or a revocation cache.
    #[serde(default)]
    pub jti: Option<String>,

    /// `typ` — as sent by the issuer. Keycloak access tokens say `Bearer`,
    /// Google ID tokens say `JWT`. Nothing here enforces it, since the value
    /// is not consistent across the providers this is meant to serve.
    #[serde(default)]
    pub typ: Option<String>,

    /// Every claim not modelled above. Empty rather than absent when there is
    /// nothing extra, so callers can index it without a presence test.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// The email, but only when the issuer asserted it *and* vouched for it.
    ///
    /// Google's docs say explicitly that a reader must not trust `email`
    /// without this flag. The same caution applies to any federated issuer.
    pub fn verified_email(&self) -> Option<&str> {
        match (self.email_verified, self.email.as_deref()) {
            (Some(true), Some(email)) => Some(email),
            _ => None,
        }
    }

    /// A stable identifier for logs: the subject, qualified by issuer, so two
    /// providers that both mint `sub = "admin"` do not collide in a log line.
    pub fn log_id(&self) -> String {
        format!("{}@{}", self.sub, self.iss)
    }
}

/// Accept `aud` as either a string or an array, and reject an empty value.
///
/// A token with no audience says who it is *not* for. That is the one thing
/// this API depends on, so an empty list is a rejection rather than a pass.
fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    let aud = match Audience::deserialize(deserializer)? {
        Audience::One(one) => vec![one],
        Audience::Many(many) => many,
    };

    if aud.is_empty() {
        return Err(serde::de::Error::custom("`aud` must not be empty"));
    }
    Ok(aud)
}
