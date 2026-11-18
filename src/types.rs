//! The identifier types this crate decides with.
//!
//! Each one moves a rule that used to be checked by [`AuthConfig::validate`]
//! into the type that carries it. The point is not tidiness. A `String` issuer
//! could be replaced after construction, so `validate` had to re-derive the URL
//! it had already parsed, and a caller could hand the crate an issuer no
//! constructor ever saw. A field typed [`IssuerUrl`] cannot hold that value, so
//! the check happens once, where the operator writes the value.
//!
//! [`AuthConfig::validate`]: crate::AuthConfig::validate

use std::fmt;

use url::Url;

use crate::error::AuthError;

/// The `iss` of one trusted issuer: the exact claim text, with its parsed form.
///
/// # What the type guarantees
///
/// Every value of this type satisfies all of the following, established at
/// construction and never re-checked:
///
/// - it is not empty;
/// - it parses as an absolute URL, so a scheme is present;
/// - it carries no query and no fragment.
///
/// # What it deliberately does not guarantee
///
/// **The scheme is not constrained.** Whether cleartext is tolerable is a
/// deployment-wide decision, made once by
/// [`AuthConfig::validate`](crate::AuthConfig::validate) against
/// `allow_insecure_http`. It is not a property of one issuer, so it is not a
/// property of this type. Moving it here would either ban `http` outright — and
/// the crate's own integration suite runs on a stub issuer at
/// `http://127.0.0.1` — or duplicate the loopback rule in a second place that
/// could disagree with the first.
///
/// # Why both forms are kept
///
/// `iss` is compared **byte for byte**. `https://example.com` and
/// `https://example.com/` are different issuers, and this crate does not guess
/// between them.
///
/// A URL parser normalises, so the parsed form is not the claim text:
///
/// ```text
/// https://accounts.google.com  ->  https://accounts.google.com/   (a slash is added)
/// https://EXAMPLE.com/foo      ->  https://example.com/foo        (the host is lowercased)
/// ```
///
/// A type that stored only the [`Url`] would therefore compare the normalised
/// text. `Issuer::discover("https://accounts.google.com", ..)` would then
/// require the slash, and Google — which does not send one — would fail every
/// token. So the claim text is kept as written, and every comparison, every
/// log line and every error message uses it. The [`Url`] is derived state: it
/// answers discovery and the scheme check, and it takes no part in identity.
#[derive(Clone)]
pub struct IssuerUrl {
    /// The exact `iss` claim value. Comparisons, `Display` and hashing use
    /// this and nothing else.
    raw: String,
    /// The parsed form, for deriving the discovery location and for the
    /// scheme decision in `AuthConfig::validate`.
    url: Url,
}

impl IssuerUrl {
    /// Parse an issuer identifier.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] when `iss` is empty, is not an absolute
    /// URL, or carries a query or a fragment. All three are values the
    /// operator wrote, so all three are theirs to fix, and all three are
    /// reported on the line that wrote them rather than at boot.
    pub fn parse(iss: &str) -> Result<Self, AuthError> {
        // Refused before the parse, so the diagnosis names a blank setting
        // rather than "this does not parse", which would send an operator
        // looking for a typo in a value they left empty on purpose.
        if iss.is_empty() {
            return Err(AuthError::Configuration("issuer is empty".to_owned()));
        }

        // `Url::parse` requires a scheme, so `keycloak.example/realms/demo`
        // fails here with `RelativeUrlWithoutBase`. The absolute-URL rule and
        // the parse are therefore the same call, not two.
        let url = Url::parse(iss).map_err(|err| {
            AuthError::Configuration(format!("issuer `{iss}` is not a URL: {err}"))
        })?;

        // A query or a fragment is not part of an issuer identifier. RFC 8414
        // §3.1 appends the well-known path to the issuer's *path*, so either
        // one would be dropped or mangled when the discovery location is
        // derived. Refusing them keeps the two forms below describing the same
        // place.
        if url.query().is_some() || url.fragment().is_some() {
            return Err(AuthError::Configuration(format!(
                "issuer `{iss}` must not carry a query or fragment"
            )));
        }

        Ok(Self {
            raw: iss.to_owned(),
            url,
        })
    }

    /// The exact `iss` claim text.
    ///
    /// This is what an incoming token's `iss` is compared against, and the
    /// only value that may be used to make that comparison.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The parsed form.
    ///
    /// For places that need URL semantics rather than the claim text: deriving
    /// the discovery location, and the scheme/host decision in
    /// [`AuthConfig::validate`](crate::AuthConfig::validate).
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Return `<iss>/.well-known/openid-configuration`, per RFC 8414 §3.1.
    ///
    /// Infallible, because the string parsed when this value was made. The
    /// path is carried through rather than replaced: a Keycloak realm lives at
    /// `/realms/<name>`, and sending its discovery request to `/` would ask the
    /// wrong server entirely.
    pub(crate) fn discovery_url(&self) -> Url {
        let mut url = self.url.clone();
        let path = url.path().to_owned();
        let path = if path.ends_with('/') {
            format!("{path}.well-known/openid-configuration")
        } else {
            format!("{path}/.well-known/openid-configuration")
        };
        url.set_path(&path);
        url
    }
}

impl fmt::Display for IssuerUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl fmt::Debug for IssuerUrl {
    /// Delegates to `Display` rather than showing both forms.
    ///
    /// The parsed URL is derived state, and printing it beside the claim text
    /// invites a reader to compare the two and conclude they disagree about
    /// the issuer. They do not: the slash a normaliser adds is not part of the
    /// identifier.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// Identity is the claim text alone.
//
// Not derived, because deriving would compare `url` as well. Two distinct
// claim texts can normalise to one URL — `https://EXAMPLE.com` and
// `https://example.com` — and those are different issuers to this crate. Deriving
// would merge them in a `HashMap` and let one issuer's keys answer for the
// other.
impl PartialEq for IssuerUrl {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for IssuerUrl {}

impl std::hash::Hash for IssuerUrl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl std::borrow::Borrow<str> for IssuerUrl {
    /// Borrow as the claim text, so a `HashMap<IssuerUrl, _>` can be read with
    /// the `&str` from a token without building an `IssuerUrl` first.
    ///
    /// Sound with respect to `Hash` and `Eq` above only because `&str`
    /// equality is `raw` equality. Any change to that is a change to this.
    fn borrow(&self) -> &str {
        &self.raw
    }
}

impl TryFrom<&str> for IssuerUrl {
    type Error = AuthError;

    fn try_from(iss: &str) -> Result<Self, Self::Error> {
        Self::parse(iss)
    }
}

impl TryFrom<String> for IssuerUrl {
    type Error = AuthError;

    fn try_from(iss: String) -> Result<Self, Self::Error> {
        Self::parse(&iss)
    }
}

impl TryFrom<&String> for IssuerUrl {
    type Error = AuthError;

    fn try_from(iss: &String) -> Result<Self, Self::Error> {
        Self::parse(iss)
    }
}

impl serde::Serialize for IssuerUrl {
    /// Serialises as the claim text, so a `Claims` value still round-trips to
    /// the JSON it came from. `#[serde(transparent)]` is not usable here
    /// because this type has two fields, only one of which is on the wire.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> serde::Deserialize<'de> for IssuerUrl {
    /// Parses, so a `Claims` value cannot hold an `iss` this type would not.
    ///
    /// Strict on purpose, and it costs nothing on the token path:
    /// `claimed_issuer` parses the same string *before* `jsonwebtoken` decodes
    /// the payload, so a malformed `iss` is reported there with a message that
    /// names it. By the time this runs the string is known to parse, so the
    /// error below is unreachable from `authenticate` and exists only to keep
    /// the invariant for a `Claims` built from arbitrary JSON.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason the type keeps two forms.
    ///
    /// A URL parser adds a trailing slash to a bare host, and a trailing slash
    /// makes a different issuer. If the claim text were dropped in favour of
    /// `Url::as_str`, the README's Google example would store
    /// `https://accounts.google.com/` and reject every real Google token.
    #[test]
    fn a_bare_host_keeps_the_claim_text_it_was_given() {
        let iss = IssuerUrl::parse("https://accounts.google.com").expect("a URL");

        assert_eq!(iss.as_str(), "https://accounts.google.com");
        assert_eq!(
            iss.url().as_str(),
            "https://accounts.google.com/",
            "the parsed form is normalised, which is exactly why it is not used for identity"
        );
        assert_ne!(
            iss,
            IssuerUrl::parse("https://accounts.google.com/").expect("a URL"),
            "a trailing slash is a different issuer"
        );
        assert_eq!(iss.to_string(), "https://accounts.google.com");
    }

    /// A scheme-less identifier is refused where it is written.
    ///
    /// This used to be found by `AuthConfig::validate`, after an `Issuer` that
    /// looked fine already existed. `Url::parse` rejects it as
    /// `RelativeUrlWithoutBase`, and that is the same call that establishes
    /// every other guarantee, so the failure moves to the line that wrote the
    /// value.
    #[test]
    fn a_scheme_less_issuer_is_refused_at_construction() {
        let err = IssuerUrl::parse("keycloak.example/realms/demo")
            .expect_err("a scheme-less issuer is not a URL");

        assert!(
            matches!(err, AuthError::Configuration(_)),
            "the operator wrote this, so it is theirs to fix: {err:?}"
        );
        assert!(
            err.to_string().contains("is not a URL"),
            "name the field that is wrong: {err}"
        );
    }

    /// An empty identifier is named as blank, not as unparseable.
    ///
    /// "Would not parse as a URL" describes the symptom of an empty string and
    /// sends the operator looking for a typo in a value they never filled in.
    #[test]
    fn an_empty_issuer_is_named_as_blank() {
        let err = IssuerUrl::parse("").expect_err("an empty `iss` is not an issuer");

        assert!(
            err.to_string().contains("issuer is empty"),
            "say it is blank: {err}"
        );
    }

    /// A query or a fragment is refused, because derivation would drop it.
    #[test]
    fn a_query_or_fragment_is_refused() {
        for bad in [
            "https://identity.example/?a=b",
            "https://identity.example/#frag",
        ] {
            let err = IssuerUrl::parse(bad).expect_err("an issuer carries neither");
            assert!(
                err.to_string()
                    .contains("must not carry a query or fragment"),
                "{bad}: {err}"
            );
        }
    }

    /// The realm path survives derivation, and a bare host gains the well-known
    /// path without doubling a slash.
    #[test]
    fn discovery_keeps_the_issuer_path() {
        let realm = IssuerUrl::parse("https://sso.example.com/realms/demo").expect("a URL");
        assert_eq!(
            realm.discovery_url().as_str(),
            "https://sso.example.com/realms/demo/.well-known/openid-configuration"
        );

        let bare = IssuerUrl::parse("https://accounts.google.com").expect("a URL");
        assert_eq!(
            bare.discovery_url().as_str(),
            "https://accounts.google.com/.well-known/openid-configuration"
        );
    }

    /// Two claim texts that normalise to one URL stay distinct as map keys.
    ///
    /// This is the `HashMap` consequence of comparing `raw` and not `url`.
    /// Merging them would let one issuer's keys answer for the other.
    #[test]
    fn normalising_to_the_same_url_does_not_merge_two_issuers() {
        use std::collections::HashSet;

        let upper = IssuerUrl::parse("https://EXAMPLE.com/foo").expect("a URL");
        let lower = IssuerUrl::parse("https://example.com/foo").expect("a URL");
        assert_eq!(upper.url(), lower.url(), "they do normalise to one URL");

        let mut set = HashSet::new();
        set.insert(upper);
        set.insert(lower);
        assert_eq!(set.len(), 2, "but they are two different issuers");
    }
}
