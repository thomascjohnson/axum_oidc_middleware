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

/// The mechanical impls shared by the string identifiers in this module.
///
/// `Audience` and `AuthorizedParty` differ in what they mean and in the sentence
/// their constructor refuses with. Everything else — `Display`, equality,
/// hashing, the serde impls and the `TryFrom` conversions — is identical, and
/// writing it twice invites the two copies to drift apart in a way no test would
/// catch.
///
/// Each type's own constructor stays hand-written, because the message it emits
/// is the part an operator reads and the part that has to name the right field.
///
/// # Equality and hashing
///
/// Both are over the wrapped string, so a `Vec<Audience>` can be compared and a
/// `HashSet` can be built without the newtype changing what equality means.
///
/// # The serde split
///
/// `Serialize` is transparent, so a `Claims` value round-trips to the JSON it
/// came from and no host's log line changes shape. `Deserialize` accepts any
/// string, including a blank one: it is on the token path, where the value is
/// untrusted input rather than the operator's statement, and the gate that reads
/// it reports what it saw. Validation belongs in the constructor.
macro_rules! string_identifier {
    ($name:ident) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        // `Debug` keeps the quoting a `String` had, so `?vec` renders
        // `["my-audience"]` exactly as it did before this type existed. The
        // TRACE line in `extract` carries `aud`, and `tests/observability.rs`
        // pins its shape — a newtype must not quietly reformat a log line.
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.0, f)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl Eq for $name {}

        impl std::hash::Hash for $name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }

        // Comparison against a literal, so a host or a test can write
        // `claims.aud[0] == "myapp"`. This is convenience, not proof: it lets
        // an arbitrary string be compared, which is fine because no gate
        // decides anything from this operator.
        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        // So `Vec<Audience> == Vec<String>` compiles. `Vec`'s `PartialEq`
        // delegates to its elements, which is what lets a test compare a parsed
        // claim against the literals it was built from without a `map`.
        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                self.0 == *other
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer).map(Self)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = AuthError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = AuthError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&String> for $name {
            type Error = AuthError;

            fn try_from(value: &String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

/// One `aud` value a token may name: the resource this API is, as the issuer
/// writes it.
///
/// # Why a type rather than a `String`
///
/// Two lists are compared against two different claims, and both used to be
/// `Vec<String>`. Nothing stopped an `aud` list being checked against an `azp`
/// set, and `src/validator.rs` did exactly that kind of comparison on both. With
/// a distinct type per role, mixing them is a compile error rather than a test
/// that has to notice.
///
/// # The one asymmetry: `new` refuses blank, `Deserialize` does not
///
/// An empty audience can never match, so a blank entry in the *configuration* is
/// an outage disguised as a security control. The operator wrote it, so
/// [`Audience::new`] refuses it where they wrote it.
///
/// [`Claims::aud`](crate::Claims::aud) is a different matter. It records what
/// the issuer asserted, which is untrusted input. A blank entry there is already
/// refused by the audience gate, which names the value it saw. Rejecting it
/// during deserialisation would replace that message with a serde failure and
/// tell an operator less. So the wire shape is taken as it arrives, and the gate
/// decides.
#[derive(Clone)]
pub struct Audience(String);

impl Audience {
    /// Take one audience a token from this issuer may name.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] when `value` is empty. An entry nothing can
    /// ever name is a gate that never opens, which reads in a config file as
    /// though it permitted something.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AuthError::Configuration(
                "audience is empty; an entry nothing can name is a gate that never opens, \
                 not a gate that is off"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// The claim text, exactly as configured.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Take a value straight off the wire, without the blank check.
    ///
    /// For the token path only. `Claims::aud` records what the issuer
    /// asserted, and a blank entry there is untrusted input that the audience
    /// gate refuses by name. See the type's documentation for why the two
    /// constructors differ.
    pub(crate) fn from_wire(value: String) -> Self {
        Self(value)
    }
}

string_identifier!(Audience);

/// One `azp` value a token from a given issuer may name: the client that asked
/// for it.
///
/// # Why it is distinct from [`Audience`]
///
/// The two are different claims with different scopes, and the crate gates on
/// both. `aud` names a resource this API is; `azp` names the client the token
/// was minted for. `src/validator.rs` compares each against its own configured
/// list, and both lists used to be `Vec<String>`. A distinct type per role means
/// an `azp` list cannot be checked against an `aud` set by accident.
///
/// # Why the type does not carry the per-issuer rule
///
/// A client id is unique within a realm, not across realms, so an accepted `azp`
/// is deliberate about its issuer. That scoping is a property of
/// [`Issuer::authorized_parties`](crate::Issuer::authorized_parties), which owns
/// the list and the reasoning. This type only says what one entry is.
///
/// # The asymmetry, matched to [`Audience`]
///
/// [`AuthorizedParty::new`] refuses a blank entry, because an entry nothing can
/// name is a gate that never opens rather than a gate that is off — and the
/// operator wrote it. The serde `Deserialize` accepts what the token carried,
/// because `Claims::azp` is untrusted input and the gate reports it.
#[derive(Clone)]
pub struct AuthorizedParty(String);

impl AuthorizedParty {
    /// Take one client id a token from this issuer may name.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] when `value` is empty. Leave
    /// [`Issuer::authorized_party`](crate::Issuer::authorized_party) uncalled to
    /// turn the gate off for an issuer; do not name a blank client to do it.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AuthError::Configuration(
                "authorised party (`azp`) is empty; an entry nothing can name is a gate \
                 that never opens, not a gate that is off — omit \
                 `Issuer::authorized_party` for this issuer to leave it off"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    /// The claim text, exactly as configured.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_identifier!(AuthorizedParty);

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

    /// A blank audience is refused where the operator writes it.
    ///
    /// It can never match, so it locks every caller of that issuer out while
    /// reading in a config file as though it permitted something. The refusal
    /// used to happen at boot, in `AuthConfig::validate`; now it happens on the
    /// line that wrote the value, where the argument is still in view.
    #[test]
    fn a_blank_audience_is_refused_at_construction() {
        let err = Audience::new("").expect_err("a blank audience names nothing");

        assert!(
            matches!(err, AuthError::Configuration(_)),
            "the operator wrote this, so it is theirs to fix: {err:?}"
        );
        assert!(
            err.to_string().contains("audience is empty"),
            "say the audience is blank: {err}"
        );
    }

    /// The token path takes a blank entry as it arrives.
    ///
    /// `Claims::aud` records what the issuer asserted. Refusing a blank there
    /// would turn a rejection the audience gate explains into a serde failure
    /// inside `decode`, which names nothing. So the wire constructor skips the
    /// check and the gate does the refusing.
    #[test]
    fn the_wire_constructor_takes_a_blank_entry() {
        let blank = Audience::from_wire(String::new());
        assert_eq!(blank.as_str(), "");
        assert_eq!(blank, "", "it still compares as the text it holds");
    }

    /// The wire shape of a `Claims` value does not move.
    ///
    /// A host reads `aud` out of a verified token and may log or forward the
    /// JSON. Transparent serialisation is what keeps that from changing shape
    /// when the field became a newtype, and it is asserted rather than assumed.
    #[test]
    fn an_audience_serialises_as_a_bare_string() {
        let one = Audience::new("my-api").expect("an audience");
        assert_eq!(
            serde_json::to_string(&one).expect("an audience serialises"),
            "\"my-api\""
        );

        let list = vec![
            Audience::new("a").expect("an audience"),
            Audience::new("b").expect("an audience"),
        ];
        let json = serde_json::to_string(&list).expect("a list serialises");
        assert_eq!(json, "[\"a\",\"b\"]");
        assert_eq!(
            serde_json::from_str::<Vec<Audience>>(&json).expect("and reads back"),
            list
        );
    }

    /// Comparing against a literal compiles, which is what keeps a host's
    /// `if aud == "my-app"` readable.
    #[test]
    fn an_audience_compares_against_a_literal() {
        let aud = Audience::new("my-api").expect("an audience");
        assert_eq!(aud, "my-api");
        assert_eq!(aud, "my-api".to_owned());
        assert_ne!(aud, "other");
        // The `Vec` form delegates to the elements, which is how a test compares
        // a parsed claim against the literals it was built from.
        assert_eq!(vec![aud], vec!["my-api".to_owned()]);
    }

    /// A blank `azp` is refused where the operator writes it.
    ///
    /// The point is the one `Audience` makes, for the claim that is easiest to
    /// get wrong. Leaving `azp` unset is how you turn that issuer's gate off;
    /// naming a blank client is not, and it used to be caught only at boot.
    #[test]
    fn a_blank_authorized_party_is_refused_at_construction() {
        let err = AuthorizedParty::new("").expect_err("a blank client names nothing");

        assert!(
            matches!(err, AuthError::Configuration(_)),
            "the operator wrote this, so it is theirs to fix: {err:?}"
        );
        let reason = err.to_string();
        assert!(
            reason.contains("azp"),
            "name the claim, so the operator knows which setting to edit: {reason}"
        );
        assert!(
            reason.contains("Issuer::authorized_party"),
            "and name the way to leave the gate off instead: {reason}"
        );
    }

    /// An `azp` serialises as a bare string, so a `Claims` value keeps its
    /// shape across the newtype.
    #[test]
    fn an_authorized_party_serialises_as_a_bare_string() {
        let party = AuthorizedParty::new("my-client").expect("a client");
        assert_eq!(
            serde_json::to_string(&party).expect("a client serialises"),
            "\"my-client\""
        );

        let some = Some(AuthorizedParty::new("my-client").expect("a client"));
        let json = serde_json::to_string(&some).expect("an option serialises");
        assert_eq!(json, "\"my-client\"");
        assert_eq!(
            serde_json::from_str::<Option<AuthorizedParty>>(&json).expect("reads back"),
            some
        );

        let none = serde_json::from_str::<Option<AuthorizedParty>>("null").expect("null is absent");
        assert_eq!(none, None, "an explicit null is still no claim");
    }

    /// The two identifier types do not interchange, which is the reason each
    /// exists. This is a compile-time property, so what is checked here is the
    /// runtime half: they compare by their own text and never to each other.
    #[test]
    fn an_audience_and_a_client_are_different_types() {
        let aud = Audience::new("myapp").expect("an audience");
        let party = AuthorizedParty::new("myapp").expect("a client");

        // Same text, different roles. Neither can be passed where the other is
        // expected, so the only thing left to assert is that the text is kept.
        assert_eq!(aud.as_str(), party.as_str());
    }

    /// `{:?}` prints the claim text, and prints it once.
    ///
    /// `IssuerUrl` holds two spellings of the same issuer, and a derived `Debug`
    /// would print both. A reader looking at
    /// `IssuerUrl { raw: "https://accounts.google.com", url: "https://accounts.google.com/" }`
    /// in a panic message or a `tracing` field concludes the two fields disagree
    /// about the issuer and starts debugging the wrong thing. They do not: the
    /// slash is what a URL parser adds, and it is not part of the identifier.
    ///
    /// This is the same hazard `Audience` and `AuthorizedParty` dodged in the
    /// other direction — their `Debug` keeps a `String`'s quoting so the TRACE
    /// line in `extract` does not change shape. Here the risk is not the format
    /// of the line but the number of answers on it.
    #[test]
    fn the_debug_form_prints_the_claim_text_once() {
        let iss = IssuerUrl::parse("https://accounts.google.com").expect("a URL");

        assert_eq!(
            format!("{iss:?}"),
            "https://accounts.google.com",
            "one value, the one a token carries"
        );
        assert!(
            !format!("{iss:?}").ends_with('/'),
            "the parsed form of this issuer ends in a slash and the claim text does \n             not, so a printed slash means the derived form leaked: {iss:?}"
        );

        // And inside a container, which is how a test failure or a log line
        // actually prints it.
        assert_eq!(
            format!("{:?}", vec![iss]),
            r"[https://accounts.google.com]",
            "a list of issuers reads as a list of issuers"
        );
    }

    /// A map keyed by `IssuerUrl` answers the bare text a token carries.
    ///
    /// `Borrow<str>` is what lets `HashMap<IssuerUrl, _>::get` take the `&str`
    /// from an unverified payload instead of building an `IssuerUrl` first. It is
    /// only sound because `Hash` and `Eq` above are both over `raw`, and a `str`
    /// hashes and compares as the same bytes — a note on the impl itself, and one
    /// that is worth a test rather than a comment, since the failure mode of
    /// drift here is a *silent miss*: the lookup returns `None` for an issuer
    /// that is configured, and the caller reads that as "not trusted".
    ///
    /// The two refusals are the half that matters. Both strings parse to the same
    /// `Url` the key holds, so a map that keyed on the parsed form would hit.
    /// They are different issuers, and must miss.
    #[test]
    fn an_issuer_keyed_map_answers_the_text_a_token_carried() {
        use std::collections::HashMap;

        let mut gates: HashMap<IssuerUrl, Vec<Audience>> = HashMap::new();
        gates.insert(
            IssuerUrl::parse("https://EXAMPLE.example/realms/demo").expect("a URL"),
            vec![Audience::new("api").expect("an audience")],
        );

        assert!(
            gates.contains_key("https://EXAMPLE.example/realms/demo"),
            "the claim text alone selects the entry"
        );
        assert!(
            !gates.contains_key("https://example.example/realms/demo"),
            "the same issuer lowercased is a different `iss`, and must not be \
             served this entry"
        );
        assert!(
            !gates.contains_key("https://EXAMPLE.example/realms/demo/"),
            "a trailing slash is a different `iss` too"
        );
    }

    /// The wire form is the claim text, not the normalised URL.
    ///
    /// `IssuerUrl` has two fields and only one of them is on the wire, so
    /// `Serialize` is hand-written. A derived impl, or one that reached for
    /// `url()`, would make a `Claims` value re-serialise with a trailing slash
    /// the issuer never sent. A host that logs or forwards that JSON would then
    /// publish an `iss` that no token it ever verified carries.
    #[test]
    fn an_issuer_serialises_as_the_claim_text_not_the_normalised_url() {
        let iss = IssuerUrl::parse("https://accounts.google.com").expect("a URL");
        assert_eq!(
            iss.url().as_str(),
            "https://accounts.google.com/",
            "the two forms do differ here, which is what makes this worth asserting"
        );

        let json = serde_json::to_string(&iss).expect("an issuer serialises");
        assert_eq!(json, "\"https://accounts.google.com\"");

        let read = serde_json::from_str::<IssuerUrl>(&json).expect("and reads back");
        assert_eq!(read, iss, "a round trip keeps the identity");
        assert_eq!(read.as_str(), iss.as_str());
    }

    /// An `iss` that is not a string cannot reach a `Claims` value.
    ///
    /// `Deserialize` is strict for this type — unlike `Audience`, whose wire
    /// constructor is deliberately lenient — so it has a failure path of its own
    /// besides the parse: the value may not be a string at all. Neither path is
    /// reachable from `authenticate`, which pre-parses `iss` in `claimed_issuer`
    /// and refuses it there with a message that names the claim. What is pinned
    /// here is the invariant for a `Claims` value built from arbitrary JSON, the
    /// way a host that fetches a JWKS-shaped document or replays a recorded
    /// payload would build one.
    #[test]
    fn an_issuer_that_is_not_a_string_or_not_a_url_is_refused_on_the_wire() {
        for not_an_issuer in [serde_json::json!(5), serde_json::json!(true)] {
            let err = serde_json::from_value::<IssuerUrl>(not_an_issuer.clone())
                .expect_err("only a string can be an `iss`");
            assert!(
                err.to_string().contains("invalid type"),
                "{not_an_issuer}: {err}"
            );
        }

        // A string that is not an absolute URL is refused by the same call that
        // makes the type, so a `Claims` value cannot hold one either.
        let err =
            serde_json::from_value::<IssuerUrl>(serde_json::json!("keycloak.example/realms/demo"))
                .expect_err("a scheme-less `iss` is not an issuer");
        assert!(
            err.to_string().contains("is not a URL"),
            "the parse's own words survive the serde wrapper: {err}"
        );
    }

    /// Both identifiers borrow as the text they wrap.
    ///
    /// `AsRef<str>` is what lets a host hand an audience to a generic it did not
    /// write — a `BTreeMap` key, a hasher, a `display` log field — without
    /// unwrapping the newtype at every call site. `as_str` is the accessor a
    /// reader sees in the docs; this pins that the two never disagree, which is
    /// the only way the generic form can be trusted.
    #[test]
    fn both_identifiers_borrow_as_the_text_they_wrap() {
        let aud = Audience::new("my-api").expect("an audience");
        let party = AuthorizedParty::new("my-client").expect("a client");

        let aud_text: &str = aud.as_ref();
        let party_text: &str = party.as_ref();
        assert_eq!(aud_text, "my-api");
        assert_eq!(party_text, "my-client");
        assert_eq!(aud_text, aud.as_str(), "`as_ref` is `as_str`");
        assert_eq!(party_text, party.as_str());

        // Reachable through a generic, which is the reason the impl exists.
        fn shout(value: impl AsRef<str>) -> String {
            value.as_ref().to_uppercase()
        }
        assert_eq!(shout(&aud), "MY-API");
        assert_eq!(shout(&party), "MY-CLIENT");
    }

    /// A `HashSet` of either identifier keeps one entry per text.
    ///
    /// Hashing is over the wrapped string, so the newtype does not change what
    /// de-duplication means — the property the macro's own documentation claims.
    /// It is what lets a host collapse the audiences it read from a config file
    /// without mapping them back to `String` first, and what makes a
    /// `HashSet<AuthorizedParty>` of two realms' client ids refuse to merge
    /// values that only look alike.
    #[test]
    fn a_hash_set_of_either_identifier_keeps_one_entry_per_text() {
        use std::collections::HashSet;

        let audiences: HashSet<Audience> = ["api", "other", "api"]
            .into_iter()
            .map(|value| Audience::new(value).expect("an audience"))
            .collect();
        assert_eq!(
            audiences.len(),
            2,
            "the repeat collapses, so hashing is over the text"
        );
        assert!(
            audiences.contains(&Audience::new("api").expect("an audience")),
            "and a value built later still finds the entry"
        );
        assert!(!audiences.contains(&Audience::new("API").expect("an audience")));

        let parties: HashSet<AuthorizedParty> = ["client", "client", "other"]
            .into_iter()
            .map(|value| AuthorizedParty::new(value).expect("a client"))
            .collect();
        assert_eq!(parties.len(), 2, "the same rule for `azp`");
    }

    /// Comparison against a bare `str`, the third of the three spellings.
    ///
    /// `PartialEq<&str>` covers `aud == "my-api"` and `PartialEq<String>` covers
    /// `Vec<Audience> == Vec<String>`. This arm is the one a host reaches when
    /// the other side is the `str` behind a slice or a split — the `*` below is
    /// the spelling that selects it, and without the impl that line stops
    /// compiling. It is convenience, not proof: no gate in the crate decides
    /// anything from it.
    #[test]
    fn both_identifiers_compare_against_a_bare_str() {
        let aud = Audience::new("my-api").expect("an audience");
        let party = AuthorizedParty::new("my-client").expect("a client");

        let from_a_split = "my-api,other".split(',').next().expect("a first item");
        assert_eq!(aud, *from_a_split, "`Audience` against a `str`");
        assert_ne!(aud, *"nope");

        let client: &str = "my-client";
        assert_eq!(party, *client, "`AuthorizedParty` against a `str`");
        assert_ne!(party, *"my-api");
    }

    /// A value read from a config file builds either identifier.
    ///
    /// Config arrives as owned `String`s, and iterating a `Vec<String>` yields
    /// `&String`, not `&str`. Without `TryFrom<&String>` a host has to `.cloned()`
    /// or `.iter().map(String::as_str)` its own settings into the shape this
    /// crate asks for, which is exactly the friction that pushes callers to
    /// `unwrap` a conversion they should have to handle.
    ///
    /// The blank refusal is asserted too: the borrowed form refuses for the same
    /// reason and with the same words as the owned one, because it delegates
    /// rather than repeating the check.
    #[test]
    fn a_config_value_held_as_an_owned_string_builds_either_identifier() {
        let owned_audiences = vec!["my-api".to_owned(), "other-api".to_owned()];
        let issuer = crate::Issuer::discover("https://identity.example", owned_audiences.iter())
            .expect("audiences read from a file are still audiences");
        assert_eq!(issuer.audiences(), owned_audiences.as_slice());

        let owned_client = "my-client".to_owned();
        let issuer = issuer
            .authorized_party(&owned_client)
            .expect("a client read from a file is still a client");
        assert_eq!(issuer.authorized_parties(), [owned_client].as_slice());

        // Conversions called directly, including the case each one refuses.
        assert_eq!(
            Audience::try_from(&String::from("my-api")).expect("an audience"),
            Audience::new("my-api").expect("an audience")
        );
        assert_eq!(
            AuthorizedParty::try_from(&String::from("my-client")).expect("a client"),
            AuthorizedParty::new("my-client").expect("a client")
        );
        assert!(
            Audience::try_from(&String::new())
                .expect_err("a borrowed blank audience is still blank")
                .to_string()
                .contains("audience is empty")
        );
        assert!(
            AuthorizedParty::try_from(&String::new())
                .expect_err("a borrowed blank client is still blank")
                .to_string()
                .contains("azp")
        );
    }
}
