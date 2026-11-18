//! Configuration for [`Authenticator`](crate::Authenticator).

use std::time::Duration;

use url::{Host, Url};

use crate::error::AuthError;
use crate::jwks::CachePolicy;
use crate::types::{Audience, AuthorizedParty, IssuerUrl};

/// Ceiling for [`AuthConfig::leeway`], in seconds.
///
/// Five minutes is already generous for clock skew between machines that both
/// read NTP. Past that, "skew" means "tokens outlive their own revocation".
/// Two places enforce the limit, and they enforce it differently on purpose:
///
/// - [`AuthConfig::validate`] rejects a larger value outright. That is the
///   right answer on the public path: a misconfiguration must stop the process
///   at startup. It must not be quietly replaced with something the operator
///   did not write.
/// - `crate::validator::base_validation` clamps the value to this limit.
///   `from_registry` is crate-internal and deliberately bypasses `validate`,
///   and a library that panics on a configuration value is worse than one that
///   narrows it. Clamping also fails in the safe direction: the limit is the
///   stricter bound, so a runaway value tightens validation instead of
///   loosening it.
///
/// Both places name this constant so they cannot disagree about the limit.
pub(crate) const MAX_LEEWAY_SECS: u32 = 300;

/// Signature algorithms this API accepts.
///
/// This is a closed set of asymmetric algorithms by design. HMAC (`HS256` and
/// friends) cannot be selected at all. The classic algorithm-confusion attack
/// re-signs a token as `HS256` using the issuer's *public* key as the HMAC
/// secret. That attack requires HMAC to be acceptable. It never is here, so
/// that whole family is unreachable rather than merely discouraged.
///
/// A variant exists only if `jsonwebtoken` can verify it with this workspace's
/// features, and each one pins the shape of the key it needs. `RS*`/`PS*` need
/// `kty: RSA`. `ES256`/`ES384` need `kty: EC` on P-256 or P-384. `EdDSA` needs
/// `kty: OKP` on Ed25519. That is why there is no `ES512`. `jsonwebtoken`
/// does ECDSA on those two curves alone, so a P-521 JWK names a key that no
/// accepted algorithm can use. JWKS skips it rather than holding a key that is
/// trusted for nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256. Google and Keycloak both issue this.
    #[default]
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    Rs384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    Rs512,
    /// RSASSA-PSS with SHA-256.
    Ps256,
    /// ECDSA with SHA-256 on P-256 — `kty: EC`, `crv: P-256`. A Keycloak realm
    /// that rotated its realm key to EC issues this, and most non-Java
    /// providers issue it by default. Opt-in: accepted only when named in
    /// [`AuthConfig::algorithms`].
    Es256,
    /// ECDSA with SHA-384 on P-384 — `kty: EC`, `crv: P-384`.
    Es384,
    /// EdDSA on Ed25519 — `kty: OKP`, `crv: Ed25519`, and `EdDSA` in an `alg`.
    /// `jsonwebtoken` implements EdDSA on Ed25519 only, so the curve is in the
    /// name: no variant here accepts an Ed448 key.
    EdDSA,
}

impl SignatureAlgorithm {
    /// The `alg` header value, which is also what a JWK's `alg` says.
    pub fn jws_name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::EdDSA => "EdDSA",
        }
    }

    /// The `jsonwebtoken` equivalent.
    pub(crate) fn decoding(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::Rs256 => jsonwebtoken::Algorithm::RS256,
            Self::Rs384 => jsonwebtoken::Algorithm::RS384,
            Self::Rs512 => jsonwebtoken::Algorithm::RS512,
            Self::Ps256 => jsonwebtoken::Algorithm::PS256,
            Self::Es256 => jsonwebtoken::Algorithm::ES256,
            Self::Es384 => jsonwebtoken::Algorithm::ES384,
            Self::EdDSA => jsonwebtoken::Algorithm::EdDSA,
        }
    }

    /// Parse a JWS algorithm name. The comparison is case-sensitive, because
    /// `alg` values are case-sensitive. Accepting `rs256` would invent a
    /// dialect.
    ///
    /// Returns `None` for anything this crate will not verify. `none`, the HMAC
    /// family, `ES512`, `PS384`, `PS512`, and typos all return `None`. `ES512`,
    /// `PS384`, and `PS512` are sound algorithms that are not part of this set.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "RS256" => Some(Self::Rs256),
            "RS384" => Some(Self::Rs384),
            "RS512" => Some(Self::Rs512),
            "PS256" => Some(Self::Ps256),
            "ES256" => Some(Self::Es256),
            "ES384" => Some(Self::Es384),
            "EdDSA" => Some(Self::EdDSA),
            _ => None,
        }
    }
}

/// One trusted identity provider.
#[derive(Debug, Clone)]
pub struct Issuer {
    /// The exact `iss` claim value to require. Compared byte-for-byte:
    /// `https://example.com` and `https://example.com/` are different issuers
    /// to RFC 9068 validators, so this crate does not guess between them.
    ///
    /// Private, and typed, so no value reaches this field that did not parse.
    /// Read it with [`Self::iss`]. A `pub` field was the one route around the
    /// constructors: assigning a scheme-less string left `validate` to notice
    /// at boot, after an `Issuer` that looked settled already existed.
    iss: IssuerUrl,
    /// Where to fetch keys. `None` means discover the location from
    /// `<iss>/.well-known/openid-configuration`.
    pub jwks_url: Option<Url>,
    /// The `aud` values that a token *from this issuer* may name. Required.
    ///
    /// # Why this list is per issuer, and why it has no default
    ///
    /// Trusting several issuers is a union, and a union at this layer is the
    /// vulnerability, not the feature. With one flat list shared by every
    /// issuer, any issuer you trust can vouch for any audience you serve. A
    /// Google token that carries a Keycloak tenant's `aud` authenticates. In
    /// the multi-tenant case, a token minted for one customer's tool is
    /// accepted as another customer's. Which audiences a token is good for is a
    /// property of the issuer that signed it. So the list is stated here rather
    /// than beside the others.
    ///
    /// And it is stated *here*, because a list beside the others is a default,
    /// and a default is what makes the mistake invisible. There is no global
    /// audience set that an issuer inherits when it says nothing, so the
    /// question "which audiences does this issuer serve?" always has exactly
    /// one answer in the configuration, and reading it never requires knowing
    /// how many other issuers exist.
    ///
    /// Three things keep the unspecified state out. Both constructors take the
    /// set as a required argument, so an issuer that names no audience is a
    /// missing argument at the call site rather than a value that compiles.
    /// Both also refuse an empty iterator, so `Issuer::discover(iss, [])` is an
    /// error instead of an issuer that fails later — arity cannot see into an
    /// iterator, and this is the check arity cannot make. And the field is
    /// private, so no literal can be assembled around them.
    /// [`AuthConfig::validate`] repeats the check anyway, for the literals this
    /// module's own tests build.
    audiences: Vec<Audience>,
    /// The `azp` values that a token *from this issuer* may name. Optional.
    ///
    /// # Why this list is per issuer
    ///
    /// The same argument as [`Self::audiences()`], with a sharper edge. `azp`
    /// names a *client*, and a client id is unique within a realm, not across
    /// realms. Two Keycloak realms you trust can each carry a client called
    /// `my-app`. A single list shared by both therefore accepts a token minted
    /// for `my-app` in realm B at an API that means `my-app` in realm A. The
    /// `aud` layer above cannot catch this: in a stock realm `aud` is
    /// `"account"` for every API, so the two tokens look identical there.
    ///
    /// So `azp` is scoped to its issuer here too, and there is no global list
    /// to fall back on.
    ///
    /// # Why it is additive, and how it is off
    ///
    /// Keycloak sets `azp` to the `client_id` that requested the token, always,
    /// with no configuration. Its `aud` is a different story. The built-in
    /// `roles` client scope carries an "Audience Resolve" mapper. That mapper
    /// fills `aud` from the clients the user holds client roles on, so a stock
    /// realm produces `aud: ["account"]` for *every* API. Matching on `aud`
    /// alone then either rejects every legitimate caller or forces you to
    /// accept `"account"`, which distinguishes nothing.
    ///
    /// This crate enforces `azp` *in addition to* `aud`, never instead of it,
    /// and `aud` stays mandatory. There is no configuration in which satisfying
    /// either claim is enough. An OR over two identity fields is satisfied by
    /// whichever one the attacker's token happens to carry. A token here must
    /// name a trusted resource in `aud` **and** a trusted client in `azp`.
    ///
    /// Empty turns the gate off for this issuer alone, which is what an issuer
    /// that does not emit `azp` at all needs — Google does not, and a gate it
    /// can never satisfy is an outage. Where one deployment trusts both a
    /// Keycloak realm and Google, Keycloak can be gated and Google left alone,
    /// because the gate is per issuer.
    ///
    /// When the gate is on for an issuer, this crate rejects a token from that
    /// issuer with no `azp` claim rather than skipping the gate. A gate that
    /// absence can bypass is not a gate.
    ///
    /// Where you control the realm, the better fix is to give `aud` a real
    /// value with an audience mapper and leave this list empty. RFC 9068 makes
    /// `aud` required of a JWT access token and does not define `azp` at all.
    /// This option is Keycloak-shaped pragmatism, not a substitute for doing
    /// that.
    authorized_parties: Vec<AuthorizedParty>,
}

impl Issuer {
    /// Discover the JWKS location through OIDC discovery.
    ///
    /// The crate compares the discovery document's own `issuer` with `iss` at
    /// startup, so a document served by the wrong realm fails fast.
    ///
    /// `audiences` is required, and there is no way to ask for an issuer
    /// without naming it — see [`Issuer::audiences()`]. Gate on `azp` with
    /// [`Self::authorized_party`].
    pub fn discover(
        iss: impl TryInto<IssuerUrl, Error = AuthError>,
        audiences: impl IntoIterator<Item = impl TryInto<Audience, Error = AuthError>>,
    ) -> Result<Self, AuthError> {
        let iss = iss.try_into()?;
        Self::new(iss, None, audiences)
    }

    /// Skip discovery and name the JWKS endpoint directly. Use this for an
    /// issuer with no discovery document, or to keep discovery off the network
    /// path.
    ///
    /// `audiences` is required for the same reason [`Self::discover`] takes it.
    pub fn with_jwks_url(
        iss: impl TryInto<IssuerUrl, Error = AuthError>,
        jwks_url: Url,
        audiences: impl IntoIterator<Item = impl TryInto<Audience, Error = AuthError>>,
    ) -> Result<Self, AuthError> {
        let iss = iss.try_into()?;
        Self::new(iss, Some(jwks_url), audiences)
    }

    /// Both the issuer and its keys must use HTTPS: these answers establish
    /// trust, and HTTP lets anyone on the path answer them.
    fn new(
        iss: IssuerUrl,
        jwks_url: Option<Url>,
        audiences: impl IntoIterator<Item = impl TryInto<Audience, Error = AuthError>>,
    ) -> Result<Self, AuthError> {
        // The scheme is deliberately not looked at here. Whether http is
        // tolerable is a deployment-wide decision that [`AuthConfig::validate`]
        // enforces once. That lets tests build a loopback issuer while
        // production defaults to https-only.
        //
        // Emptiness, a scheme, a query and a fragment were all refused by
        // `IssuerUrl::parse` before this point, so this function has no URL
        // problem left to report.
        //
        // Arity cannot see inside an iterator, so `[]` reaches here. An empty
        // set is the *unspecified* state, not a settled one, and once there is
        // no deployment-wide list to inherit it has no reading but "any
        // audience". So it is refused here, at the only point that can see it,
        // rather than left for `validate` to catch after a caller already holds
        // an `Issuer` that looks fine.
        let audiences: Vec<Audience> = audiences
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<_, _>>()?;
        if audiences.is_empty() {
            return Err(AuthError::Configuration(format!(
                "issuer `{iss}` names no audiences; every trusted issuer must state \
                 the audiences its own tokens may carry — `Issuer::discover(iss, \
                 [AUDIENCE])` — because an issuer that names nothing and accepts \
                 everything lets a token minted for one purpose authenticate as any \
                 other"
            )));
        }

        Ok(Self {
            iss,
            jwks_url,
            // Non-empty by construction, so this line needs no note about an
            // unspecified state: there is no such value to hold here.
            audiences,
            // Empty is settled: it means the `azp` gate is off for this issuer.
            authorized_parties: Vec::new(),
        })
    }

    /// Add one more accepted `azp` for this issuer's tokens. Repeatable.
    ///
    /// The first call turns the gate on for *this issuer*; each one after admits
    /// another client. It cannot gate any other issuer — see
    /// [`Issuer::authorized_parties()`].
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] when `azp` is empty. A blank entry is a
    /// gate that never opens, and the way to leave the gate off is to not call
    /// this method at all. The blank check used to happen at boot, in
    /// `AuthConfig::validate`; it now happens here, where the argument is still
    /// in view.
    ///
    /// This returns `Result` rather than `Self`, which is why a caller of the
    /// builder chain needs one more `?`. Nothing that used to compile with a
    /// *valid* client compiles differently; only the blank case is new, and it
    /// is new as an error rather than as a value.
    pub fn authorized_party(
        mut self,
        azp: impl TryInto<AuthorizedParty, Error = AuthError>,
    ) -> Result<Self, AuthError> {
        self.authorized_parties.push(azp.try_into()?);
        Ok(self)
    }

    /// The `iss` value a token from this issuer must carry.
    ///
    /// Compared byte-for-byte, so the exact text the operator wrote is what a
    /// token has to match. There is no setter: the value is settled when the
    /// issuer is constructed.
    pub fn iss(&self) -> &IssuerUrl {
        &self.iss
    }

    /// The `aud` values a token from this issuer may name.
    pub fn audiences(&self) -> &[Audience] {
        &self.audiences
    }

    /// The `azp` values a token from this issuer may name, empty when that
    /// issuer's gate is off.
    pub fn authorized_parties(&self) -> &[AuthorizedParty] {
        &self.authorized_parties
    }

    /// Return `<iss>/.well-known/openid-configuration`, per RFC 8414 §3.1.
    pub(crate) fn discovery_url(&self) -> Url {
        self.iss.discovery_url()
    }
}

/// Everything needed to authenticate requests.
///
/// # Built with `empty()` and `with_*`
///
/// Describe a deployment with [`AuthConfig::empty`] and then one
/// [`Self::with_issuer`], [`Self::with_algorithms`], and so on per setting.
///
/// # Where the trust scope lives
///
/// `AuthConfig` has no audience field and no `azp` field. Both are stated on the
/// issuer they describe — [`Issuer::audiences()`] and
/// [`Issuer::authorized_parties()`], where the reasoning for that split lives.
/// [`Self::all_audiences()`] and [`Self::all_authorized_parties()`] derive a
/// union for reporting; neither is a second setting that could disagree with the
/// issuers.
///
/// What enforces the rule is the shape of [`Issuer`], not a field here. An
/// `Issuer` cannot be built without naming its audiences, and cannot be built
/// as a literal at all. `audiences` and `authorized_parties` are private, and
/// `iss` accepts only an [`IssuerUrl`], which is not something a literal can
/// conjure:
///
/// ```compile_fail
/// use axum_oidc_middleware::Issuer;
///
/// let issuer = Issuer {
///     iss: "https://identity.example".to_owned(), // the field takes an `IssuerUrl`
///     jwks_url: None,
///     audiences: vec![],
///     authorized_parties: vec![],
/// };
/// ```
///
/// Both barriers point the same way. A caller writes [`Issuer::discover`] or
/// [`Issuer::with_jwks_url`], and those parse the issuer and take the audience
/// set as a required argument.
///
/// Functional record update on `AuthConfig` still compiles, and that is fine:
/// every field it can carry is safe to write, and an `Issuer` in that vector
/// has already had to say what it serves.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Trusted issuers. Must not be empty. Each issuer carries the audiences
    /// its own tokens may name, and optionally the clients — see
    /// [`Issuer::audiences()`] and [`Issuer::authorized_parties()`].
    pub issuers: Vec<Issuer>,
    /// Accepted signing algorithms. Defaults to RS256 alone.
    pub algorithms: Vec<SignatureAlgorithm>,
    /// Clock skew tolerance in seconds, applied to `exp` and `nbf`.
    ///
    /// Keep this small. It is for the skew between unrelated machines, not for
    /// tolerating long-lived tokens. Every second here is a second a revoked or
    /// expired token still works.
    ///
    /// Unsigned, and deliberately narrow. `jsonwebtoken`'s `Validation::leeway`
    /// is a `u64`, so a signed field here had to be `as u64`-cast. A negative
    /// `i64` through that cast lands near `u64::MAX`, on the order of five
    /// hundred billion years of grace. One plausible typo, a minus signed on
    /// the wrong keystroke, would silently disable expiry and `nbf` for every
    /// token from every issuer. Nothing in the response or the logs would say
    /// so. The type is the guard: no value of this field turns expiry off.
    pub leeway: u32,
    /// JWKS fetching and caching.
    pub policy: CachePolicy,
    /// Permit `http` issuers and JWKS endpoints.
    ///
    /// **Off, and it should stay off.** The trust anchors are the discovery
    /// document that names a `jwks_uri` and the keys behind it. They must not
    /// be retrievable in cleartext, where anyone on the path can answer them
    /// and mint tokens at will. This exists for loopback tests against a stub
    /// issuer and for nothing else. A non-loopback `http` issuer is a
    /// vulnerability wearing a config flag.
    ///
    /// [`AuthConfig::validate`] also refuses a cleartext issuer whose host is
    /// not loopback, even when this is `true`. The flag therefore relaxes the
    /// transport only for a process on the same machine. Loopback means
    /// `127.0.0.0/8`, `::1`, and `localhost`.
    pub allow_insecure_http: bool,
}

/// Flatten a sequence of per-issuer lists into one union, keeping the first
/// occurrence of each value and therefore preserving issuer order.
///
/// Used only for the derived readbacks on [`AuthConfig`], never to decide that
/// a token is trusted. Order is stable so `audiences()` reads the same way
/// across runs, which matters in a startup log line and in test failures.
///
/// Takes the values rather than an `Issuer` and a way to pick a field off it.
/// The only two callers differ in which field they flatten, and that is a
/// question `flat_map` already answers at the call site.
fn union_of<'a, T>(values: impl IntoIterator<Item = &'a T>) -> Vec<T>
where
    T: Clone + PartialEq + 'a,
{
    let mut out: Vec<T> = Vec::new();
    for value in values {
        if !out.contains(value) {
            out.push(value.clone());
        }
    }
    out
}

/// Whether `url` names a host that can only be this machine.
///
/// The whole of `127.0.0.0/8` counts, not `127.0.0.1` alone. That block is
/// loopback on every platform this crate runs on, and a test binds whichever
/// address it picks.
///
/// `localhost` and its subdomains count too. That is how a test names a stub
/// issuer. The URL parser already lowercases and IDN-normalizes the domain
/// before this function sees it.
///
/// A URL with no host is not loopback. `file:///jwks.json` is not a place keys
/// come from.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(host)) => host.is_loopback(),
        Some(Host::Ipv6(host)) => host.is_loopback(),
        Some(Host::Domain(name)) => name == "localhost" || name.ends_with(".localhost"),
        None => false,
    }
}

impl AuthConfig {
    /// Trust nothing. Validation fails until an issuer exists, and every
    /// issuer states the audiences it serves.
    pub fn empty() -> Self {
        Self {
            issuers: Vec::new(),
            algorithms: vec![SignatureAlgorithm::default()],
            leeway: 30,
            policy: CachePolicy::default(),
            allow_insecure_http: false,
        }
    }

    /// Trust one more issuer. Repeatable.
    ///
    /// The issuer arrives already carrying the audiences *its own* tokens may
    /// name, because [`Issuer::discover`] will not return one that names none.
    /// There is no call on [`AuthConfig`] that supplies an audience to an
    /// issuer which did not ask for one.
    pub fn with_issuer(mut self, issuer: Issuer) -> Self {
        self.issuers.push(issuer);
        self
    }

    /// Trust every issuer in `issuers`. An existing [`Self::issuers`] vector is
    /// handed straight over, rather than a loop of [`Self::with_issuer`].
    ///
    /// Empty is not a valid end state: [`Self::validate`] refuses a config with
    /// no issuers. So this widens nothing that an empty config could not
    /// already reach.
    pub fn with_issuers(mut self, issuers: impl IntoIterator<Item = Issuer>) -> Self {
        self.issuers.extend(issuers);
        self
    }

    /// Accept exactly these signing algorithms, in place of the default.
    ///
    /// This replaces the set rather than adding to it, because the default is a
    /// decision and not a seed. [`Self::empty`] trusts RS256 alone, so a realm
    /// that moved to ECDSA has to *swap* the set. Adding `ES256` to it would
    /// leave RS256 acceptable, which is a wider trust boundary than the
    /// operator asked for. [`Self::validate`] refuses an empty set: an
    /// algorithm set nothing can verify is an outage, not a hardening.
    pub fn with_algorithms(
        mut self,
        algorithms: impl IntoIterator<Item = SignatureAlgorithm>,
    ) -> Self {
        self.algorithms = algorithms.into_iter().collect();
        self
    }

    /// Fetch and cache keys under `policy`.
    ///
    /// [`Self::empty`] carries [`CachePolicy::default`]. A test overrides the
    /// whole policy rather than one field, because the fields trade against
    /// each other. A `min_fetch_gap` longer than the `timeout` would let a
    /// request wait out the fetch it is waiting for.
    pub fn with_policy(mut self, policy: CachePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Permit `http` issuers and JWKS endpoints, if `allow`.
    ///
    /// Off unless asked for, and it should stay off. The discovery document and
    /// the keys behind it are the trust anchors, and over cleartext anyone on
    /// the path can answer for them. Loopback tests against a stub issuer are
    /// the only legitimate use — see the field documentation.
    ///
    /// [`AuthConfig::validate`] enforces that limit: with this flag on, a
    /// cleartext URL is still refused unless its host is loopback. The flag
    /// therefore cannot widen cleartext to the internet, only relax the transport
    /// for a process on the same machine.
    pub fn with_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// Every `aud` any configured issuer serves: the union over the issuers, in
    /// issuer order, deduplicated.
    ///
    /// The `all_` prefix is doing work. This is the deployment-wide answer, and
    /// it reads against the per-issuer one,
    /// [`Issuer::audiences()`](Issuer::audiences), which is what decides whether
    /// a particular token may name a particular audience. There is no
    /// deployment-wide *setting* for this to silently disagree with: the value is
    /// derived, so it can only contain an audience some issuer named, and it
    /// contains every one of those.
    ///
    /// Two consumers. The verifier's base validation hands it to `jsonwebtoken`'s
    /// audience gate, the outer of the two gates — a union is right there because
    /// it is the widest set the deployment ever intended, and the narrow question
    /// is answered after the signature by the per-issuer set. A host also logs it
    /// at startup. Neither reads it as permission for one token.
    pub fn all_audiences(&self) -> Vec<Audience> {
        union_of(self.issuers.iter().flat_map(|issuer| &issuer.audiences))
    }

    /// Every `azp` named by any configured issuer, empty when no issuer gates
    /// on `azp`.
    ///
    /// Reporting only. Nothing enforces this list: an entry is accepted only
    /// from the issuer that named it, which is the pairing
    /// [`Issuer::authorized_parties()`](Issuer::authorized_parties) carries. The
    /// `all_` prefix is the warning label rather than decoration. One list of
    /// accepted clients, consulted for every issuer, is what let a client id
    /// from one realm pass at another. This accessor aggregates for a log line
    /// and never for a decision.
    pub fn all_authorized_parties(&self) -> Vec<AuthorizedParty> {
        union_of(
            self.issuers
                .iter()
                .flat_map(|issuer| &issuer.authorized_parties),
        )
    }

    /// Return why the crate must not fetch `url` for its trust anchors. Return
    /// `None` when it may fetch it.
    ///
    /// The scheme must be https. `allow_insecure_http` relaxes that for a
    /// loopback host only — see [`Self::allow_insecure_http`].
    ///
    /// `what` names the setting in the message and carries its value. An
    /// operator reads one line at boot. That line has to say which issuer and
    /// which flag.
    ///
    /// The relaxation used to be unbounded. Once an operator set the flag,
    /// `http://oidc.example.com` passed validation. A deployment that set the
    /// flag for a stub issuer could then ship it to production. The host test
    /// leaves the documented use — a stub issuer on `127.0.0.1` — as the only
    /// use.
    fn cleartext_problem(&self, url: &Url, what: &str) -> Option<String> {
        if url.scheme() == "https" {
            return None;
        }

        if !self.allow_insecure_http {
            return Some(format!(
                "{what} uses `{}`. This crate requires https. Set allow_insecure_http \
                 only for an issuer on loopback.",
                url.scheme()
            ));
        }

        if is_loopback(url) {
            return None;
        }

        // Two different shapes reach this point. A remote host is a transport
        // question: whoever sits between this process and that host answers for
        // the trust anchors. A URL with no host at all is not an issuer, and a
        // message about its host would describe a host that is not there.
        let why = match url.host() {
            Some(_) => format!(
                "{what} uses `{}` on a host that is not loopback. Anyone on the path to \
                 that host can serve the discovery document and the keys that decide who \
                 authenticates.",
                url.scheme()
            ),
            None => format!(
                "{what} uses `{}` and names no host, so it is not an issuer reachable \
                 over https.",
                url.scheme()
            ),
        };

        Some(format!(
            "{why} allow_insecure_http admits an issuer on 127.0.0.1, ::1, or localhost \
             only."
        ))
    }

    /// Refuse a configuration that would silently weaken authentication.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Configuration`] naming everything wrong, so a
    /// deployment misconfiguration is one log line rather than a bisect.
    pub fn validate(&self) -> Result<(), AuthError> {
        let mut problems: Vec<String> = Vec::new();

        if self.issuers.is_empty() {
            problems.push("no trusted issuers configured".to_owned());
        }
        if self.algorithms.is_empty() {
            problems.push("no allowed signature algorithms".to_owned());
        }
        if self.leeway > MAX_LEEWAY_SECS {
            problems.push(format!(
                "leeway of {}s is outside 0..={MAX_LEEWAY_SECS}s",
                self.leeway
            ));
        }
        if self.policy.timeout < Duration::from_millis(100) {
            problems
                .push("provider timeout is under 100ms, which will only cause failures".to_owned());
        }
        if self.policy.min_fetch_gap < Duration::from_secs(1) {
            problems.push(
                "JWKS min_fetch_gap under 1s lets forged tokens hammer the issuer".to_owned(),
            );
        }

        // Duplicate detection compares the claim text, which is
        // `IssuerUrl`'s identity. Two entries for one `iss` mean two trust
        // decisions about the same provider, and those can disagree — which is
        // what this rule is for.
        //
        // Emptiness and a missing scheme are not checked here. `IssuerUrl`
        // cannot hold either, so the constructors refuse both before an
        // `Issuer` exists. The check moved to the line that writes the value,
        // which is also the line whose argument a reader can still see.
        let mut seen: Vec<&IssuerUrl> = Vec::new();
        for issuer in &self.issuers {
            if seen.contains(&&issuer.iss) {
                problems.push(format!("issuer `{}` is listed twice", issuer.iss));
            }
            seen.push(&issuer.iss);

            // The scheme gate lives here, not in `Issuer`'s constructors and not
            // in `IssuerUrl`, so exactly one place decides whether cleartext is
            // tolerable. That place is off unless a caller says otherwise, and
            // even then it reaches loopback only.
            //
            // The URL comes off the value rather than being re-parsed from a
            // string. It is the same parse the constructor did, kept instead of
            // discarded.
            if let Some(problem) =
                self.cleartext_problem(issuer.iss.url(), &format!("issuer `{}`", issuer.iss))
            {
                problems.push(problem);
            }

            if let Some(keys) = &issuer.jwks_url
                && let Some(problem) = self.cleartext_problem(keys, &format!("JWKS URL `{keys}`"))
            {
                problems.push(problem);
            }

            // ── This issuer's own scope ──────────────────────────────────────
            //
            // One rule remains here, stated per issuer since there is no
            // deployment-wide list left to check an issuer against.
            //
            // * Naming no audience is refused for *every* issuer, not merely a
            //   second one. There is no ceiling left for an unspecified issuer
            //   to fall back on, and "no audience" read as "any audience" is
            //   the vulnerability the per-issuer list exists to close. The
            //   constructors already refuse an empty iterator, so this is the
            //   backstop for the field-by-field literals this module's tests
            //   build — the one shape a private field still permits, in here.
            //
            // Two checks that used to sit beside it are gone, not weakened.
            // A blank audience and a blank `azp` both used to be caught here,
            // because both were `String` and either could be blank. Now
            // `Audience::new` and `AuthorizedParty::new` refuse one where the
            // operator writes it, and `AuthorizedParty` has no other
            // constructor at all — `AuthorizedParty::new` is the only way to
            // build one inside this crate or outside it. Neither value exists
            // in a blank state, so a check for that state could only be dead
            // code wearing the look of a safeguard.
            if issuer.audiences.is_empty() {
                problems.push(format!(
                    "issuer `{iss}` names no audiences; every trusted issuer must \
                     state the audiences its own tokens may carry — \
                     `Issuer::discover(iss, [AUDIENCE])` — because an issuer \
                     that names nothing and accepts everything lets a token \
                     minted for one purpose authenticate as any other. With no \
                     global audience list to inherit, there is no value here \
                     that means \"whatever the deployment serves\"",
                    iss = issuer.iss,
                ));
            }
            if issuer
                .audiences
                .iter()
                .any(|audience| audience.as_str().is_empty())
            {
                problems.push(format!(
                    "issuer `{}` is configured with an empty audience",
                    issuer.iss
                ));
            }
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(AuthError::Configuration(problems.join("; ")))
        }
    }

    /// Algorithm names, for JWK `alg` comparison.
    pub(crate) fn algorithm_names(&self) -> Vec<String> {
        self.algorithms
            .iter()
            .map(|alg| alg.jws_name().to_owned())
            .collect()
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty `iss` is refused at the public constructors, not at boot.
    ///
    /// Both `discover` and `with_jwks_url` take `impl TryInto<IssuerUrl>`, so the
    /// blank value is refused while the argument is still in view. This test
    /// pins that the refusal reaches the caller unchanged, rather than being
    /// swallowed or restated as a URL that would not parse — which would send
    /// an operator looking for a typo in a string they left blank.
    ///
    /// The state is worth refusing rather than tolerating because an issuer
    /// keyed on `""` is not inert. It becomes a slot in the registry that no
    /// token can ever name. The `iss` claim of a real token is never the empty
    /// string, so gate 2 never selects it. It also takes part in `validate`'s
    /// duplicate-issuer scan and in the count of configured issuers. So a
    /// deployment reads as "two issuers trusted" while one of them is
    /// unreachable by construction.
    ///
    /// The guard itself now lives in [`IssuerUrl::parse`], which is where the
    /// blank value is first seen. What is left to check here is the plumbing:
    /// that neither constructor has a path around it.
    #[test]
    fn an_empty_issuer_is_refused_at_the_choice_point() {
        for err in [
            Issuer::discover("", ["api"]).expect_err("an empty `iss` is not an issuer"),
            Issuer::with_jwks_url(
                "",
                Url::parse("https://issuer.example/jwks.json").expect("a JWKS URL"),
                ["api"],
            )
            .expect_err("an empty `iss` is not an issuer"),
        ] {
            assert!(
                matches!(err, AuthError::Configuration(_)),
                "the operator set this, so it is theirs to fix: {err:?}"
            );
            assert!(
                err.to_string().contains("issuer is empty"),
                "say it is blank; 'would not parse as a URL' describes the symptom and \
                 sends them looking for a typo: {err}"
            );
        }
    }

    /// The empty audience set is refused where it is created, not at boot.
    ///
    /// Arity cannot see inside an iterator, so `[]` compiles and reaches `new`.
    /// Refusing it there means an `Issuer` that exists always names at least one
    /// audience, and a caller learns about the mistake on the line that made it
    /// rather than from a boot failure in another file, which is where the
    /// constructor arguments are no longer in view.
    ///
    /// `validate` keeps its own check for the literals this module can still
    /// build, and both halves are pinned here. The backstop is not decoration:
    /// it is the branch that reads "this issuer named nothing" as a refusal
    /// instead of "anything".
    #[test]
    fn an_issuer_with_no_audiences_is_refused_at_the_choice_point() {
        let err = Issuer::discover("https://identity.example", Vec::<String>::new())
            .expect_err("naming no audience is not an issuer");

        assert!(
            matches!(err, AuthError::Configuration(_)),
            "the operator wrote this, so it is theirs to fix: {err:?}"
        );
        let reason = err.to_string();
        assert!(
            reason.contains("names no audiences") && reason.contains("identity.example"),
            "the message must name the issuer that said nothing: {reason}"
        );

        let literal = Issuer {
            iss: IssuerUrl::parse("https://identity.example").expect("a URL"),
            jwks_url: None,
            audiences: Vec::new(),
            authorized_parties: Vec::new(),
        };
        let refused = AuthConfig::empty().with_issuer(literal).validate();
        assert!(
            matches!(
                refused,
                Err(AuthError::Configuration(ref reason)) if reason.contains("names no audiences")
            ),
            "an empty set that reached a literal must still not boot: {refused:?}"
        );
    }

    /// `discovery_url` cannot be reached with an issuer that is not a URL.
    ///
    /// This used to be a runtime guard inside `discovery_url`, which took a
    /// `Result` and reported `is not a URL` on the scheme-less case. The guard
    /// is gone because the case is gone: `IssuerUrl` cannot hold a string that
    /// did not parse, so a scheme-less issuer never becomes an `Issuer` at all.
    ///
    /// The regression this pins is a *trust* one. RFC 8414 §3.1 derives the
    /// discovery location by surgery on `iss`, and the document fetched from
    /// there names the `jwks_uri` whose keys decide who authenticates. A
    /// location derived from a half-written identifier would ask a server the
    /// operator did not name. Derivation is now infallible precisely because
    /// the input is a type that cannot be wrong.
    ///
    /// The literal below is built *inside* this module, which is the only place
    /// an `Issuer` can be assembled field-by-field. Every field is typed or
    /// private, so even that route cannot produce a scheme-less `iss`: the only
    /// way to obtain an `IssuerUrl` is [`IssuerUrl::parse`].
    #[test]
    fn a_scheme_less_issuer_never_reaches_discovery() {
        let err = Issuer::discover("keycloak.example/realms/demo", ["api"])
            .expect_err("a scheme-less issuer has no well-known location to derive");

        assert!(
            matches!(err, AuthError::Configuration(_)),
            "a missing scheme is the operator's to fix: {err:?}"
        );
        assert!(
            err.to_string().contains("is not a URL"),
            "name the field that is wrong, and do not fall through to a URL built \
             out of nothing: {err}"
        );
    }
}
