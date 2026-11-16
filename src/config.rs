//! Configuration for [`Authenticator`](crate::Authenticator).

use std::time::Duration;

use url::{Host, Url};

use crate::error::AuthError;
use crate::jwks::CachePolicy;

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
    pub iss: String,
    /// Where to fetch keys. `None` means discover the location from
    /// `<iss>/.well-known/openid-configuration`.
    pub jwks_url: Option<Url>,
    /// The `aud` values that a token *from this issuer* may name.
    ///
    /// # Why the audience set is per issuer
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
    /// Every entry must also appear in [`AuthConfig::audiences`], which is the
    /// ceiling. This list only narrows within it
    /// ([`AuthConfig::issuer_audiences`]).
    ///
    /// Empty means "the whole ceiling". [`AuthConfig::validate`] allows that
    /// for a lone issuer: with one issuer the ceiling *is* its audience set, so
    /// existing single-issuer deployments need no new setting. Validation
    /// refuses it for a second issuer. Leaving an issuer unspecified in a
    /// multi-issuer topology is exactly the confusion this field exists to
    /// close.
    pub audiences: Vec<String>,
}

impl Issuer {
    /// Discover the JWKS location through OIDC discovery.
    ///
    /// The crate compares the discovery document's own `issuer` with `iss` at
    /// startup, so a document served by the wrong realm fails fast.
    pub fn discover(iss: impl Into<String>) -> Result<Self, AuthError> {
        let iss = iss.into();
        let url = Url::parse(&iss).map_err(|err| {
            AuthError::Configuration(format!("issuer `{iss}` is not a URL: {err}"))
        })?;
        Self::new(iss, url, None)
    }

    /// Skip discovery and name the JWKS endpoint directly. Use this for an
    /// issuer with no discovery document, or to keep discovery off the network
    /// path.
    pub fn with_jwks_url(iss: impl Into<String>, jwks_url: Url) -> Result<Self, AuthError> {
        let iss = iss.into();
        Self::new(
            iss.clone(),
            Url::parse(&iss).map_err(|err| {
                AuthError::Configuration(format!("issuer `{iss}` is not a URL: {err}"))
            })?,
            Some(jwks_url),
        )
    }

    /// Both the issuer and its keys must use HTTPS: these answers establish
    /// trust, and HTTP lets anyone on the path answer them.
    fn new(iss: String, url: Url, jwks_url: Option<Url>) -> Result<Self, AuthError> {
        if iss.is_empty() {
            return Err(AuthError::Configuration("issuer is empty".to_owned()));
        }
        // The code does not look at the scheme here. Whether http is tolerable
        // is a deployment-wide decision that [`AuthConfig::validate`] enforces
        // once. That lets tests build a loopback issuer while production
        // defaults to https-only.
        if url.query().is_some() || url.fragment().is_some() {
            return Err(AuthError::Configuration(format!(
                "issuer `{iss}` must not carry a query or fragment"
            )));
        }
        Ok(Self {
            iss,
            jwks_url,
            // Empty here is the *unspecified* state, not a settled one. It
            // survives `validate` only when this is the only issuer, where it
            // means "accept the whole ceiling".
            audiences: Vec::new(),
        })
    }

    /// Add one more `aud` for this issuer's tokens. Repeatable.
    ///
    /// Naming an audience that is not in [`AuthConfig::audiences`] is a
    /// startup error rather than a silent narrowing. The request path
    /// intersects the two lists, so such an entry could never match a real
    /// token. A deployment whose callers can never satisfy it is an outage
    /// waiting to be mistaken for a bug in the client.
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.audiences.push(aud.into());
        self
    }

    /// Return `<iss>/.well-known/openid-configuration`, per RFC 8414 §3.1.
    pub(crate) fn discovery_url(&self) -> Result<Url, AuthError> {
        let mut url = Url::parse(&self.iss).map_err(|err| {
            AuthError::Configuration(format!(
                "issuer `{iss}` is not a URL: {err}",
                iss = self.iss
            ))
        })?;
        // RFC 8414 appends to the issuer's path. `set_path` replaces the path
        // rather than joining it, so the code carries the existing path
        // through. Dropping it would send every Keycloak realm's discovery
        // request to `/`.
        let path = url.path().to_string();
        let path = if path.ends_with('/') {
            format!("{path}.well-known/openid-configuration")
        } else {
            format!("{path}/.well-known/openid-configuration")
        };
        url.set_path(&path);
        Ok(url)
    }
}

/// Everything needed to authenticate requests.
///
/// # Built with `empty()` and `with_*`, not a struct literal
///
/// Describe a deployment with [`AuthConfig::empty`] and then one
/// [`Self::with_audience`], [`Self::with_issuer`], [`Self::with_algorithms`],
/// and so on per setting. That is the same shape [`Issuer`] uses. Functional
/// record update (`AuthConfig { issuers, ..AuthConfig::empty() }`) no longer
/// compiles, even for a site that names no audiences:
///
/// ```compile_fail
/// use axum_oidc_middleware::{AuthConfig, Issuer};
///
/// let config = AuthConfig {
///     issuers: vec![Issuer::discover("https://identity.example").unwrap()],
///     ..AuthConfig::empty()
/// };
/// ```
///
/// Record update requires *every* field to be visible at the site, and the
/// audience ceiling is deliberately not visible. So the shape of the type now
/// enforces the rule the ceiling exists to hold. No `AuthConfig` reaches the
/// verifier before its caller names an audience set through
/// [`Self::with_audience`]. The per-issuer lists are then compared against it.
/// The cost is real: every construction goes through the builders. The cost is
/// accepted, because the alternative is a public field that can be left out of
/// a literal by accident.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Trusted issuers. Must not be empty. Each issuer carries the audiences
    /// its own tokens may name — see [`Issuer::audiences`].
    pub issuers: Vec<Issuer>,
    /// The audience **ceiling**: every `aud` any issuer may ever be accepted
    /// for. Required. The audience gate cannot be turned off.
    ///
    /// Without a ceiling at all, this crate accepts a token minted for any
    /// other client of the same issuer. That makes the issuer's whole client
    /// roster part of your trust boundary. With a ceiling but no per-issuer
    /// lists, every issuer serves every audience in it. That is why
    /// [`Issuer::audiences`] is mandatory as soon as a second issuer appears.
    ///
    /// # Why it is private
    ///
    /// The old public `audiences: Vec<String>` was the flattened union that
    /// made one issuer able to vouch for another's audience, so the shape is
    /// gone rather than repurposed. Reads go through [`Self::audiences`] and
    /// writes through [`Self::with_audience`]. A per-issuer list can only be
    /// read back as [`Self::issuer_audiences`] — narrowed by this field. There
    /// is no longer a way to hand the verifier an audience set that the ceiling
    /// does not already cover.
    audiences: Vec<String>,
    /// Accepted `azp` (authorised party) values — the client that asked for
    /// the token. Empty means the gate is off, which is the default.
    ///
    /// # Why this exists, and why it is additive
    ///
    /// Keycloak sets `azp` to the `client_id` that requested the token, always,
    /// with no configuration. Its `aud` is a different story. The built-in
    /// `roles` client scope carries an "Audience Resolve" mapper. That mapper
    /// fills `aud` from the clients the user holds client roles on, so a stock
    /// realm produces `aud: ["account"]` for *every* API. Matching on `aud`
    /// alone then either rejects every legitimate caller or forces you to
    /// accept `"account"`, which distinguishes nothing.
    ///
    /// So this crate enforces `azp` *in addition to* `aud`, never instead of
    /// it, and `aud` stays mandatory. There is no configuration in which
    /// satisfying either claim is enough. An OR over two identity fields is
    /// satisfied by whichever one the attacker's token happens to carry. A
    /// token here must name a trusted resource in `aud` **and** a trusted
    /// client in `azp`.
    ///
    /// When you configure `azp`, this crate rejects a token with no `azp` claim
    /// rather than skipping the gate. A gate that absence can bypass is not a
    /// gate.
    ///
    /// Where you control the realm, the better fix is to give `aud` a real
    /// value with an audience mapper and leave this list empty. RFC 9068 makes
    /// `aud` required of a JWT access token and does not define `azp` at all.
    /// This option is Keycloak-shaped pragmatism, not a substitute for doing
    /// that.
    pub authorized_parties: Vec<String>,
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
    /// Trust nothing. Validation fails until an issuer exists and a ceiling is
    /// named.
    pub fn empty() -> Self {
        Self {
            issuers: Vec::new(),
            audiences: Vec::new(),
            authorized_parties: Vec::new(),
            algorithms: vec![SignatureAlgorithm::default()],
            leeway: 30,
            policy: CachePolicy::default(),
            allow_insecure_http: false,
        }
    }

    /// Add one audience to the ceiling.
    ///
    /// This widens the set, and it is deliberately spelled as an action. An
    /// issuer can only ever narrow what this list allows. So the only way to
    /// accept a new `aud` anywhere is to say so here.
    pub fn with_audience(mut self, aud: impl Into<String>) -> Self {
        self.audiences.push(aud.into());
        self
    }

    /// Trust one more issuer. Repeatable.
    ///
    /// The issuer carries the audiences *its own* tokens may name — see
    /// [`Issuer::audience`]. So an issuer added without any is a statement that
    /// it is served by the whole ceiling. [`Self::validate`] permits that for a
    /// lone issuer and refuses it for a second one. That is the point of making
    /// each issuer say so rather than sharing one list.
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

    /// Accept `azp` from one more client. Repeatable.
    ///
    /// The empty list means the gate is off, so this only ever narrows. The
    /// first call turns the gate on, and every one after it admits another
    /// client alongside the rest. See [`Self::authorized_parties`] for why
    /// `azp` narrows `aud` rather than standing in for it.
    pub fn with_authorized_parties(
        mut self,
        parties: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.authorized_parties
            .extend(parties.into_iter().map(Into::into));
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

    /// The ceiling: every `aud` any issuer may be accepted for.
    ///
    /// This answers "is this audience servable at all". It is *not* the answer
    /// to "is this audience servable for this issuer". That answer is
    /// [`Self::issuer_audiences`], and a token has to satisfy both.
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// The audiences a token from `issuer` may name: `issuer`'s own list,
    /// narrowed by [`Self::audiences`].
    ///
    /// # Why the narrowing cannot be skipped, or escaped
    ///
    /// Both branches return a subset of the ceiling, and neither is a rule a
    /// caller has to remember:
    ///
    /// * `issuer.audiences`, because [`Self::validate`] refuses the one shape
    ///   that could name an audience outside the ceiling. So after validation,
    ///   the intersection and the list are the same set.
    /// * the ceiling itself for the lone issuer that named nothing, which by
    ///   definition contains it.
    ///
    /// Returning a borrow is the point. The request path reads this, and
    /// intersect-then-clone per request would allocate to recompute a set that
    /// cannot change after startup. [`Authenticator::start`](crate::Authenticator::start)
    /// therefore intersects once per issuer and keeps the result. So the
    /// verifier enforces a value that came out of intersection, even if some
    /// caller hand-built an [`Authenticator`](crate::Authenticator) without
    /// validating.
    pub fn issuer_audiences<'a>(&'a self, issuer: &'a Issuer) -> &'a [String] {
        if issuer.audiences.is_empty() {
            return &self.audiences;
        }
        &issuer.audiences
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
        if self.audiences.iter().any(String::is_empty) || self.audiences.is_empty() {
            problems.push(
                "no non-empty audience configured; audience checking cannot be disabled".to_owned(),
            );
        }
        if self.algorithms.is_empty() {
            problems.push("no allowed signature algorithms".to_owned());
        }
        // A blank in this list would be a gate that can never pass, which is
        // an outage disguised as a security control.
        if self.authorized_parties.iter().any(String::is_empty) {
            problems
                .push("an authorised party (`azp`) is configured as an empty string".to_owned());
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

        let mut seen: Vec<&str> = Vec::new();
        for issuer in &self.issuers {
            if issuer.iss.is_empty() {
                problems.push("issuer is empty".to_owned());
            }
            if seen.contains(&issuer.iss.as_str()) {
                problems.push(format!("issuer `{}` is listed twice", issuer.iss));
            }
            seen.push(issuer.iss.as_str());

            // The scheme gate lives here, not in `Issuer`'s constructors, so
            // exactly one place decides whether cleartext is tolerable. That
            // place is off unless a caller says otherwise, and even then it
            // reaches loopback only.
            match Url::parse(&issuer.iss) {
                Ok(url) => {
                    if let Some(problem) =
                        self.cleartext_problem(&url, &format!("issuer `{}`", issuer.iss))
                    {
                        problems.push(problem);
                    }
                }
                Err(_) => problems.push(format!("issuer `{}` is not a URL", issuer.iss)),
            }

            if let Some(keys) = &issuer.jwks_url
                && let Some(problem) = self.cleartext_problem(keys, &format!("JWKS URL `{keys}`"))
            {
                problems.push(problem);
            }

            // ── This issuer's slice of the audience ceiling ──────────────────
            //
            // Two rules, both decided at boot because both are invisible at
            // request time:
            //
            // * An entry outside the ceiling could never match. The verifier
            //   intersects each issuer's list with the ceiling, so a stray
            //   `aud` here describes a caller that can never be authenticated.
            //   Refuse the configuration instead of shipping a filter nothing
            //   can satisfy.
            // * Naming nothing is tolerable for the only issuer and forbidden
            //   for a second one. With one issuer the ceiling already *is* its
            //   audience set. That covers every deployment that predates this
            //   field, so asking it to restate the obvious buys nothing. With
            //   two, an unspecified issuer accepts the whole ceiling, which
            //   re-creates the exact cross-issuer confusion the per-issuer
            //   layer exists to close. So that topology must state what each
            //   issuer is for, and state it before serving a request.
            if issuer.audiences.iter().any(String::is_empty) {
                problems.push(format!(
                    "issuer `{}` is configured with an empty audience",
                    issuer.iss
                ));
            }
            if issuer.audiences.is_empty() && self.issuers.len() > 1 {
                problems.push(format!(
                    "issuer `{iss}` names no audiences while {count} issuers are \
                     trusted; each issuer must state the audiences its own tokens \
                     may carry — `Issuer::audience` in code, \
                     `--issuer-audience {iss}=<AUDIENCE>` on the command line — \
                     because one audience list shared by {count} issuers lets a \
                     token minted for one of them authenticate as all of them",
                    iss = issuer.iss,
                    count = self.issuers.len(),
                ));
            }
            for aud in &issuer.audiences {
                if !self.audiences.contains(aud) {
                    problems.push(format!(
                        "issuer `{}` names audience `{aud}`, which the global \
                         audience list does not contain; the global list is the \
                         ceiling and a per-issuer audience can only narrow within \
                         it",
                        issuer.iss
                    ));
                }
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

    /// The one function that both constructors funnel through rejects an empty
    /// `iss`.
    ///
    /// Neither `discover` nor `with_jwks_url` can produce it, because each runs
    /// `Url::parse(iss)` first and `""` does not parse. That is why this test
    /// lives here rather than in `tests/`. Through the public surface, an empty
    /// issuer is reported as a URL that would not parse. That sends an operator
    /// to look for a typo in a string they left blank. The guard below is what
    /// makes the diagnosis match the mistake, and it is exercised only by
    /// coming at `new` from inside the module.
    ///
    /// The state is worth refusing rather than tolerating because an issuer
    /// keyed on `""` is not inert. It becomes a slot in the registry that no
    /// token can ever name. The `iss` claim of a real token is never the empty
    /// string, so gate 2 never selects it. It also takes part in `validate`'s
    /// duplicate-issuer scan and in the count of configured issuers. So a
    /// deployment reads as "two issuers trusted" while one of them is
    /// unreachable by construction.
    #[test]
    fn an_empty_issuer_is_refused_at_the_choice_point() {
        let url = Url::parse("https://issuer.example/jwks.json").expect("a JWKS URL");

        let err =
            Issuer::new(String::new(), url, None).expect_err("an empty `iss` is not an issuer");

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

    /// `discovery_url` refuses to invent a location for an issuer that is not a
    /// URL.
    ///
    /// `AuthConfig::validate` parses `iss` too and reports `issuer `x` is not a
    /// URL`, so an `Authenticator` built by `start` never reaches this line.
    /// That is the same shadowing that hides the guard above, and the same
    /// reason to pin it directly. `discovery_url` is `pub(crate)`, and the next
    /// caller of it does not have to come through `start`. RFC 8414 §3.1
    /// derives the discovery location by string surgery on `iss`. So a non-URL
    /// `iss` that reached this function would yield a parse panic. Or, if the
    /// scheme is permissive, a URL pointing somewhere the issuer does not live. A discovery document fetched from the wrong place is then a *trust*
    /// problem, not a configuration one.
    ///
    /// The test builds the `Issuer` below as a literal on purpose. Its fields
    /// are `pub` so a host can assemble one from its own config type. That is
    /// the route that bypasses both constructors and their parse.
    #[test]
    fn a_non_url_issuer_never_yields_a_discovery_location() {
        let issuer = Issuer {
            iss: "keycloak.example/realms/demo".to_owned(), // the scheme went missing
            jwks_url: None,
            audiences: Vec::new(),
        };

        let err = issuer
            .discovery_url()
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
