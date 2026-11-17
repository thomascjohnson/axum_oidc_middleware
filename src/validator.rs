//! The verifier: pick a trust bundle, verify the signature, enforce the claims.
//!
//! # The algorithm set is per key, not per authenticator
//!
//! `jsonwebtoken` 12 does not tolerate an `algorithms` list that spans key
//! families. [`verify_signature_body`] rejects a token unless *every*
//! algorithm in `Validation::algorithms` shares the family of the token's own
//! `alg`. That verifier, built from `alg` plus the selected key, is already
//! built to fail on a key of any other family. One `Validation` per
//! authenticator therefore cannot cover a realm with more than one key type.
//! Such a realm needs the list narrowed per request, to the family that the
//! selected `kid` actually names.
//!
//! A single `Validation` carrying `[RS256, ES256]` rejected *every* token in
//! such a realm. `jsonwebtoken` rejected the RSA token because `ES256` sat in
//! the list, and it rejected the EC token because `RS256` sat there. That is an
//! auth outage on the exact configuration EC support exists to make possible.
//! That is why [`FamilyValidations`], rather than one `Validation`, sits in
//! [`Inner`].
//!
//! Narrowing is the only direction this moves the trust boundary. The set
//! `decode` receives is `configured ∩ family(selected key)`, a subset of what
//! the operator configured. [`Authenticator::authenticate`] still rejects an
//! unconfigured `alg` from the header before the crate reads a key. So this is
//! never where an algorithm becomes *chosen*, only where the impossible ones
//! drop out.
//!
//! [`verify_signature_body`]: https://docs.rs/jsonwebtoken/12.0.0/src/jsonwebtoken/decoding.rs.html

use std::collections::HashMap;
use std::sync::Arc;

use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, Validation, decode_header};
use serde::Deserialize;
use tracing::{debug, warn};
use url::Url;

use crate::claims::Claims;
use crate::config::{AuthConfig, Issuer, SignatureAlgorithm};
use crate::error::AuthError;
use crate::jwks::{CachePolicy, JwksRegistry};

/// Verifies bearer tokens from one or more OIDC issuers.
///
/// This is cheap to clone and safe to share. Wrap it in axum state or a tower
/// extension. An `Authenticator` exists only after `start` accepts the
/// configuration and loads every issuer's keys. So "authentication is
/// working" is a startup fact rather than a first-request surprise.
#[derive(Debug, Clone)]
pub struct Authenticator {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    keys: JwksRegistry,
    /// One `Validation` per key family. See [`FamilyValidations`].
    validations: FamilyValidations,
    /// Every configured algorithm, the union of the per-family sets. The crate
    /// tests this set against the token header before it reads a key. So this,
    /// not the per-family selection, is what keeps `none` and HMAC unreachable.
    allowed: Vec<Algorithm>,
    /// Every `aud` any configured issuer asked for, derived once here so the
    /// accessor is allocation-free. **Reporting only — no gate reads it.**
    ///
    /// The union `jsonwebtoken` enforces is a different value with a different
    /// lifetime: [`base_validation`] builds it from the config, and that is what
    /// `set_audience` receives. This copy exists so
    /// [`Authenticator::all_audiences`] can answer without re-walking the issuers at
    /// call time. The `_for_reporting` suffix is the point. An earlier shape of
    /// this struct kept one `Vec` of accepted audiences and the verifier read
    /// it, so any trusted issuer could vouch for any audience the deployment
    /// served. The field must not be able to grow back into that by being
    /// reached for out of habit.
    audiences_for_reporting: Vec<String>,
    /// Per-issuer audience sets, keyed by the exact `iss`, copied once here
    /// rather than walked per request.
    ///
    /// Two gates run on `aud`, and both must pass. The `Validation` behind
    /// [`FamilyValidations::for_key`] requires the union; this gate requires
    /// the *issuer's own* set. So a token minted for one issuer's audience is
    /// refused by an authenticator that also trusts another issuer for it, which
    /// is the confusion a single shared list re-creates.
    ///
    /// Every entry comes straight from an `Issuer` that had to name at least
    /// one audience to exist. There is no ceiling to intersect with and no
    /// inherit branch: the answer for an issuer is the list on that issuer.
    issuer_audiences: HashMap<String, Vec<String>>,
    /// Every `azp` named by any issuer, derived once, for the accessor.
    /// Reporting only — nothing here accepts a token, and the name says so.
    authorized_parties_for_reporting: Vec<String>,
    /// Per-issuer `azp` sets, keyed by the exact `iss`. An entry is the set of
    /// clients accepted *from that issuer*, and the `azp` gate is off for an
    /// issuer whose entry is empty.
    ///
    /// The key is the verified `iss` rather than a union because a client id is
    /// unique within a realm, not across realms. The reasoning, and the swap a
    /// shared list would allow, are on
    /// [`Issuer::authorized_parties()`](crate::Issuer::authorized_parties).
    issuer_authorized_parties: HashMap<String, Vec<String>>,
}

impl Authenticator {
    /// Discover every issuer, load its keys, and reject an unusable
    /// configuration.
    ///
    /// This fails fast on an unreachable issuer, a bad URL, or a discovery
    /// document whose `issuer` disagrees with the one configured. Each of
    /// those would otherwise show up as every request failing.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] for unusable settings,
    /// [`AuthError::ProviderUnavailable`] when an issuer cannot be reached or
    /// publishes no usable keys.
    pub async fn start(config: AuthConfig) -> Result<Self, AuthError> {
        config.validate()?;

        let algorithm_names = config.algorithm_names();
        let mut issuers: Vec<(String, Url)> = Vec::with_capacity(config.issuers.len());

        for issuer in &config.issuers {
            let jwks_url = match &issuer.jwks_url {
                Some(url) => url.clone(),
                None => discover(issuer, config.allow_insecure_http).await?,
            };
            issuers.push((issuer.iss.clone(), jwks_url));
        }

        let registry = JwksRegistry::new(
            issuers,
            &algorithm_names,
            config.policy,
            config.allow_insecure_http,
        )?;
        registry.warm_up().await?;

        Ok(Self::from_registry(registry, &config))
    }

    /// Build from an already-warm registry. This lets tests inject keys
    /// without a network, and lets a host cache JWKS however it likes.
    pub(crate) fn from_registry(keys: JwksRegistry, config: &AuthConfig) -> Self {
        let base = base_validation(config);
        let validations = FamilyValidations::new(&base, &config.algorithms);

        // The pre-key gate: every configured algorithm, across every family.
        // This is deliberately the union rather than any one family's list, so
        // the per-family narrowing below can only ever shrink what this already
        // allowed. It can never name an algorithm the operator did not.
        let allowed = config
            .algorithms
            .iter()
            .map(|algorithm| algorithm.decoding())
            .collect();

        // Each issuer's accepted audience set and accepted `azp` set, resolved
        // once. Both are copied straight off the `Issuer`, not derived from a
        // deployment-wide list: the `Issuer` is the only place either scope is
        // stated, and `validate` already refused an issuer that named no
        // audience.
        let issuer_audiences: HashMap<String, Vec<String>> = config
            .issuers
            .iter()
            .map(|issuer| (issuer.iss.clone(), issuer.audiences().to_vec()))
            .collect();
        let issuer_authorized_parties: HashMap<String, Vec<String>> = config
            .issuers
            .iter()
            .map(|issuer| (issuer.iss.clone(), issuer.authorized_parties().to_vec()))
            .collect();

        Self {
            inner: Arc::new(Inner {
                keys,
                allowed,
                validations,
                audiences_for_reporting: config.all_audiences(),
                issuer_audiences,
                authorized_parties_for_reporting: config.all_authorized_parties(),
                issuer_authorized_parties,
            }),
        }
    }

    /// The issuers whose tokens this crate accepts.
    pub fn issuers(&self) -> impl Iterator<Item = &str> {
        self.inner.keys.issuers()
    }

    /// Every `aud` any configured issuer asked for, across all of them.
    ///
    /// This is not what a given token may name. Two issuers serving different
    /// audiences report the union here and the narrow set only through
    /// [`Self::issuer_audiences`], because the narrow set is what the verifier
    /// enforces. It is derived from the issuers, not set beside them — see
    /// [`AuthConfig::all_audiences`].
    ///
    /// Reporting only, like the field behind it: this is the union of what
    /// [`Self::issuer_audiences`] answers for each issuer, never a set a token is
    /// checked against on its own. `the_reporting_unions_match_the_per_issuer_sets`
    /// pins the two to the same value. The `all_` prefix marks the width, so a
    /// caller cannot mistake it for the narrower answer beside it.
    pub fn all_audiences(&self) -> &[String] {
        &self.inner.audiences_for_reporting
    }

    /// The `aud` values a token from `iss` may name, or `None` when no such
    /// issuer is configured. This is the set the audience gate enforces.
    pub fn issuer_audiences(&self, iss: &str) -> Option<&[String]> {
        self.inner.issuer_audiences.get(iss).map(Vec::as_slice)
    }

    /// Every `azp` named by any configured issuer, empty when none gates on
    /// `azp`.
    ///
    /// Reporting only, like the field behind it. An entry here is accepted only
    /// from the issuer that named it, which is what
    /// [`Self::issuer_authorized_parties`] holds. This is the union of those
    /// per-issuer sets, not a set any gate consults.
    pub fn all_authorized_parties(&self) -> &[String] {
        &self.inner.authorized_parties_for_reporting
    }

    /// The `azp` values a token from `iss` may name, or `None` when no such
    /// issuer is configured. An empty slice means that issuer's `azp` gate is
    /// off, and it is off for that issuer alone.
    pub fn issuer_authorized_parties(&self, iss: &str) -> Option<&[String]> {
        self.inner
            .issuer_authorized_parties
            .get(iss)
            .map(Vec::as_slice)
    }

    /// The per-issuer audience gate. It runs once the verified `iss` is known.
    ///
    /// This is the half of the audience decision that cannot live in
    /// `Validation`. A token's issuer is only *known* after its signature
    /// passes. Picking a per-issuer `Validation` from the unverified `iss` would
    /// choose a trust decision from a claim that verification has not yet
    /// proven. So `decode` enforces the union of every issuer's audiences and
    /// this gate enforces the one issuer's set, one gate on top of the other.
    /// Both must pass. This one can only ever refuse: a token that named
    /// nothing acceptable would have failed the union gate already.
    ///
    /// A missing entry is a refusal rather than a pass-through. It is
    /// unreachable for an authenticator built by `start`: every configured
    /// issuer gets an entry, and one statement earlier the signature bound `iss`
    /// to a configured issuer. But an empty entry reads fail-closed as "this
    /// issuer has no configured audience". A default that accepted would bring
    /// the vulnerability back through a `HashMap::get`.
    fn check_issuer_audience(&self, claims: &Claims) -> Result<(), AuthError> {
        match self.inner.issuer_audiences.get(&claims.iss) {
            Some(accepted) if claims.aud.iter().any(|aud| accepted.contains(aud)) => Ok(()),
            Some(_) => Err(AuthError::InvalidToken(format!(
                "`aud` {} is not an audience issuer `{}` is trusted for here",
                aud_hint(&claims.aud),
                claims.iss
            ))),
            None => Err(AuthError::InvalidToken(format!(
                "no audience is accepted for issuer `{}`",
                claims.iss
            ))),
        }
    }

    /// The authorised-party gate. It runs after everything else passed, and it
    /// is scoped to the issuer that signed the token.
    ///
    /// This is deliberately a second gate rather than an alternative audience
    /// rule. A token already named a trusted `aud` for its own issuer to get
    /// here, so this can only ever narrow the callers the crate accepts, never
    /// widen them. Substituting `azp` for `aud` would accept whichever of the
    /// two a token happened to carry.
    ///
    /// The accepted set is looked up under the verified `iss`, which is the whole
    /// point of the lookup. A client id is unique within a realm, not across
    /// realms, so one shared list would let realm B's `my-app` authenticate where
    /// realm A's is meant to — see
    /// [`Issuer::authorized_parties()`](crate::Issuer::authorized_parties) for why
    /// `aud` cannot catch that swap either.
    ///
    /// An empty set means that issuer gates on nothing — which is what an issuer
    /// that never emits `azp` needs, and it is off for that issuer alone. When
    /// the set is not empty, a missing `azp` is a rejection. Otherwise an absent
    /// claim would defeat the gate.
    ///
    /// A missing entry refuses, like [`Self::check_issuer_audience`]. Both maps
    /// are keyed off the same `config.issuers`, so neither can be missing one
    /// the other has. The message names the missing fact rather than reporting an
    /// empty client list, because the two have different fixes: a blank list is a
    /// policy choice, and an issuer with no entry is a config that drifted from
    /// its keys.
    fn check_authorised_party(&self, claims: &Claims) -> Result<(), AuthError> {
        let accepted = self
            .inner
            .issuer_authorized_parties
            .get(&claims.iss)
            .ok_or_else(|| {
                AuthError::InvalidToken(format!("issuer `{}` is not configured", claims.iss))
            })?;
        if accepted.is_empty() {
            return Ok(());
        }

        match claims.azp.as_deref() {
            Some(azp) if accepted.iter().any(|party| party == azp) => Ok(()),
            // Distinguished in the message only. Both are the same refusal,
            // and `azp`-absent versus `azp`-unexpected is enough to tell a
            // misconfigured client scope apart from the wrong client. The
            // issuer is named because the accepted set is its own.
            Some(other) => Err(AuthError::InvalidToken(format!(
                "`azp` `{other}` is not an authorised party for issuer `{}` here",
                claims.iss
            ))),
            None => Err(AuthError::InvalidToken(format!(
                "token from issuer `{}` has no `azp` claim, which this API requires \
                 from that issuer",
                claims.iss
            ))),
        }
    }

    /// Verify a token and return its claims.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidToken`] when the token is not trustworthy,
    /// [`AuthError::ProviderUnavailable`] when the issuer could not be
    /// consulted, [`AuthError::Configuration`] for an unusable algorithm.
    #[tracing::instrument(level = "debug", err(Debug), skip_all)]
    pub async fn authenticate(&self, token: &str) -> Result<Claims, AuthError> {
        let token = token.trim();
        if token.is_empty() {
            return Err(AuthError::MissingToken);
        }

        // ── 1. Header: is this an algorithm we can even consider? ────────────
        let header = decode_header(token)
            .map_err(|err| AuthError::InvalidToken(format!("unreadable JWT header: {err}")))?;

        // Reject a disallowed `alg` before touching keys. `none` and the HMAC
        // family die here, which is what makes algorithm confusion unreachable
        // rather than merely unlikely. `decode_header` has already rejected an
        // `alg` it cannot name. This rejects the ones it can, such as `HS256`.
        if !self.inner.allowed.contains(&header.alg) {
            return Err(AuthError::InvalidToken(format!(
                "algorithm `{:?}` is not accepted",
                header.alg
            )));
        }

        // ── 1b. Does this token demand anything we do not implement? ────────
        //
        // RFC 7515 §4.1.11: a `crit` entry names header extensions the
        // recipient MUST understand, and "the JWS MUST be rejected" if any of
        // them are not. This verifier implements no extensions. It has no
        // decompression, no claim constraints, and no per-recipient keys, so
        // any `crit` value names something it cannot honour, and an empty one
        // declares a demand it never fills.
        //
        // What is deliberately NOT rejected here is an unrecognised header that
        // is not listed in `crit`. §4 is explicit that unknown members MUST be
        // ignored, and rejecting them would break interop with every IdP that
        // adds a private parameter. `crit` is the sole switch that turns
        // "ignore me" into "refuse me". An issuer that set it to require a
        // tenant-isolation gate this server does not have would otherwise
        // receive a successful verification.
        //
        // `jsonwebtoken` 12 checks `crit` inside `decode` and refuses an empty
        // list there. That check runs after this one, and its reason names
        // nothing. The crate therefore keeps its own rule, so the messages below
        // stay specific whatever upstream decides next.
        if let Some(critical) = header.crit.as_deref() {
            if critical.is_empty() {
                return Err(AuthError::InvalidToken(
                    "token has an empty `crit` header".into(),
                ));
            }
            return Err(AuthError::InvalidToken(format!(
                "token requires unhandled critical header(s): {}",
                // Bounded because the crate reads `crit` from an unverified
                // header, and it renders the reason into a response header.
                // `quote` caps it again, and doing it here means never building
                // a megabyte string only to discard most of it.
                critical
                    .iter()
                    .map(String::as_str)
                    .take(4)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        // ── 2. Which issuer's keys are we about to trust? ───────────────────
        //
        // The crate reads the claimed `iss` *unverified*, and only to select a
        // trust bundle. That selection is not a security decision and proves
        // nothing. The signature over that issuer's keys is what makes the
        // token real, and `Validation::set_issuer` then requires the verified
        // `iss` to equal the configured one. A forged `iss` therefore fails
        // twice over. The wrong bundle cannot produce a valid signature, and
        // the claim gate rejects any mismatch.
        let claimed_iss = claimed_issuer(token)?.ok_or_else(|| {
            AuthError::InvalidToken("token has no `iss` claim; cannot select a trust bundle".into())
        })?;

        debug!(iss = %claimed_iss, kid = ?header.kid, "selecting issuer keys");

        // ── 3. The key that `iss` + `kid` names ─────────────────────────────
        let key = self
            .inner
            .keys
            .key_for(&claimed_iss, header.kid.as_deref())
            .await?;

        // ── 4. Verify the signature, then the claims ────────────────────────
        //
        // `verify` narrows the algorithm list to this key's family. So an
        // `RS256` header naming an EC key fails on the spot. It never reaches
        // an RSA verifier that would have to fail on it anyway.
        let claims = self.verify(token, &key)?;

        // The bundle was chosen by the claimed issuer. Make sure the issuer
        // that actually signed is the same one. `set_issuer` above covers this,
        // and this is cheap enough to be certain no future refactor quietly
        // drops that line.
        if claims.iss != claimed_iss {
            warn!(
                claimed = %claimed_iss,
                verified = %claims.iss,
                "token issuer changed between selection and verification"
            );
            return Err(AuthError::InvalidToken(
                "`iss` does not match the issuer that verified this token".into(),
            ));
        }

        // ── 5. Which audiences may *this* issuer vouch for? ─────────────────
        //
        // After the `iss` binding above, deliberately. The gate keys on the
        // issuer whose key verified the signature, not on the one the header
        // claimed. `decode` already required `aud` to sit inside the union of
        // every issuer's set. This gate requires it to sit inside this issuer's.
        self.check_issuer_audience(&claims)?;

        // ── 6. Which client is this token for? ─────────────────────────
        //
        // Last, and only narrowing: the signature, `iss`, `aud` and `exp` all
        // passed to reach here. Keycloak's `aud` is often useless, because a
        // stock realm puts `"account"` in it for every API. That is what this
        // gate is for. It never stands in for `aud`.
        self.check_authorised_party(&claims)?;
        Ok(claims)
    }

    /// One `jsonwebtoken` decode: signature over `key`, then `exp`/`nbf`,
    /// `iss` membership, `aud` overlap.
    ///
    /// The algorithm list comes from `key`, which is the only way to reach one
    /// entry of [`FamilyValidations`]. See there for why one list cannot span
    /// families. It is a subset of what the operator configured, and of what
    /// the header gate at step 1 already passed. So this can remove algorithms
    /// from the decision but never add one.
    ///
    /// When a key's family has no configured algorithm, this refuses the key
    /// rather than passing it on with an empty list. `jsonwebtoken` calls that
    /// `MissingAlgorithm`, which reads like a validation bug when it is really
    /// "this published key cannot verify anything you accept".
    ///
    /// Every failure becomes `InvalidToken`. The caller sent something we
    /// cannot trust, which is not the same as our provider being unreachable.
    fn verify(&self, token: &str, key: &DecodingKey) -> Result<Claims, AuthError> {
        let validation = self.inner.validations.for_key(key).ok_or_else(|| {
            // `debug!`, not `warn!`, for the same reason `jwks` logs an
            // unusable `kty` at debug. A client who learns one such `kid`
            // could otherwise fill the log at will. Every rejected token here
            // already reaches the boundary in `error` at debug, with this
            // reason attached.
            debug!(
                family = ?key.family(),
                accepted = ?self.inner.allowed,
                "the selected key cannot verify any accepted algorithm"
            );
            AuthError::InvalidToken(
                "the issuer's key cannot be used for any algorithm this API accepts".into(),
            )
        })?;

        jsonwebtoken::decode::<Claims>(token, key, validation)
            .map(|data| data.claims)
            .map_err(|err| {
                // Name the common kinds so a rejected request is debuggable
                // without turning on trace logging.
                use jsonwebtoken::errors::ErrorKind;
                let reason = match err.kind() {
                    ErrorKind::ExpiredSignature => "token has expired",
                    ErrorKind::InvalidSignature => "signature does not match the issuer's key",
                    ErrorKind::InvalidAudience => "`aud` does not name an accepted audience",
                    ErrorKind::InvalidIssuer => "`iss` is not a trusted issuer",
                    ErrorKind::MissingRequiredClaim(claim) => {
                        return AuthError::InvalidToken(format!(
                            "required claim `{claim}` is missing"
                        ));
                    }
                    _ => "failed validation",
                };
                AuthError::InvalidToken(format!("{reason} ({err})"))
            })
    }
}

/// One `Validation` per key family, each naming only the configured
/// algorithms of that family.
///
/// The constraint this exists for is `jsonwebtoken` 12's
/// `verify_signature_body`. It rejects a token unless *every* algorithm in
/// `Validation::algorithms` shares the family of the verifier in the call. That
/// verifier comes from the token's `alg`, and its constructor already refuses a
/// key from a different family. One list spanning `[RS256, ES256]` therefore
/// failed every token in a realm that publishes both key types. That is not a
/// degradation. It is an auth outage. So the list cannot live on `Inner` as one
/// value.
///
/// # Why keyed by family, and read from the key
///
/// The only accessor is [`Self::for_key`], and it takes the `DecodingKey`
/// itself. There is no way to ask for "the RSA `Validation`". The code reads
/// the family off the key that is about to verify. So passing an RSA-family
/// `Validation` to an EC key is not a rule to remember but a call that cannot
/// be written. Keying by the concrete `SignatureAlgorithm` would be the wrong
/// granularity. One RSA key is legitimately the key for `RS256`, `RS384` and
/// `PS256` at once, and family is exactly where `jsonwebtoken` draws its line.
///
/// # Narrowing only
///
/// Each list is `configured ∩ family`, so it is a subset of
/// [`AuthConfig::algorithms`](crate::AuthConfig::algorithms) by construction.
/// Every list is also non-empty, because the code groups it out of algorithms
/// that exist. A family with nothing configured simply has no entry, and
/// `for_key` answers `None`. That is a refusal at the call site, which is the
/// fail-closed half. If an empty `algorithms` list reached `decode`, it would
/// come back as `MissingAlgorithm`. That is a misleading name for "this key
/// cannot verify anything you accept", and it is the error a caller would have
/// to debug.
#[derive(Debug)]
pub(crate) struct FamilyValidations {
    /// At most one entry per asymmetric family, so a `Vec` beats a map. You
    /// need no `Hash` impl for a foreign enum, and the scan covers three items.
    entries: Vec<(AlgorithmFamily, Validation)>,
}

impl FamilyValidations {
    /// Group `algorithms` by family, each group layered onto `base`.
    ///
    /// The code clones `base` once per family rather than once per algorithm.
    /// Two algorithms of one family differ in nothing but the name in the list,
    /// and that list is the only thing `jsonwebtoken` chooses between.
    fn new(base: &Validation, algorithms: &[SignatureAlgorithm]) -> Self {
        let mut entries: Vec<(AlgorithmFamily, Validation)> = Vec::new();

        for algorithm in algorithms {
            let decoding = algorithm.decoding();
            match entries
                .iter_mut()
                .find(|(family, _)| *family == decoding.family())
            {
                // This family is already here, so every other field of its
                // `Validation` is already right. Only the list grows.
                Some((_, entry)) => entry.algorithms.push(decoding),
                None => {
                    let mut entry = base.clone();
                    entry.algorithms = vec![decoding];
                    entries.push((decoding.family(), entry));
                }
            }
        }

        Self { entries }
    }

    /// The `Validation` for `key`, or `None` when the operator configured
    /// nothing for that key's family.
    ///
    /// `None` is a refusal, never a fallback. It is reachable without any bug.
    /// A JWK's `alg` is optional (RFC 7515 §4.1.1). So `jwks` admits an
    /// `alg`-less `kty: EC` entry to the bundle even in an RS256-only
    /// deployment. A token naming that `kid` then arrives with an `alg` that
    /// passed the header gate but has no family-matching algorithm to run.
    fn for_key(&self, key: &DecodingKey) -> Option<&Validation> {
        let family = key.family();
        self.entries
            .iter()
            .find(|(known, _)| *known == family)
            .map(|(_, validation)| validation)
    }
}

/// The `Validation` every family starts from: everything except the
/// algorithm list, which is per family and always replaced by
/// [`FamilyValidations::new`].
///
/// Its audience set is the **union** of every configured issuer's set, and that
/// is not an oversight. A per-issuer audience set cannot live in a `Validation`
/// shared across a family without becoming a second selection axis. The
/// (family × issuer) cross product would need its own way to be chosen, which is
/// precisely the second algorithm gate this crate refuses to have. Narrowing by
/// issuer happens after the signature instead, in
/// [`Authenticator::check_issuer_audience`], where the issuer is a verified fact
/// rather than an unverified claim. The two gates in series accept only what the
/// signing issuer itself named, which is the whole point: the union can only be
/// as wide as what the issuers asked for, since it is derived from them.
fn base_validation(config: &AuthConfig) -> Validation {
    let mut validation = Validation::new(
        config
            .algorithms
            .first()
            .copied()
            .unwrap_or_default()
            .decoding(),
    );

    // `Validation::new` starts from `HS256` and `required_spec_claims =
    // {exp}`. Every line below replaces a default that would be wrong here,
    // so none of them are optional. `Validation::new` sets `algorithms` and it
    // is then replaced per family. It is never used as-is.
    validation.validate_exp = true;
    // `validate_nbf` defaults to **false** in `jsonwebtoken`, so a token
    // whose `nbf` is an hour in the future is accepted unless this line is
    // here. `Validation::new` does not turn it on.
    validation.validate_nbf = true;
    // `u64::from`, not `as`. Widening an unsigned width cannot wrap, so the
    // conversion is total. A future change to either type then becomes a
    // compile error rather than a silent reinterpretation. See
    // `AuthConfig::leeway`.
    //
    // Clamped to the ceiling `validate` enforces. `from_registry` is
    // crate-internal and bypasses `validate` by design. So a test or an
    // in-crate wrapper can hand this `u32::MAX`. That is
    // `u64::from(u32::MAX)` seconds, about a hundred and thirty years during
    // which no token expires. Narrowing is defensible where panicking on a
    // config value in a library is not. The ceiling is the stricter bound, so
    // the mistake always lands on the safe side. The constant lives in `config`
    // precisely so these two cannot drift.
    validation.leeway = u64::from(config.leeway.min(crate::config::MAX_LEEWAY_SECS));
    // The audience gate is never off, so `aud` must be present too. It is not
    // enough for it to be correct when it happens to appear.
    validation.validate_aud = true;
    validation.set_required_spec_claims(&["exp", "aud", "iss"]);

    // The multi-issuer rule that matters: a token is only good for the
    // issuer whose keys verified it.
    validation.set_issuer(
        &config
            .issuers
            .iter()
            .map(|issuer| issuer.iss.as_str())
            .collect::<Vec<_>>(),
    );
    // The union of what the issuers asked for, so this gate is the wide one and
    // `check_issuer_audience` is the narrow one. Bound rather than inlined:
    // `set_audience` takes `&[T]`, and a temporary would not outlive the call.
    let accepted_audiences = config.all_audiences();
    validation.set_audience(&accepted_audiences);

    validation
}

/// Read `iss` from an unverified payload, to choose a trust bundle.
///
/// The crate never returns this value to a caller as verified. Nothing here
/// decides the token's validity beyond which public keys to try. Returns
/// `Ok(None)` when the payload is readable but has no string `iss`.
///
/// Owns its result. This call decodes the payload from a `Vec<u8>` it built,
/// so a borrow from it would not outlive the call.
fn claimed_issuer(token: &str) -> Result<Option<String>, AuthError> {
    #[derive(Deserialize)]
    struct IssuerOnly {
        iss: Option<String>,
    }

    let (_, payload, _) = split_three_parts(token)?;
    let bytes = base64_url_decode(payload)?;

    let issuer = serde_json::from_slice::<IssuerOnly>(&bytes)
        .map_err(|err| AuthError::InvalidToken(format!("unreadable JWT payload: {err}")))?
        .iss;

    Ok(issuer)
}

/// Split a compact JWS into its three segments.
///
/// Use `splitn(4, '.')`, not `split('.').collect::<Vec<_>>()`. The token comes
/// from an attacker, and a collect allocates one slot per dot. Four items
/// settle the count. A fourth item means the token has too many parts.
pub(crate) fn split_three_parts(token: &str) -> Result<(&str, &str, &str), AuthError> {
    let mut parts = token.splitn(4, '.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(payload), Some(signature), None) => Ok((header, payload, signature)),
        _ => Err(AuthError::InvalidToken(
            "not a compact JWS: expected three dot-separated parts".to_owned(),
        )),
    }
}

/// Decode base64url, accepting or requiring padding as the encoder chose.
///
/// JWS payloads are base64url *without* padding (RFC 7515 §2), but encoders in
/// the wild emit padding, so both are read.
pub(crate) fn base64_url_decode(segment: &str) -> Result<Vec<u8>, AuthError> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // One path for both spellings. RFC 7515 mandates unpadded base64url, but
    // issuers do pad, and the crate has to accept both. Stripping trailing `=`
    // and decoding unpadded handles every case the earlier two-engine dance
    // did: padded, unpadded with a length divisible by four, and
    // unpadded-short. The acceptance set is identical, because a `=`-stripped
    // string always decodes under `URL_SAFE_NO_PAD`. The branch on
    // `len().is_multiple_of(4)` only guessed which engine might work, then fell
    // back. It added a path without adding any accepted token.
    let bytes = URL_SAFE_NO_PAD.decode(segment.trim_end_matches('='));

    bytes.map_err(|err| AuthError::InvalidToken(format!("invalid base64url segment: {err}")))
}

/// Follow OIDC discovery for one issuer and return its `jwks_uri`.
async fn discover(issuer: &Issuer, allow_http: bool) -> Result<Url, AuthError> {
    #[derive(Deserialize)]
    struct Discovery {
        issuer: Option<String>,
        jwks_uri: Option<String>,
    }

    let url = issuer.discovery_url()?;
    let client = crate::http::client(CachePolicy::default().timeout, allow_http);

    let document: Discovery = client
        .get(url.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|err| AuthError::ProviderUnavailable(format!("discovery `{url}` failed: {err}")))?
        .error_for_status()
        .map_err(|err| AuthError::ProviderUnavailable(format!("discovery `{url}` failed: {err}")))?
        .json()
        .await
        .map_err(|err| {
            AuthError::ProviderUnavailable(format!(
                "discovery `{url}` returned unreadable JSON: {err}"
            ))
        })?;

    // A document served by a different realm hands out that realm's keys.
    // Accepting it would silently trust a neighbour, which is exactly the
    // confusion a multi-tenant Keycloak makes easy.
    match document.issuer.as_deref() {
        Some(found) if found == issuer.iss => {}
        Some(found) => {
            return Err(AuthError::Configuration(format!(
                "issuer `{iss}` reported itself as `{found}` in {url}",
                iss = issuer.iss
            )));
        }
        // `issuer` is REQUIRED by OIDC Discovery §3. Its absence is a bug or
        // a probe, not something to guess past.
        None => {
            return Err(AuthError::Configuration(format!(
                "discovery document at {url} has no `issuer`"
            )));
        }
    }

    let jwks_uri = document.jwks_uri.ok_or_else(|| {
        AuthError::Configuration(format!("discovery document at {url} has no `jwks_uri`"))
    })?;

    Url::parse(&jwks_uri).map_err(|err| {
        AuthError::Configuration(format!("`jwks_uri` `{jwks_uri}` is not a URL: {err}"))
    })
}

/// Render a token's audience list for an error message, bounded and honestly
/// counted.
///
/// Not `aud.join(", ")`. The reasoning this replaced argued that the vector was
/// closed, because the gate runs after signature verification. On that
/// reasoning `aud` cannot be forged — which is true of *forgery* and beside the
/// point. A real token signed by the real issuer key can carry hundreds of
/// audiences. RFC 8707 resource indicators exist for exactly that, and any
/// registered client a tenant can create asks for them. The signature passes,
/// this refusal runs, and the joined list escapes twice over.
///
/// Escapes twice, because a cap at the header is not a cap. [`quote`] bounds
/// the `WWW-Authenticate` value, but `join` has already allocated the full
/// string by then. `IntoResponse` also logs `reason = %err` through
/// `AuthError`'s `Display`. That path never passes through `quote`, so the
/// unbounded list goes straight to stdout and to whatever collector reads it. A
/// cap one layer above an unbounded allocation protects the header and leaks the
/// memory and the log. That is the mistake of applying it there and stopping.
///
/// Three, then the count. Three is enough to spot the `aud`-misconfigured class
/// by eye. The count matters because "and 497 you are not shown" tells the
/// operator where to look. One client, or the IdP's whole audience model.
fn aud_hint(aud: &[String]) -> String {
    const SHOWN: usize = 3;
    // `take` rather than `join`: the whole point is to never build the long
    // string, so the bound has to be structural and not a trim afterwards.
    let shown = aud
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    // `saturating_sub`, matched on zero — not `checked_sub` matched on `None`.
    //
    // `checked_sub` reports underflow. That is the wrong question to ask an
    // output boundary. "There are fewer than `SHOWN`" and "nothing is hidden"
    // are two different facts, and at exactly `SHOWN` they disagree. There the
    // hidden count really is zero. So the old form printed "a, b, c (+0
    // more)": a sentence about a remainder that does not exist. It sends an
    // operator hunting for a truncation that never happened, which is worse
    // than silence. Below `SHOWN` the old form came out right only by
    // underflowing into `None`. It was correct with no intent behind it. It
    // would have broken the moment `SHOWN` moved to 1 and every
    // single-audience token claimed a remainder.
    match aud.len().saturating_sub(SHOWN) {
        0 => shown,
        hidden => format!("{shown} (+{hidden} more)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `SHOWN` boundary, where the count and the list stop agreeing.
    ///
    /// At exactly `SHOWN` audiences the hidden count is zero. A zero-count
    /// suffix is a sentence about a remainder that does not exist. "a, b, c
    /// (+0 more)" makes an operator look for a truncation that never happened.
    /// That is worse than silence, because it sends them to the wrong place.
    ///
    /// This reads as a cosmetic wording bug, and it is filed as one. The reason
    /// for the test is bigger than the wording: `checked_sub` is the wrong tool
    /// at an output boundary. It signals underflow. "Fewer than shown" and
    /// "nothing hidden" are two different facts that it happens to collapse.
    /// Below `SHOWN` the function is right only by underflowing into `None`.
    /// That is correctness with no intent behind it. It is the kind that breaks
    /// when someone changes `SHOWN` to 1 and every one-element token starts
    /// claiming a remainder.
    #[test]
    fn aud_hint_never_announces_a_remainder_of_zero() {
        let list =
            |n: usize| -> Vec<String> { (0..n).map(|k| format!("aud-{k}")).collect::<Vec<_>>() };

        assert_eq!(aud_hint(&list(0)), "");
        assert_eq!(aud_hint(&list(1)), "aud-0");
        assert_eq!(aud_hint(&list(2)), "aud-0, aud-1");
        // The boundary itself: three shown, nothing hidden.
        assert_eq!(aud_hint(&list(3)), "aud-0, aud-1, aud-2");
        // First case that genuinely has a remainder, and its arithmetic.
        assert_eq!(aud_hint(&list(4)), "aud-0, aud-1, aud-2 (+1 more)");
        assert_eq!(aud_hint(&list(500)), "aud-0, aud-1, aud-2 (+497 more)");

        for n in 0..=6 {
            assert!(
                !aud_hint(&list(n)).contains("+0 more"),
                "{n} audiences must not claim a zero remainder"
            );
        }
    }

    /// `base64_url_decode` accepts both spellings of base64url on one path.
    ///
    /// It used to branch on `len().is_multiple_of(4)` and try the padded
    /// engine first, with an unpadded fallback. Collapsing to
    /// `URL_SAFE_NO_PAD` after stripping `=` is only safe if the accepted set
    /// stays identical. So this test asserts each shape the old branch told
    /// apart. One shape is awkward: an unpadded segment whose length happens
    /// to be a multiple of four. That is exactly the case that made the old
    /// `if` guess wrong and lean on its own fallback.
    #[test]
    fn every_base64url_spelling_decodes_to_the_same_bytes() {
        use base64::Engine as _;
        use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};

        // Payloads chosen to cover every length class mod 4, because that is
        // what the removed branch keyed on. Three and five bytes are the
        // interesting ones. Their *unpadded* forms are exactly a multiple of
        // four wide. That is precisely what made the old `if` reach for the
        // padded engine first, then fall back to the unpadded one it should
        // have used throughout.
        let payloads: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            &[0xff, 0xff, 0xff], // unpadded -> 4 chars
            b"abcd",
            b"abcde", // unpadded -> 8 chars
        ];

        for payload in payloads {
            let unpadded = URL_SAFE_NO_PAD.encode(payload);
            let padded = URL_SAFE.encode(payload);
            // Both spellings of the same bytes, and they differ for every
            // payload except the empty one.
            for segment in [&unpadded, &padded] {
                // One statement, so a refusal is a failed assertion rather than
                // a branch this test can only ever walk past. `assert_eq` names
                // the segment, shows both sides, and still prints the decode
                // error when there is one.
                assert_eq!(
                    base64_url_decode(segment).as_deref(),
                    Ok(*payload),
                    "`{segment}` must decode to its bytes"
                );
            }
        }
    }

    #[test]
    fn a_non_base64url_segment_is_still_refused() {
        // The simplification must not have turned the decoder permissive. `+`
        // and `/` are standard-base64, not base64url, and `!` is neither. An
        // embedded `=` is padding in the middle of the value, which no legal
        // spelling produces.
        for segment in ["ab+d", "ab/d", "ab!d", "ab=d"] {
            let outcome = base64_url_decode(segment);
            assert!(
                outcome.is_err(),
                "`{segment}` is not base64url and must not decode: {outcome:?}"
            );
        }
    }

    /// The clamp that makes `base_validation` safe for callers that bypass
    /// `validate`.
    ///
    /// `from_registry` is crate-internal and does not run `validate`, so the
    /// `0..=MAX_LEEWAY_SECS` gate in `config` does not stand between it and a
    /// `u32::MAX`. Leeway is applied to `exp` *and* `nbf`, so an unclamped
    /// ceiling there is not a loose bound — it is expiry not existing, for
    /// every issuer, silently.
    #[test]
    fn leeway_is_clamped_even_when_validate_was_never_called() {
        let runaway = AuthConfig::empty().with_issuer(
            Issuer::discover("https://idp.example.com", ["qg"]).expect("valid issuer"),
        );
        assert_eq!(
            runaway.leeway, 30,
            "the default must be untouched by the clamp"
        );
        assert_eq!(
            base_validation(&runaway).leeway,
            30,
            "a sane leeway passes through unchanged"
        );

        let mut runaway = runaway;
        runaway.leeway = u32::MAX;
        let clamped = base_validation(&runaway).leeway;
        assert_eq!(
            clamped,
            u64::from(crate::config::MAX_LEEWAY_SECS),
            "u32::MAX seconds is 136 years of tokens that never expire; the
             ceiling must bind here even though `validate` was skipped"
        );

        // And the public path still refuses outright rather than silently
        // correcting what the operator wrote.
        let rejected = {
            let mut config = AuthConfig::empty().with_issuer(
                Issuer::discover("https://idp.example.com", ["qg"]).expect("valid issuer"),
            );
            config.leeway = crate::config::MAX_LEEWAY_SECS + 1;
            config.validate()
        };
        assert!(
            rejected.is_err(),
            "`validate` must reject a leeway over the ceiling, not clamp it: {rejected:?}"
        );
    }

    #[test]
    fn an_unpadded_length_three_segment_decodes() {
        // The odd width among these shapes: one byte plus a fragment, no
        // padding at all. Spelled apart because it is legal, and it would be
        // easy for a "reject anything not a multiple of four" over-correction
        // to refuse it.
        assert_eq!(
            base64_url_decode("abc").expect("legal unpadded base64url"),
            vec![0x69, 0xb7]
        );
    }

    /// The two copies of one fact do not drift.
    ///
    /// [`Inner`] names each scope twice: per issuer, for the gates, and as one
    /// union, for the accessors. Nothing in the gates reads the union, so the
    /// accessors are the only consumer — and they are what a host wires into a
    /// startup log line or a `/health` payload. A union that disagreed with the
    /// per-issuer sets would therefore be believed *because* nothing enforces
    /// it. So it is asserted to be exactly the deduplicated union of the sets
    /// the gates read, in issuer order.
    #[test]
    fn the_reporting_unions_match_the_per_issuer_sets() {
        let jwks_url = Url::parse("https://issuer.example/jwks.json").expect("a JWKS URL");
        let other_url = Url::parse("https://other.example/jwks.json").expect("a JWKS URL");
        let registry = JwksRegistry::new(
            [
                ("https://issuer.example".to_owned(), jwks_url.clone()),
                ("https://other.example".to_owned(), other_url.clone()),
            ],
            &["RS256".to_owned()],
            CachePolicy::default(),
            false,
        )
        .expect("two issuers, one algorithm");

        // `billing` appears on both issuers on purpose: the union deduplicates.
        let config = AuthConfig::empty().with_issuers([
            Issuer::with_jwks_url("https://issuer.example", jwks_url, ["api", "billing"])
                .expect("an issuer")
                .authorized_party("client"),
            Issuer::with_jwks_url("https://other.example", other_url, ["billing", "reports"])
                .expect("an issuer"),
        ]);

        let auth = Authenticator::from_registry(registry, &config);

        assert_eq!(
            auth.all_audiences().to_vec(),
            vec!["api", "billing", "reports"],
            "issuer order, first occurrence kept"
        );
        assert_eq!(
            auth.all_authorized_parties().to_vec(),
            vec!["client"],
            "the second issuer gates on nothing, so it adds nothing here"
        );

        // The accessor a host reads to see what an issuer gates on, in its three
        // states. The last two are the pair a caller can confuse: an issuer that
        // gates on nothing still has an entry, and only an issuer that is not
        // configured at all is absent. `None` is what `check_authorised_party`
        // treats as drift, so reading it as "no gate" would read the one value
        // that means "this config no longer matches its keys".
        assert_eq!(
            auth.issuer_authorized_parties("https://issuer.example")
                .map(<[String]>::to_vec),
            Some(vec!["client".to_owned()]),
            "the gating issuer reports the client it named"
        );
        assert_eq!(
            auth.issuer_authorized_parties("https://other.example")
                .map(<[String]>::to_vec),
            Some(Vec::new()),
            "the ungated issuer has an entry, and it is empty"
        );
        assert_eq!(
            auth.issuer_authorized_parties("https://unconfigured.example")
                .map(<[String]>::to_vec),
            None,
            "an issuer that is not configured has no entry at all"
        );

        // The same answer, recomputed from the maps the gates actually read.
        // This is the assertion that would fail if a future edit updated one
        // copy and not the other.
        let mut derived: Vec<String> = Vec::new();
        for iss in ["https://issuer.example", "https://other.example"] {
            for aud in auth
                .issuer_audiences(iss)
                .expect("every configured issuer has an entry")
            {
                if !derived.contains(aud) {
                    derived.push(aud.clone());
                }
            }
        }
        assert_eq!(
            auth.all_audiences(),
            derived.as_slice(),
            "the reporting union must equal the union of the per-issuer sets"
        );

        // And the same for the client sets. `azp` had no such check: the union
        // was asserted on its own above, and nothing compared it with what the
        // gate actually looks up per issuer.
        let mut derived_parties: Vec<String> = Vec::new();
        for iss in ["https://issuer.example", "https://other.example"] {
            for client in auth
                .issuer_authorized_parties(iss)
                .expect("every configured issuer has an entry")
            {
                if !derived_parties.contains(client) {
                    derived_parties.push(client.clone());
                }
            }
        }
        assert_eq!(
            auth.all_authorized_parties(),
            derived_parties.as_slice(),
            "the reporting union must equal the union of the per-issuer client sets"
        );
    }

    /// The `azp` gate refuses an issuer it has no entry for, and says that.
    ///
    /// The same disagreement shape as the audience counterpart below: keys and
    /// config that drifted apart. Two things are pinned. The arm refuses rather
    /// than falling through to "no client list, so no gate", which is the
    /// fail-open reading. And it reports the missing *issuer*, not a blank client
    /// list, because a blank list is legal policy while a missing entry is a
    /// broken config — different fixes, so different sentences.
    #[test]
    fn an_issuer_with_no_authorised_party_entry_refuses_rather_than_accepting() {
        let jwks_url = Url::parse("https://issuer.example/jwks.json").expect("a JWKS URL");
        let registry = JwksRegistry::new(
            [("https://issuer.example".to_owned(), jwks_url.clone())],
            &["RS256".to_owned()],
            CachePolicy::default(),
            false,
        )
        .expect("one issuer, one algorithm");

        let config = AuthConfig::empty().with_issuer(
            Issuer::with_jwks_url("https://issuer.example", jwks_url, ["api"]).expect("an issuer"),
        );

        let auth = Authenticator::from_registry(registry, &config);

        let claims_for = |iss: &str| {
            serde_json::from_value::<Claims>(serde_json::json!({
                "sub": "user-1",
                "iss": iss,
                "aud": ["api"],
                "exp": 4_000_000_000_i64,
            }))
            .expect("claims")
        };

        let err = auth
            .check_authorised_party(&claims_for("https://some-other-issuer.example"))
            .expect_err("no entry means no policy, which is a refusal");
        assert!(
            err.to_string().contains("is not configured"),
            "the refusal must name the missing issuer rather than report an empty \
             client list, which is a legal configuration: {err}"
        );

        // And the configured issuer with no `azp` gate is the settled empty
        // case, not the missing one: the gate is off, so this passes.
        auth.check_authorised_party(&claims_for("https://issuer.example"))
            .expect("an issuer that named no clients gates on none");
    }

    /// The crate refuses an issuer with no audience layer rather than waving it
    /// through.
    ///
    /// `check_issuer_audience` runs after the signature binds `iss`. So for an
    /// authenticator built by `start`, every reachable `iss` has a layer and this
    /// arm is dead. The test pins it anyway. The alternative is the whole
    /// vulnerability again, through a `HashMap::get`. A `None` that fell through
    /// to acceptance would read "this issuer has no configured audience" as
    /// "any audience is fine for this issuer". That is the flat shared audience
    /// list that per-issuer layers exist to prevent. So this test does not exist
    /// to raise a number. It exists because this arm is the fail-closed side of a
    /// fail-open decision. A refactor of `from_registry` that forgot one issuer
    /// should fail here rather than authenticate cross-tenant tokens.
    ///
    /// The test calls `from_registry` directly, with a config that names a
    /// different issuer than the registry does. That is the state an arm like
    /// this exists for: keys and config that disagree.
    #[test]
    fn an_issuer_with_no_audience_layer_refuses_rather_than_accepting() {
        let jwks_url = Url::parse("https://issuer.example/jwks.json").expect("a JWKS URL");
        let registry = JwksRegistry::new(
            [("https://issuer.example".to_owned(), jwks_url.clone())],
            &["RS256".to_owned()],
            CachePolicy::default(),
            false,
        )
        .expect("one issuer, one algorithm");

        let config = AuthConfig::empty().with_issuer(
            Issuer::with_jwks_url("https://issuer.example", jwks_url, ["api"]).expect("an issuer"),
        );

        let auth = Authenticator::from_registry(registry, &config);

        // Claims whose issuer has no layer. Live traffic cannot produce this,
        // because gate 2 finds no keys for it. Here it is the shape of a
        // registry and a config that drifted apart.
        let claims = serde_json::from_value::<Claims>(serde_json::json!({
            "sub": "user-1",
            "iss": "https://some-other-issuer.example",
            "aud": ["api"],
            "exp": 4_000_000_000_i64,
        }))
        .expect("claims");

        let err = auth
            .check_issuer_audience(&claims)
            .expect_err("no layer means no audience is accepted, which is a refusal");

        assert!(
            matches!(err, AuthError::InvalidToken(_)),
            "the token named an issuer this authenticator has no policy for, so it \
             is refused as a token problem, not raised as a provider outage the \
             caller would retry: {err:?}"
        );
        assert!(
            err.to_string()
                .contains("no audience is accepted for issuer"),
            "the refusal should say there is no policy for this issuer, which is a \
             different fix than naming the wrong `aud`: {err}"
        );
    }

    /// `split_three_parts` counts segments, and only counts them.
    ///
    /// Reached through the public API only in principle: `authenticate` runs
    /// `decode_header` first, and that refuses anything without three segments,
    /// so `verify` never sees these. Called directly, the helper's own contract
    /// is what is pinned, and the interesting half of that contract is what it
    /// does *not* look at. The split answers a question about separators, so
    /// `"a.b."` and `".b.c"` split cleanly and hand back an empty segment. That
    /// is safe for the one caller that exists, `claimed_issuer`, because it
    /// decodes the payload and never looks at the signature slot. That is worth
    /// writing down rather than leaving to inference. Another caller might read
    /// that third slice. For such a caller one empty signature would mean
    /// something this helper never meant.
    #[test]
    fn split_three_parts_counts_segments_and_nothing_else() {
        for token in ["", "a", "a.b", "a.b.c.d", "a.b.c.d.e"] {
            // Pinned as one value rather than matched and then unwrapped, so no
            // `panic!` arm sits in a test that can only ever take the other
            // branch. And naming the exact error is a stronger claim than "it is
            // an InvalidToken whose text mentions parts".
            assert_eq!(
                split_three_parts(token),
                Err(AuthError::InvalidToken(
                    "not a compact JWS: expected three dot-separated parts".to_owned()
                )),
                "`{token}` has the wrong number of parts; refusing it for its shape \
                 is the one thing the caller can act on"
            );
        }

        // Three parts is three parts, whatever is between the dots. Tightening
        // this to reject empty segments would be defensible. Doing it silently
        // would not be, so the shapes it currently accepts are named here.
        for (token, parts) in [
            ("a.b.c", ("a", "b", "c")),
            ("a.b.", ("a", "b", "")),
            (".b.c", ("", "b", "c")),
        ] {
            assert_eq!(
                split_three_parts(token).expect("`token` has three parts by count"),
                parts,
                "`{token}` splits by count; an empty segment is the caller's problem, \
                 not this helper's"
            );
        }
    }

    /// The crate refuses a signature that verifies, from an issuer nobody
    /// configured, for the reason that is actually true.
    ///
    /// `InvalidIssuer` cannot arrive through `authenticate`. Gate 2 selects the
    /// trust bundle using the unverified `iss`, and `set_issuer` below comes
    /// from that same configured set. So anything that reaches `decode` was
    /// already routed by an `iss` that is a member of it. This test exercises
    /// the arm by calling `verify` directly, which is worth doing *because* it
    /// is unreachable on the request path. One day `set_issuer` narrows per
    /// key, or `decode` takes a `Validation` built elsewhere. That arm then
    /// moves from dead code onto the request path. Its wording is already
    /// pinned.
    ///
    /// What the wording has to get right is the blame. The token below carries
    /// the signature of the very key that verifies it, and it is well-formed in
    /// every way. The only thing wrong with it is who it says issued it. Say
    /// "signature does not match the issuer's key" and an operator debugging a
    /// realm mismatch goes looking for a rotated key. That is the wrong
    /// haystack entirely.
    #[test]
    fn a_signature_from_an_untrusted_issuer_is_named_as_an_issuer_problem() {
        use base64::Engine as _;
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        use rsa::PrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        use rsa::traits::PublicKeyParts;

        let private = PrivateKey::new(&mut rand::rng(), 2048).expect("generate an RSA key");
        let public = private.to_public_key();
        let pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("serialise the private key to PKCS#8 PEM");
        let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);

        let key = DecodingKey::from_rsa_components(
            &encode(&public.n_bytes()),
            &encode(&public.e_bytes()),
        )
        .expect("an RSA decoding key from its own components");

        let jwks_url = Url::parse("https://issuer.example/jwks.json").expect("a JWKS URL");
        let registry = JwksRegistry::new(
            [("https://issuer.example".to_owned(), jwks_url.clone())],
            &["RS256".to_owned()],
            CachePolicy::default(),
            false,
        )
        .expect("one issuer, one algorithm");
        let config = AuthConfig::empty().with_issuer(
            Issuer::with_jwks_url("https://issuer.example", jwks_url, ["api"]).expect("an issuer"),
        );
        let auth = Authenticator::from_registry(registry, &config);

        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &serde_json::json!({
                "sub": "user-1",
                "iss": "https://someone-elses-realm.example",
                // An audience this API does accept, so the audience gate is not
                // what refuses it and the refusal below is about the issuer alone.
                "aud": ["api"],
                "exp": 4_000_000_000_i64,
            }),
            &EncodingKey::from_rsa_pem(pem.as_bytes()).expect("an RSA encoding key"),
        )
        .expect("sign the token");

        let err = auth
            .verify(&token, &key)
            .expect_err("a key this API trusts does not vouch for that issuer");

        assert!(
            matches!(err, AuthError::InvalidToken(_)),
            "a token from an issuer we do not trust is the caller's problem, not a \
             provider outage to retry: {err:?}"
        );
        assert!(
            err.to_string().contains("`iss` is not a trusted issuer"),
            "the signature verified, so the refusal must not mention the key: {err}"
        );
    }
}
