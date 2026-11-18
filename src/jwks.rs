//! Per-issuer JWKS fetching and caching, including key rotation.
//!
//! # Key selection is exact-match only
//!
//! A token's `kid` must name a key in *that issuer's* set. There is no "try
//! each key until one verifies" fallback. There is no fallback to the first
//! key when `kid` is absent. A fallback widens the set of signatures accepted
//! for a token that already names the key it was signed with. It also makes
//! key rotation look like a success instead of a mismatch. Both are actively
//! harmful. A provider that omits `kid` is unsupported here. Google and
//! Keycloak both publish `kid`.
//!
//! # Key types are allowlisted, not inferred
//!
//! A JWK joins the bundle only if `convert_key` names its `kty`: RSA, EC on
//! P-256/P-384, OKP on Ed25519. That list is written out by hand rather than
//! left to `DecodingKey::try_from`, because `try_from` is not a trust
//! decision. Handed an `oct` JWK it returns a working HMAC key, because
//! jsonwebtoken does HMAC too. A symmetric key in the bundle is the second
//! half of the algorithm-confusion forgery this crate exists to refuse: the
//! "secret" an attacker signs a forged token with is a public key the
//! verifier already holds. Which algorithms are possible at all is a separate,
//! independent gate, owned by
//! [`SignatureAlgorithm`](crate::SignatureAlgorithm), which cannot name an
//! HMAC variant. There are two gates rather than one, so widening one
//! (accepting a new `kty`, or a new `alg`) cannot quietly widen the other.
//!
//! # Two locks, and neither is held across the network
//!
//! Per-issuer state is split in two. The key bundle sits behind a
//! `tokio::sync::RwLock<Option<Arc<TrustBundle>>>`. A request read-shares it,
//! clones the `Arc`, and the guard is gone before the `kid` lookup. The
//! refresh bookkeeping sits behind a plain `std::sync::Mutex`, held for
//! nanoseconds and never across an `await`. The fetch itself holds nothing.
//!
//! One mutex over both, as this file used to have, put the network on the
//! critical path of every authenticated request for that issuer. A hung JWKS
//! call held the lock for the whole client timeout, so tokens naming
//! long-cached keys queued behind an unrelated refresh and p99 looked like an
//! outage on routes that never needed the provider. Sharing the read side is
//! what makes a slow issuer cost the one request that actually waited.
//!
//! One case still waits, deliberately: a `kid` we hold no key for at all,
//! while another request is already fetching it. That request is blocked on
//! the network whichever way it is handled, and refusing it with a 401 is
//! worse than delaying it. Clients retry a slow response, not a rejected one,
//! so a key rotation under load would fail real logins. What keeps the split
//! intact is that only a `kid` with no key behind it can park, and only for as
//! long as one fetch could take.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{AlgorithmFamily, DecodingKey};
use serde::Deserialize;
// Read/write, not a mutex: the read side is per-request and has to be shared.
// `watch` carries the generation counter that wakes requests parked on a
// refresh somebody else owns.
use tokio::sync::{RwLock, watch};
use tracing::{debug, info, warn};
use url::Url;

use crate::error::AuthError;
use crate::types::IssuerUrl;

/// Largest JWKS body accepted, in bytes. This guards against a compromised or
/// misbehaving issuer turning one token request into memory exhaustion.
const MAX_JWKS_BYTES: usize = 1 << 20; // 1 MiB

/// Tunables for the JWKS cache and its refresh policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    /// How long the crate treats a fetched key set as fresh. An unknown `kid`
    /// detects rotation immediately, so this only bounds how long a key the
    /// issuer quietly withdrew stays trusted.
    pub ttl: Duration,
    /// Smallest gap between two fetches from one issuer. This is also the
    /// retry interval after a failure. It is what stops forged tokens bearing
    /// invented `kid` values from being turned into a flood of requests to the
    /// identity provider.
    pub min_fetch_gap: Duration,
    /// Bounds on discovery and JWKS requests.
    pub timeout: Duration,
    /// Refuse a JWKS larger than this. Defaults to 1 MiB. A real key set is a
    /// few kilobytes, so anything past this is somebody filling memory.
    pub max_bytes: usize,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(15 * 60),
            min_fetch_gap: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            max_bytes: MAX_JWKS_BYTES,
        }
    }
}

/// A JWKS document as published by an issuer.
#[derive(Debug, Deserialize)]
struct JwksDocument {
    /// Deliberately unparsed. Reading the whole set as a
    /// `jsonwebtoken::jwk::JwkSet` in one fallible step turns one bad JWK into
    /// an error for the *document*. A component of the wrong JSON type, or a
    /// `kty` that `Jwk` cannot represent, is enough. That document error would
    /// then take the issuer's usable keys down with it.
    /// [`JwksRegistry::convert_key`] reads each entry on its own.
    #[serde(default)]
    keys: Vec<serde_json::Value>,
}

/// A verified-ish snapshot of one issuer's public keys.
#[derive(Debug, Clone)]
struct TrustBundle {
    /// `(kid, key)` pairs, `kid` always present.
    keys: Vec<(String, DecodingKey)>,
    fetched_at: Instant,
}

/// Refresh bookkeeping for one issuer: who may fetch, and how recently.
///
/// The key bundle keeps this apart. So the code can decide *whether* to go to
/// the network atomically, without parking anyone who only wants to read keys.
/// A `std` mutex guards it, which is a promise that the code never holds it
/// across an `await`.
#[derive(Debug)]
struct RefreshState {
    /// Single-flight flag: set while one fetch is in flight, cleared by the
    /// [`Flight`] guard that set it.
    fetching: bool,
    /// When the last fetch *ended*. This is also the retry interval after a
    /// failure, and the reason an unknown `kid` cannot become a request flood.
    last_attempt: Option<Instant>,
    /// Last transport/parse failure, for diagnostics.
    last_error: Option<String>,
    /// Bumped once per completed fetch, to wake whoever decided to wait for
    /// it. This is a `watch` rather than a `Notify` because a waiter that
    /// arrives late must be able to see that the generation already moved. The
    /// value itself is never read, only its changing matters.
    generation: watch::Sender<u64>,
}

/// One identity provider's keys, and how to keep them current.
#[derive(Debug)]
struct IssuerSlot {
    iss: IssuerUrl,
    jwks_url: Url,
    /// What requests are served from. This is swapped wholesale, so a reader
    /// either sees the old bundle or the new one and never a half-installed
    /// set.
    bundle: RwLock<Option<Arc<TrustBundle>>>,
    refresh: Mutex<RefreshState>,
}

impl IssuerSlot {
    fn new(iss: IssuerUrl, jwks_url: Url) -> Self {
        Self {
            iss,
            jwks_url,
            bundle: RwLock::new(None),
            refresh: Mutex::new(RefreshState {
                fetching: false,
                last_attempt: None,
                last_error: None,
                generation: watch::channel(0).0,
            }),
        }
    }

    /// The bookkeeping lock, with a panic recovered rather than propagated.
    ///
    /// No [`RefreshState`] field is an invariant spanning two others, so a
    /// poisoned lock still holds sound data. Letting one panicked request
    /// disable refreshing for the life of the process is the worse failure.
    fn refresh_state(&self) -> MutexGuard<'_, RefreshState> {
        self.refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The served bundle, with the read guard already released.
    ///
    /// This is the only way to reach the keys. The method hands back the `Arc`,
    /// not a guard. That makes "no `await` while holding the read lock"
    /// unrepresentable at a call site, instead of a rule each caller has to
    /// remember. Cloning the `Arc` is the entire critical section.
    async fn cached(&self) -> Option<Arc<TrustBundle>> {
        self.bundle.read().await.clone()
    }

    /// Publish a freshly fetched bundle.
    ///
    /// The write guard covers one assignment and no `await`, so anyone queued
    /// behind it waits for a pointer swap, not for a network call.
    async fn publish(&self, bundle: Arc<TrustBundle>) {
        *self.bundle.write().await = Some(bundle);
    }

    /// The key for `kid` in whatever bundle is served right now.
    ///
    /// `None` means "this issuer has not given us this key yet". That is what
    /// separates a request that has an answer in hand from one genuinely
    /// blocked on somebody else's fetch.
    async fn key_holding(&self, kid: &str) -> Option<DecodingKey> {
        self.cached()
            .await
            .as_ref()
            .and_then(|bundle| lookup(bundle, kid))
    }

    /// Ask to fetch this issuer's keys.
    ///
    /// Both tests and the `fetching` flag live in one lock acquisition, so two
    /// concurrent unknown `kid`s cannot both reach the issuer.
    ///
    /// The code subscribes the `Busy` receiver *inside* that same lock, and
    /// that ordering is the whole hazard this API exists to close. It is the
    /// whole hazard because [`Flight::drop`] bumps the counter under this lock.
    /// So a receiver taken before the code observed the flag set cannot have
    /// missed that bump. If this API handed back a `Receiver` to make after
    /// `begin_flight` returns, the flight could land in between. The waiter
    /// would then sleep out its entire timeout for a bump that already
    /// happened.
    fn begin_flight(&self, min_fetch_gap: Duration) -> Turn<'_> {
        let mut refresh = self.refresh_state();

        if refresh.fetching {
            return Turn::Busy(refresh.generation.subscribe());
        }

        if refresh
            .last_attempt
            .is_some_and(|when| when.elapsed() < min_fetch_gap)
        {
            return Turn::TooSoon;
        }

        refresh.fetching = true;
        Turn::Mine(Flight {
            slot: self,
            // Un-settled by construction. Ownership of the flight is handed
            // over precisely so that an attempt which never reaches an outcome
            // is still accounted for. See `Flight::settle`.
            settled: false,
        })
    }
}

/// What asking to fetch one issuer's keys produced.
enum Turn<'a> {
    /// It is this request's turn. Fetch, and drop the guard when done.
    Mine(Flight<'a>),
    /// Another request owns the flight. This receiver changes when it lands.
    Busy(watch::Receiver<u64>),
    /// `min_fetch_gap` has not elapsed and nothing is in flight, so there is
    /// nothing to wait for. An invented `kid` is refused on the spot rather
    /// than parked for the length of a fetch nobody is making.
    TooSoon,
}

/// Ownership of one issuer's single flight, for exactly one fetch.
///
/// The drop clears this, not the call sites. A panic part-way through a fetch
/// would otherwise leave `fetching` set for the life of the process. Every
/// later unknown `kid` would then fail without the crate ever consulting the
/// issuer again. One bug would wedge an issuer forever.
struct Flight<'a> {
    slot: &'a IssuerSlot,
    /// Set once the fetch reached an outcome the call site already recorded.
    /// Its absence at drop time is the signal. It marks a third case, neither
    /// success nor error: the caller abandoned the fetch.
    settled: bool,
}

impl Flight<'_> {
    /// Declare that the fetch reached an outcome, so dropping the guard is
    /// ordinary teardown rather than a lost attempt.
    fn settle(&mut self) {
        self.settled = true;
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        let mut refresh = self.slot.refresh_state();
        refresh.fetching = false;
        // Stamped when the attempt ends, not when it starts, so the rate limit
        // covers the fetch that just happened. While this guard is alive there
        // is nothing to stamp: nobody else is allowed to try.
        refresh.last_attempt = Some(Instant::now());
        // An abandoned fetch has to be remembered as a failure, and this drop
        // is the only place still able to see it.
        //
        // The path is cancellation, not error. The caller's future is destroyed
        // whenever a client hangs up or a proxy times out mid-fetch. That is an
        // ordinary event under real traffic. `fetch` dies at its next `.await`,
        // so the `Err` arm that writes `last_error` never runs. The guard still
        // fires and still stamps the rate limit, as though an attempt had
        // completed, while `last_error` stays whatever it was.
        //
        // That pairing is precisely the mislabelling the refusal site goes to
        // lengths to avoid. For `min_fetch_gap` afterwards an unknown `kid`
        // takes `Turn::TooSoon`, finds no failure recorded, and is refused
        // `invalid_token`. That blames a token for a fetch that was never
        // allowed to finish, in front of a client that discards good sessions
        // on that word. Recording an outcome we do not know is the conservative
        // direction: "this issuer's reachability is currently unconfirmed" is
        // both true and retryable.
        if !self.settled && refresh.last_error.is_none() {
            refresh.last_error = Some(
                "the previous key fetch for this issuer was abandoned before it completed \
                 (client disconnect or timeout); issuer reachability is unconfirmed"
                    .to_owned(),
            );
        }
        // And the generation moves with it, waking whoever chose to wait for
        // this issuer's keys. It is bumped on failure as well as success, because
        // a waiter wanted an answer, and "the fetch failed" is one. The
        // waiter's own re-lookup decides whether that is a key or a refusal,
        // and it decides it now rather than after a timeout.
        refresh.generation.send_modify(|generation| {
            *generation += 1;
        });
    }
}

/// The key sets of every trusted issuer.
#[derive(Debug)]
pub struct JwksRegistry {
    http: reqwest::Client,
    policy: CachePolicy,
    /// Keyed by the exact `iss`. [`IssuerUrl`] hashes on the claim text, so a
    /// lookup borrows the verified `iss` and allocates nothing.
    slots: HashMap<IssuerUrl, IssuerSlot>,
    /// `alg` names the JWS header and the JWK may use, e.g. `RS256`.
    allowed_algorithms: Vec<String>,
}

impl JwksRegistry {
    /// Build a registry for already-discovered issuers.
    ///
    /// `allow_http` is forwarded to the HTTP client. See
    /// [`AuthConfig::allow_insecure_http`](crate::AuthConfig::allow_insecure_http).
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] when the algorithm list is empty. An
    /// unusable `iss` cannot reach here: [`IssuerUrl`] parsed before an
    /// [`Issuer`](crate::Issuer) existed, so the check that used to live at
    /// this line is now the constructor of the type in the tuple.
    pub fn new(
        issuers: impl IntoIterator<Item = (IssuerUrl, Url)>,
        allowed_algorithms: &[String],
        policy: CachePolicy,
        allow_http: bool,
    ) -> Result<Self, AuthError> {
        if allowed_algorithms.is_empty() {
            return Err(AuthError::Configuration(
                "no allowed signature algorithms configured".to_owned(),
            ));
        }

        let http = crate::http::client(policy.timeout, allow_http);
        let slots = issuers
            .into_iter()
            .map(|(iss, jwks_url)| {
                let slot = IssuerSlot::new(iss.clone(), jwks_url);
                (iss, slot)
            })
            .collect();

        Ok(Self {
            http,
            policy,
            slots,
            allowed_algorithms: allowed_algorithms.to_vec(),
        })
    }

    /// Every issuer this registry can serve.
    pub fn issuers(&self) -> impl Iterator<Item = &IssuerUrl> {
        self.slots.keys()
    }

    /// Fetch every issuer's keys now, so a bad URL or an unreachable provider
    /// fails at startup instead of on the first user request.
    ///
    /// # Errors
    ///
    /// This propagates the first failure. An issuer with no keys cannot
    /// authenticate anyone, so starting is worse than stopping.
    pub async fn warm_up(&self) -> Result<(), AuthError> {
        for slot in self.slots.values() {
            // No flight is claimed here. Nothing else is running yet. A failure
            // has to reach the caller, and not be filtered by a rate limit that
            // exists to protect the issuer from a stampede.
            let bundle = self.fetch(slot).await.inspect_err(|err| {
                warn!(iss = %slot.iss, error = %err, "JWKS warm-up failed");
            })?;
            let keys = bundle.keys.len();
            info!(
                iss = %slot.iss,
                keys,
                jwks_url = %slot.jwks_url,
                "loaded issuer keys"
            );
            slot.publish(Arc::new(bundle)).await;

            // Stamp the attempt, so the first unknown `kid` after startup is
            // rate-limited like any other. Otherwise it would be treated as
            // "never tried" and answered with an immediate second fetch.
            let mut refresh = slot.refresh_state();
            refresh.last_attempt = Some(Instant::now());
            refresh.last_error = None;
        }
        Ok(())
    }

    /// The key that a token's `iss` + `kid` names, refreshing once if that
    /// `kid` is unknown. An unknown `kid` is the usual sign of a rotation.
    ///
    /// A `kid` already in the bundle is answered without touching the network,
    /// fresh or not. A `kid` with no key behind it may wait for one refresh:
    /// either the one it starts, or the one it joins. That wait is bounded by
    /// [`CachePolicy::timeout`].
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidToken`] for an untrusted issuer, a token with no
    /// `kid`, or a `kid` that stays unknown after a refresh.
    /// [`AuthError::ProviderUnavailable`] when the issuer has no keys at all
    /// and cannot be reached. The two are distinct so an outage is not logged
    /// as an attack.
    pub async fn key_for(
        &self,
        iss: &IssuerUrl,
        kid: Option<&str>,
    ) -> Result<DecodingKey, AuthError> {
        let slot = self
            .slots
            .get(iss)
            .ok_or_else(|| AuthError::InvalidToken(format!("untrusted issuer `{iss}`")))?;

        // `kid` is required to name a key. Without it, exact selection is
        // impossible and only a try-all-keys search would succeed.
        let kid = kid.ok_or_else(|| {
            AuthError::InvalidToken("token header has no `kid`; cannot select a key".to_owned())
        })?;

        // Fast path: a fresh bundle that already names the key. The read guard
        // exists for the duration of one `Arc` clone and nothing else. So the
        // crate answers a token that names a key it already holds in
        // microseconds, however badly the issuer behaves.
        if let Some(bundle) = slot.cached().await
            && let Some(key) = lookup(&bundle, kid)
            && bundle.fetched_at.elapsed() < self.policy.ttl
        {
            return Ok(key);
        }

        // Nothing to serve from the fast path. The `kid` is unknown, which is
        // the usual sign of a rotation. Or the bundle is past its TTL, so the
        // crate has to stop accepting a quietly withdrawn key. Ask to fetch,
        // and hold no lock at all while the network is in use. That is what
        // turns a hung issuer into one slow request instead of a queue of them.
        //
        // Two kinds of request lose that race, and they are not the same
        // request. The one whose bundle still names the `kid` has an answer in
        // hand. A key past its TTL is still that issuer's public key, and it
        // must never wait for anything. The one with nothing to serve waits on
        // a fetch another request owns. Refusing it is the worse answer,
        // whichever way that fetch answers. A client retries a slow response,
        // not a 401. So a rotation under concurrent traffic would fail real
        // logins for the length of a fetch. It waits once, bounded, and looks
        // once. It does not fetch a second time. A second fetch would be a
        // queue with extra steps.
        match slot.begin_flight(self.policy.min_fetch_gap) {
            // This binding owns the single flight, and the flight ends when
            // this arm does.
            Turn::Mine(mut flight) => match self.fetch(slot).await {
                Ok(bundle) => {
                    info!(iss = %slot.iss, keys = bundle.keys.len(), "refreshed issuer keys");
                    slot.publish(Arc::new(bundle)).await;
                    // A success retires the failure note. `last_error` is read
                    // after an outage to mean "still broken", and a stale entry
                    // says that about a healthy provider.
                    slot.refresh_state().last_error = None;
                    flight.settle();
                }
                Err(err) => {
                    let note = err.to_string();
                    slot.refresh_state().last_error = Some(note.clone());
                    // Settled *before* the early return below. Dropping the
                    // guard un-settled would overwrite this precise reason with
                    // the vague abandoned-fetch one.
                    flight.settle();

                    // No keys were ever fetched, so the crate has nothing here
                    // to answer with.
                    if slot.cached().await.is_none() {
                        return Err(AuthError::ProviderUnavailable(format!(
                            "{iss}: cannot fetch keys ({note})"
                        )));
                    }
                    // Otherwise keep serving the previous set. The keys we have
                    // are still valid public keys, and a provider blip should
                    // not log every signed-in user out. Rotation is recovered by
                    // the next attempt, `min_fetch_gap` later.
                    warn!(
                        iss = %slot.iss,
                        error = %note,
                        "JWKS refresh failed; continuing with cached keys"
                    );
                }
            },
            Turn::Busy(mut generation) => {
                // The stale-but-known case is served as it is, without
                // waiting: it has its key, and the refresh is somebody else's
                // problem. Looking up again under the read lock rather than
                // reusing
                // the fast path's clone is deliberate. The flight may have
                // landed in between, and the newer bundle is the better answer.
                if slot.key_holding(kid).await.is_none() {
                    // Bounded by the budget the fetch itself has, so waiting
                    // for another request's refresh can never cost more than
                    // owning it would have. A timeout is not an error here: the
                    // re-lookup below decides the answer. `Turn::TooSoon` is
                    // what keeps a storm of invented `kid`s from becoming a
                    // storm of parked requests.
                    if tokio::time::timeout(self.policy.timeout, generation.changed())
                        .await
                        .is_err()
                    {
                        debug!(
                            iss = %slot.iss,
                            kid,
                            "no refresh landed to wake this request for"
                        );
                    }
                }
            }
            // Rate-limited, nothing in flight: answered from the bundle we
            // have, which is the existing refusal for a `kid` this issuer has
            // never published.
            Turn::TooSoon => {}
        }

        // Serve whatever is current now. That is the bundle just installed, the
        // one a flight we waited on installed, or the one already held after a
        // failed or skipped fetch.
        let served = slot.cached().await;

        served
            .as_ref()
            .and_then(|bundle| lookup(bundle, kid))
            .ok_or_else(|| {
                // Three cases, and the middle one is what this closes.
                //
                // No bundle at all is plainly the provider's failure. A bundle,
                // an issuer just reached, and no such `kid` is the token's
                // failure. That is a key this issuer has never published, and
                // calling it anything else would hand a forgery a retryable
                // status.
                //
                // A bundle plus a failed *most recent* refresh is neither.
                // A failed fetch stamps `last_attempt` like any other. So for
                // `min_fetch_gap` afterwards, every request that names a
                // not-yet-cached `kid` takes `Turn::TooSoon`, and the crate
                // answers it from the stale bundle. A 50ms reset at a reverse
                // proxy during a key rotation therefore turns every token minted
                // against the new key into a `401 invalid_token`. That status
                // blames the token for a fetch that failed. Clients treat
                // `invalid_token` as terminal and discard the session. That
                // contradicts the decision two statements earlier to keep
                // serving stale keys. That decision exists so a provider blip
                // does not log every signed-in user out. The keys were served.
                // The answer about the new one has to carry the same mercy.
                //
                // The next success clears `last_error`, so this reads "still
                // broken" rather than "broke once". It changes only the label.
                // `Turn::TooSoon` still gates the fetch, so an invented `kid`
                // cannot become a request flood any more than it could before.
                // It is just no longer told its token is forged.
                let unreachability_is_ours = slot.refresh_state().last_error.is_some();
                match (served, unreachability_is_ours) {
                    (None, _) => {
                        AuthError::ProviderUnavailable(format!("{iss}: no keys available"))
                    }
                    (Some(_), true) => AuthError::ProviderUnavailable(format!(
                        "{iss}: no key `{kid}` in the cached set, and the refresh \
                         that would have updated it failed"
                    )),
                    (Some(_), false) => {
                        AuthError::InvalidToken(format!("issuer `{iss}` has no key `{kid}`"))
                    }
                }
            })
    }

    /// Fetch and convert one issuer's JWKS.
    ///
    /// The caller holds no lock here. The [`Flight`] guard at the call site is
    /// what makes this single-flight. So a hung identity provider occupies the
    /// one request waiting on it, and nothing else.
    async fn fetch(&self, slot: &IssuerSlot) -> Result<TrustBundle, AuthError> {
        // `mut` for `chunk()`, which reads the body in place.
        let mut response = self
            .http
            .get(slot.jwks_url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| AuthError::ProviderUnavailable(err.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            return Err(AuthError::ProviderUnavailable(format!(
                "{url} answered {status}",
                url = slot.jwks_url
            )));
        }

        // Trust an honest advertised length only as an early exit, so an
        // oversized response is refused without opening the body at all. It is
        // not the bound. `Response::content_length` reports the length the
        // transport *decoded*, a `Transfer-Encoding: chunked` body has no
        // length to advertise, and a server may advertise one it does not keep.
        // Nothing above stops more than `max_bytes` arriving.
        if let Some(len) = response.content_length()
            && len > self.policy.max_bytes as u64
        {
            return Err(AuthError::ProviderUnavailable(format!(
                "JWKS is {len} bytes, over the {} byte limit",
                self.policy.max_bytes
            )));
        }

        // `response.bytes()` is unusable here. It folds the whole stream into
        // one allocation, so an oversized body is fully resident before
        // anything can look at its length. That cap would bound correctness and
        // not memory. A provider that streams 10 GB would see 10 GB allocated
        // first. Taking one chunk at a time and measuring the total *before*
        // appending holds peak bytes to the cap plus one chunk. The code
        // refuses the offending chunk instead of copying it. `chunk()` yields
        // `None` only at end of stream, which is the single normal exit.
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| AuthError::ProviderUnavailable(err.to_string()))?
        {
            // Written as the room that is left rather than as a sum, because
            // `bytes` is at or under the cap on entry by induction. The guard
            // asks "does this chunk fit", and that form cannot wrap. The test
            // here is what makes the old post-fetch `bytes.len() > max_bytes`
            // guard structurally unreachable rather than merely unlikely. The
            // code measures every byte against the cap before it appends, so
            // the old guard is gone. It is not kept as a guard that cannot
            // fire.
            if chunk.len() > self.policy.max_bytes - bytes.len() {
                return Err(AuthError::ProviderUnavailable(format!(
                    "JWKS body was {} bytes, over the {} byte limit",
                    bytes.len() + chunk.len(),
                    self.policy.max_bytes
                )));
            }

            bytes.extend_from_slice(&chunk);
        }

        let document: JwksDocument = serde_json::from_slice(&bytes).map_err(|err| {
            AuthError::ProviderUnavailable(format!(
                "{url} returned unreadable JSON: {err}",
                url = slot.jwks_url
            ))
        })?;

        let keys = self.convert_keys(document.keys, slot.iss.as_str());
        if keys.is_empty() {
            return Err(AuthError::ProviderUnavailable(format!(
                "{iss} published no usable keys",
                iss = slot.iss
            )));
        }

        Ok(TrustBundle {
            keys,
            fetched_at: Instant::now(),
        })
    }

    /// Turn a fetched JWKS into `(kid, DecodingKey)` pairs, skipping unusable
    /// keys one at a time.
    ///
    /// The code logs each rejection per key. Skipping a bad key beats failing
    /// the whole document. That is what lets a provider publish an encryption
    /// key, an `oct` key, or a declined algorithm alongside the signing keys in
    /// use.
    fn convert_keys(&self, raw: Vec<serde_json::Value>, iss: &str) -> Vec<(String, DecodingKey)> {
        let mut keys = Vec::with_capacity(raw.len());

        for jwk in raw {
            if let Some(key) = self.convert_key(jwk, iss) {
                keys.push(key);
            }
        }

        keys
    }

    /// Admit one JWK to the trust bundle, or refuse it with a log line.
    ///
    /// The order of the gates is the whole design. The code decides everything
    /// answerable from the JWK's own strings first, and converts the key only
    /// after its `kty` passes the allowlist. The reason: `DecodingKey::try_from`
    /// accepts an `oct` JWK and hands back a usable HMAC key. A symmetric key in
    /// this bundle is exactly the leg of the algorithm-confusion forgery that
    /// `lib.rs` describes. The attacker's "secret" is then a public key the
    /// verifier already trusts. That `try_from` can parse a key is not a reason
    /// to trust it.
    fn convert_key(&self, raw: serde_json::Value, iss: &str) -> Option<(String, DecodingKey)> {
        let text = |field: &str| raw.get(field).and_then(serde_json::Value::as_str);

        let kid = match text("kid") {
            Some(kid) => kid.to_owned(),
            None => {
                debug!(iss, "skipping JWK with no `kid`");
                return None;
            }
        };

        // Only signature keys. An encryption key is a different key for a
        // different purpose and must never verify a signature.
        if text("use") == Some("enc") {
            debug!(iss, kid, "skipping JWK with `use`: enc");
            return None;
        }

        // `alg` is optional on a JWK. When present it must be one we accept.
        // That field is the issuer telling us which tokens a key is for.
        // Believing it is what stops a key from becoming usable for an
        // algorithm nobody configured.
        if let Some(alg) = text("alg")
            && !self.allowed_algorithms.iter().any(|a| a == alg)
        {
            debug!(iss, kid, alg, "skipping JWK: algorithm not allowed");
            return None;
        }

        // Kept for the log lines below: once `raw` is consumed by the parse
        // there is nothing left to report about a key that failed it.
        let kty = text("kty").unwrap_or("-").to_owned();
        let crv = text("crv").unwrap_or("-").to_owned();

        let jwk = match serde_json::from_value::<Jwk>(raw) {
            Ok(jwk) => jwk,
            // `Jwk` is an untagged enum with a catch-all variant. In practice
            // that means a JWK which is not an object, or one whose common
            // parameters have the wrong JSON type.
            Err(err) => {
                warn!(iss, %kid, %kty, error = %err, "skipping unreadable JWK");
                return None;
            }
        };

        // The allowlist, spelled as key shapes. Everything not named here is
        // refused by the last arm. That includes `oct`, whose variant `try_from`
        // would have turned into an HMAC key, and any `kty` jsonwebtoken has
        // never heard of. Such a `kty` parses into its catch-all `Other` shape,
        // so it has to be refused for *not* being one of these three.
        let key = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => DecodingKey::try_from(&jwk),
            // The curve must match an algorithm this crate can name. There is
            // no `ES512`, so a P-521 key could never verify anything. Refusing
            // it here writes "unusable key type" to the log. Accepting it would
            // turn a realm that rotated to P-521 into a wave of bad signatures.
            AlgorithmParameters::EllipticCurve(params)
                if matches!(params.curve, EllipticCurve::P256 | EllipticCurve::P384) =>
            {
                DecodingKey::try_from(&jwk)
            }
            AlgorithmParameters::OctetKeyPair(params) if params.curve == EllipticCurve::Ed25519 => {
                DecodingKey::try_from(&jwk)
            }
            _ => {
                debug!(iss, kid, %kty, crv, "skipping JWK of unsupported key type");
                return None;
            }
        };

        let key = match key {
            Ok(key) => key,
            // Components that are present but nonsense: an EC point that is
            // not on its curve, a base64 `n`, an empty `y`. The issuer's other
            // keys are still fine, which is why this is a log and not an error.
            Err(err) => {
                warn!(iss, %kid, %kty, error = %err, "skipping JWK with unreadable components");
                return None;
            }
        };

        // Two guards the conversion cannot make for itself. They run here
        // because nothing downstream looks at a key again once the code bundles
        // it.
        //
        // The `kty` match refuses `oct` already. This says the same thing about
        // the *result*. So the property "no symmetric key is ever verified
        // against" survives an edit to that match. It also survives a
        // jsonwebtoken release that maps a JWK shape to a different family.
        if key.family() == AlgorithmFamily::Hmac {
            warn!(iss, kid, %kty, "skipping JWK that resolved to a symmetric key");
            return None;
        }

        // `EdDSAVerifier::new` in jsonwebtoken 12 reads the key as
        // `&bytes[..32]`, which panics on a short slice. A JWKS entry with a
        // five-byte `x` would therefore crash whichever request named that
        // `kid`, inside `decode`, on the authentication path. That would be a
        // provider bug turned into a remote crash. Whoever admits the key
        // measures its length, because upstream does not.
        if key.family() == AlgorithmFamily::Ed
            && !key.try_get_as_bytes().is_ok_and(|x| x.len() == 32)
        {
            warn!(iss, kid, "skipping Ed25519 JWK whose `x` is not 32 bytes");
            return None;
        }

        Some((kid, key))
    }
}

/// Exact `kid` match. There is no fallback, by design. See the module docs.
fn lookup(bundle: &TrustBundle, kid: &str) -> Option<DecodingKey> {
    bundle
        .keys
        .iter()
        .find(|(published, _)| published == kid)
        .map(|(_, key)| key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crate refuses an empty algorithm set rather than building it into a
    /// registry that can never verify anything.
    ///
    /// `Authenticator::start` rejects an unusable config first, and
    /// [`AuthConfig::validate`](crate::AuthConfig::validate) refuses an empty
    /// `algorithms`. So nothing arriving through the public API reaches this
    /// guard. That is exactly why it belongs in a unit test rather than the
    /// `tests/` suite. The suite can only ever show the *other* message
    /// (`no allowed signature algorithms`, from `validate`). A guard that no
    /// test exercises is a guard a later edit can delete unnoticed.
    ///
    /// What it is worth: without it, an empty set flows into
    /// `FamilyValidations` as an empty narrowing. Every key then fails the
    /// "this key cannot verify any accepted algorithm" rule. The deployment
    /// starts cleanly, warms its keys, and reports itself healthy. It then
    /// refuses every token from every caller forever, and each refusal blames
    /// the caller's token. That is an outage with a `200` on the health
    /// endpoint. It is the one configuration mistake in this file that does not
    /// announce itself.
    #[test]
    fn a_registry_with_no_accepted_algorithms_is_refused_at_construction() {
        let issuers = [(
            IssuerUrl::parse("https://issuer.example").expect("a URL"),
            Url::parse("https://issuer.example/jwks.json").expect("a JWKS URL"),
        )];

        let err = JwksRegistry::new(issuers, &[], CachePolicy::default(), true)
            .expect_err("an empty algorithm set must not yield a registry");

        assert!(
            matches!(err, AuthError::Configuration(_)),
            "an unusable algorithm set is a misconfiguration the operator owns, \
             not a provider failure they would retry: {err:?}"
        );
        assert!(
            err.to_string()
                .contains("no allowed signature algorithms configured"),
            "the message should say which knob is empty, since that is the whole \
             fix: {err}"
        );
    }

    /// An issuer this process has never reached takes the blame, both times.
    ///
    /// The first call owns the flight, fails to connect, and, with nothing
    /// cached, answers `cannot fetch keys`. The second arrives inside
    /// `min_fetch_gap`, is turned away `TooSoon`, finds no stale bundle to
    /// serve, and has to answer something too. Both are
    /// [`AuthError::ProviderUnavailable`], and that agreement is the point.
    /// The other reading available to the second call is `issuer has no key`.
    /// That tells the caller their token is forged, when the truth is that
    /// nobody here has ever spoken to the issuer. A client treats
    /// `invalid_token` as terminal and throws its session away. The mislabel is
    /// what turns a misconfiguration into users logged out.
    ///
    /// `Authenticator::start` cannot produce this state. It warms every slot and
    /// refuses to return without keys. So this test builds the registry directly
    /// and leaves `warm_up` off. That makes this the only test of an invariant
    /// that `start` relies on rather than performs. An empty bundle must answer
    /// "we cannot reach a decision", never "your token is bad". If a future
    /// construction path hands out a cold registry, this is what its callers
    /// meet.
    #[tokio::test]
    async fn an_issuer_that_has_never_been_reached_is_blamed_rather_than_the_token() {
        // A port that was bound and released. Nothing listens, so connecting
        // is refused immediately and the failure is the transport's. There is
        // no server, no timing, and no port that somebody else might have
        // claimed.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("a free port")
            .local_addr()
            .expect("the address it bound");
        let iss = IssuerUrl::parse(&format!("http://{addr}")).expect("a URL");
        let jwks_url = Url::parse(&format!("{iss}/jwks.json")).expect("a JWKS URL");

        let registry = JwksRegistry::new(
            [(iss.clone(), jwks_url)],
            &["RS256".to_owned()],
            CachePolicy::default(),
            true,
        )
        .expect("one issuer, one algorithm");

        let first = registry
            .key_for(&iss, Some("k1"))
            .await
            .expect_err("nothing is listening");
        let second = registry
            .key_for(&iss, Some("k1"))
            .await
            .expect_err("and the rate limit does not conjure a key");

        assert!(
            matches!(first, AuthError::ProviderUnavailable(_)),
            "the fetch failure is ours: {first:?}"
        );
        assert!(first.to_string().contains("cannot fetch keys"), "{first}");

        assert!(
            matches!(second, AuthError::ProviderUnavailable(_)),
            "rate-limited with nothing to serve is still our problem, not the \
             caller's: {second:?}"
        );
        assert!(second.to_string().contains("no keys available"), "{second}");

        for refusal in [&first, &second] {
            assert!(
                !matches!(refusal, AuthError::InvalidToken(_)),
                "neither \
                     refusal may read as a bad token, because that is the one a \
                     client stops retrying: {refusal}"
            );
            assert!(
                refusal.retryable(),
                "and both are worth trying again once \
                                          the provider is reachable: {refusal}"
            );
        }
    }

    /// A request that panicked holding the refresh lock leaves it usable.
    ///
    /// `refresh_state` recovers a poisoned lock rather than propagating. The
    /// reasoning is written on the method: no [`RefreshState`] field is an
    /// invariant spanning two others. So what sits behind a poisoned lock is
    /// still sound. One panicked request must not disable key refreshing for
    /// the life of the process.
    ///
    /// Nothing reachable can bring that panic about, because every critical
    /// section under this lock is infallible. That is why the recovery is a
    /// recovery instead of an `expect`. It is also why this test can only live
    /// here. Provoking it needs the `Mutex` itself, and there is no way to name
    /// it from outside this module.
    ///
    /// The test holds the guard *across* the panic on purpose.
    /// `slot.refresh_state().x = y;` drops its guard at the end of the
    /// statement. So a `panic!` on the next line would unwind nothing and poison
    /// nothing, and the assertions below would pass having tested the happy
    /// path.
    #[test]
    fn a_request_that_panicked_holding_the_refresh_lock_leaves_it_usable() {
        const BOOM: &str = "poisoning the refresh lock, on purpose";

        let slot = IssuerSlot::new(
            IssuerUrl::parse("https://demo.example").expect("a URL"),
            Url::parse("https://demo.example/jwks.json").expect("a JWKS URL"),
        );

        // No panic hook juggling: `cargo test` captures a caught panic's
        // output, so the deliberate `panic!` below prints nothing in a normal
        // run. With `--nocapture` it prints one line, which is the test working
        // rather than failing. Installing a filtering hook globally to hide it
        // was worth neither the dead branch nor the risk to another test's
        // diagnostics.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut state = slot.refresh_state();
            state.last_error = Some("written by the panicked holder".to_owned());
            panic!("{BOOM}");
        }));
        assert!(
            outcome.is_err(),
            "the holder should have panicked with the guard alive"
        );

        // The setup, not the recovery. If no poisoning actually happened, every
        // assertion below runs against an ordinary lock and passes for free.
        // That is the trap this file has already fallen into once elsewhere.
        assert!(
            slot.refresh.lock().is_err(),
            "the panic was caught but the mutex is not poisoned, so the recovery \
             this test is about never ran"
        );

        // The claim on the method: `into_inner` hands back the real state, not a
        // fresh one, because there is no cross-field invariant to be violated.
        let state = slot.refresh_state();
        assert_eq!(
            state.last_error.as_deref(),
            Some("written by the panicked holder"),
            "a recovered guard should carry what the panicked holder wrote to it"
        );
        drop(state);

        // And it keeps working, which is the other half. `into_inner` does not
        // clear the poison flag, so after one panic *every* later access takes
        // this path. This is not a one-time rescue. It is the permanent state
        // of a process that panicked once under this lock.
        slot.refresh_state().last_error = None;
        assert!(
            slot.refresh_state().last_error.is_none(),
            "the lock must stay writable after the recovery, not merely readable \
             once"
        );
    }
}
