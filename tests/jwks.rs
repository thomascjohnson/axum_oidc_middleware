//! The JWKS read path while the identity provider is slow.
//!
//! A refresh must never sit on the critical path of a request that already
//! holds the key it needs. Each test here hangs `/jwks.json`, then sends a
//! request while that fetch is stuck. Each test covers one of these cases:
//!
//! - The bundle already holds the key. That request must not wait.
//! - The key is only coming. That request must wait for the fetch, and the
//!   authenticator must not reject it early.
//!
//! These tests guard against two failure modes:
//!
//! - p99 on authenticated routes reads as a total outage.
//! - The opposite: a clean-looking 401 for a token whose key was one second
//!   from arriving.

mod common;

use std::time::{Duration, Instant};

use axum_oidc_middleware::{AuthConfig, AuthError, Authenticator, CachePolicy, Claims, Issuer};
use common::{StubIssuer, TestKey, raw_token};

const AUDIENCE: &str = "myaudience";

/// How long the issuer parks for. Long enough that sharing a lock with the
/// network shows up as seconds rather than as scheduling noise.
const STALL: Duration = Duration::from_secs(2);

/// Four times faster than the stall. The timer covers an `Arc` clone plus an
/// RSA signature check, which takes microseconds. This margin is slack, not
/// the threshold the test decides on.
const PROMPT: Duration = Duration::from_millis(500);

/// The bound a request waits for somebody else's refresh, mirrored from the
/// policy below. Also the ceiling on how long an invented `kid` can tie up a
/// request.
const WAIT: Duration = Duration::from_secs(10);

/// Between `STALL` and `WAIT`: a waiter woken by the generation bump clears
/// this, and one that slept out its timeout does not. The gap is the
/// assertion — without it a missed wake-up would only make the test slow.
const ANSWERED: Duration = Duration::from_secs(5);

/// `min_fetch_gap` short enough for a test to wait out, `timeout` long enough
/// that a stalled fetch is still in flight when the cached-key request runs.
fn policy(ttl: Duration) -> CachePolicy {
    CachePolicy {
        ttl,
        min_fetch_gap: Duration::from_secs(1),
        timeout: WAIT,
        ..CachePolicy::default()
    }
}

/// An authenticator warmed against a stub issuer publishing `key`.
///
/// This helper warms the authenticator here, not the caller. That keeps "the
/// cache has this key" out of the assertions: without it a slow answer could
/// be an honest miss.
async fn harness(key: &TestKey, ttl: Duration) -> (StubIssuer, Authenticator, String) {
    let stub = StubIssuer::start_local(std::slice::from_ref(key)).await;
    let iss = stub.iss();

    let config = AuthConfig::empty()
        .with_issuer(Issuer::discover(iss.clone(), [AUDIENCE]).expect("valid issuer"))
        .with_policy(policy(ttl))
        .with_insecure_http(true);

    let auth = Authenticator::start(config)
        .await
        .expect("start an authenticator against the stub issuer");

    let token = key.sign(&key.claims(&iss, AUDIENCE));
    auth.authenticate(&token).await.expect("warm the key cache");

    (stub, auth, iss)
}

/// A token naming a key the issuer has not published yet — the one thing that
/// forces a refresh — with an otherwise valid payload.
fn rotation_token(key: &TestKey, iss: &str) -> String {
    raw_token(
        &serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": "kid-rotating-in" }),
        &key.claims(iss, AUDIENCE),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
}

/// Drive one refresh attempt in the background. Report its outcome next to how
/// long it took, so "the endpoint really stalled" is an assertion too.
fn refresh(
    auth: &Authenticator,
    key: &TestKey,
    iss: &str,
) -> tokio::task::JoinHandle<(Result<(), AuthError>, Duration)> {
    let auth = auth.clone();
    let key = key.clone();
    let iss = iss.to_owned();

    tokio::spawn(async move {
        let started = Instant::now();
        // No bundle publishes this `kid`. The only interesting part of the
        // result is when the authenticator rejects it: it waits out the fetch
        // first, then rejects.
        let outcome = auth
            .authenticate(&rotation_token(&key, &iss))
            .await
            .map(|_| ());
        (outcome, started.elapsed())
    })
}

#[tokio::test]
async fn a_known_key_is_served_while_a_refresh_hangs() {
    let key = TestKey::generate("k1");
    // A TTL nothing in this test outlives: the second request is meant to be
    // answered by the ordinary cache hit.
    let (stub, auth, iss) = harness(&key, Duration::from_secs(600)).await;
    let token = key.sign(&key.claims(&iss, AUDIENCE));

    stub.set_delay(STALL);
    // Past `min_fetch_gap`, so the next unknown `kid` may start a fetch.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let hits = stub.jwks_requests();
    let stalled = refresh(&auth, &key, &iss);

    // Only once the fetch reaches the issuer does a refresh exist to block on.
    assert!(
        stub.wait_for_jwks_requests(hits + 1).await,
        "the refresh never reached `/jwks.json`"
    );

    let started = Instant::now();
    let claims = auth
        .authenticate(&token)
        .await
        .expect("a token naming a cached key must still authenticate");
    let elapsed = started.elapsed();

    assert_eq!(claims.sub, "user-123");
    assert!(
        elapsed < PROMPT,
        "a cached `kid` waited {elapsed:?} behind a refresh parked for {STALL:?}: \
         the read path is sharing a lock with the network"
    );
    assert_eq!(
        stub.jwks_requests(),
        hits + 1,
        "a cache hit must not start a second fetch behind the stalled one"
    );

    // The stalled request is slow, not lost, and it is the only one that paid.
    let (outcome, refresh_elapsed) = stalled.await.expect("the refresh task runs");
    assert!(
        matches!(outcome, Err(AuthError::InvalidToken(_))),
        "an unpublished `kid` is still refused, got {outcome:?}"
    );
    assert!(
        refresh_elapsed >= STALL,
        "the refresh should have waited on the stalled endpoint, took {refresh_elapsed:?}"
    );
    assert_eq!(
        stub.jwks_requests(),
        hits + 1,
        "one fetch per issuer, however long it takes"
    );
}

#[tokio::test]
async fn a_stale_bundle_serves_a_known_kid_without_a_second_fetch() {
    // The same discipline one step further in. The bundle holds this `kid`,
    // but the bundle is older than its TTL. The request therefore walks into
    // the refresh path and still comes back without touching the network.
    let key = TestKey::generate("k1");
    let (stub, auth, iss) = harness(&key, Duration::from_millis(250)).await;
    let token = key.sign(&key.claims(&iss, AUDIENCE));

    stub.set_delay(STALL);
    // Past the TTL *and* `min_fetch_gap`, so this request would fetch if it
    // were the first one allowed to.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let hits = stub.jwks_requests();
    let stalled = refresh(&auth, &key, &iss);

    assert!(
        stub.wait_for_jwks_requests(hits + 1).await,
        "the refresh never reached `/jwks.json`"
    );

    let started = Instant::now();
    let claims = auth
        .authenticate(&token)
        .await
        .expect("a stale bundle still serves a key it holds");
    let elapsed = started.elapsed();

    assert_eq!(claims.sub, "user-123");
    assert!(
        elapsed < PROMPT,
        "a known `kid` waited {elapsed:?} on a fetch another request owns; losing \
         the turn must mean serving the stale bundle, not queueing"
    );
    assert_eq!(
        stub.jwks_requests(),
        hits + 1,
        "the single flight must not be doubled by a losing request"
    );

    let (outcome, _) = stalled.await.expect("the refresh task runs");
    assert!(
        matches!(outcome, Err(AuthError::InvalidToken(_))),
        "an unpublished `kid` is still refused, got {outcome:?}"
    );
}

/// `authenticate`, paired with how long the call took.
async fn timed(auth: &Authenticator, token: &str) -> (Result<Claims, AuthError>, Duration) {
    let started = Instant::now();
    let outcome = auth.authenticate(token).await;
    (outcome, started.elapsed())
}

#[tokio::test]
async fn concurrent_requests_for_a_rotating_key_share_one_fetch() {
    // The rotation case. This is why the authenticator does not simply reject
    // a request that loses the single flight. `k2` signs a token whose key
    // this process has never seen, so neither request can read an answer from
    // cache. One request claims the flight, and the other waits for the first
    // to wake it when the fetch lands. The alternative is a 401 that lasts the
    // length of a fetch. An HTTP client does not retry a 401 the way it
    // retries a slow response.
    let first = TestKey::generate("k1");
    let next = TestKey::generate("k2");
    let (stub, auth, iss) = harness(&first, Duration::from_secs(600)).await;

    // The issuer moves to `k2` and then slows down. The fetch that finds it
    // therefore stays genuinely in progress for as long as the test needs.
    stub.rotate(std::slice::from_ref(&next));
    stub.set_delay(STALL);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let hits = stub.jwks_requests();
    let token = next.sign(&next.claims(&iss, AUDIENCE));

    // Concurrent on one thread: the first future parks on the stalled network
    // call, so by the time the second reaches `begin_flight` the flight is
    // provably owned. Which of the two owns it is not decided here — the point
    // is that neither answer is a rejection.
    let (one, two) = tokio::join!(timed(&auth, &token), timed(&auth, &token));

    for (outcome, elapsed) in [one, two] {
        let claims = outcome.expect("a rotated key must authenticate, whoever had to fetch it");
        assert_eq!(claims.sub, "user-123");
        assert!(
            elapsed < ANSWERED,
            "a rotation request took {elapsed:?}: it should be woken by the fetch \
             landing after {STALL:?}, not by its own {WAIT:?} timeout"
        );
    }

    // This claim is what stops "everyone fetches their own". The issuer
    // answers one fetch, and the second request reads from what that one fetch
    // installed.
    assert_eq!(
        stub.jwks_requests(),
        hits + 1,
        "two concurrent requests for an unknown `kid` must be one fetch"
    );
}

/// A refresh that fails must not be reported as a bad token.
///
/// The scenario is a key rotation with a transient fault behind it. The issuer
/// moves to `k2`, and the one fetch that would have learned of it dies. Causes:
/// a reset at a reverse proxy, a 502, or a DNS blip. A failed attempt stamps the
/// rate limit exactly as a successful one does. So for `min_fetch_gap`
/// afterwards, every request naming `k2` is answered from the stale bundle.
///
/// Serving those stale keys is the accepted design, and this test keeps it: the
/// bundle is still used, nobody is logged out. What must change is the label on
/// the one request it cannot serve. `invalid_token` tells a client its token is
/// counterfeit and the session is discarded. The token was fine, the fetch was
/// not.
#[tokio::test]
async fn a_failed_refresh_blames_the_provider_rather_than_the_token() {
    let first = TestKey::generate("k1");
    let next = TestKey::generate("k2");
    let (stub, auth, iss) = harness(&first, Duration::from_secs(600)).await;

    // Rotate, break the issuer, then wait out `min_fetch_gap`. The next
    // request then genuinely owns a flight and watches it fail, instead of the
    // rate limiter stopping it before it tries.
    stub.rotate(std::slice::from_ref(&next));
    stub.set_failing(true);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let token = next.sign(&next.claims(&iss, AUDIENCE));

    // The request that owned the failed fetch.
    let err = auth
        .authenticate(&token)
        .await
        .expect_err("k2 was never published to this process, so nothing can verify it");
    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "a token whose key is missing *because the refresh failed* is a provider \
         problem, not a forged token: {err:?}"
    );
    assert!(
        err.retryable(),
        "the caller has to be told to try again; this token is valid and will \
         verify the moment the issuer is reachable: {err:?}"
    );

    // The reviewer's actual case: requests 2..N arriving during the cooldown.
    // These do not even attempt a fetch — `Turn::TooSoon` gates them — so the
    // question is purely what a stale-bundle refusal claims.
    for _ in 0..3 {
        let err = auth
            .authenticate(&token)
            .await
            .expect_err("still rate-limited, still no k2");
        assert!(
            matches!(err, AuthError::ProviderUnavailable(_)) && err.retryable(),
            "a cooldown refusal during an outage must not read as `invalid_token`: {err:?}"
        );
    }

    // And it heals: the moment the issuer answers, the authenticator clears
    // `last_error`, the new key lands, and the same token verifies.
    stub.set_failing(false);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let claims = auth
        .authenticate(&token)
        .await
        .expect("once the issuer answers, the rotated key must work");
    assert_eq!(claims.sub, "user-123");
}

/// The refusal above must not become the default for every unknown `kid`.
///
/// The distinction is the whole value of the change. An issuer that is healthy,
/// that published its key set, and that still does not recognise a `kid` says
/// the key was never issued. Everything in that sentence is verifiable: the fetch
/// succeeded, the document was parsed, and the `kid` is absent from it. The only
/// remaining explanation belongs to the token. Calling *that* retryable would
/// hand a forged `kid` an endless loop of `503`s and invite a client to hammer a
/// provider that already answered.
#[tokio::test]
async fn an_unknown_kid_from_a_healthy_issuer_is_still_the_tokens_fault() {
    let key = TestKey::generate("k1");
    let ghost = TestKey::generate("k-never-published");
    let (_stub, auth, iss) = harness(&key, Duration::from_secs(600)).await;

    let token = ghost.sign(&ghost.claims(&iss, AUDIENCE));
    let err = auth
        .authenticate(&token)
        .await
        .expect_err("no such key was ever published");

    assert!(
        matches!(err, AuthError::InvalidToken(_)),
        "the issuer answered and does not know this `kid`; that is the token's \
         problem and must stay a 401: {err:?}"
    );
    assert!(
        !err.retryable(),
        "a retryable status here would turn a forged `kid` into a client that \
         never gives up: {err:?}"
    );
}

/// A fetch that never finished must not be recorded as one that failed benignly.
///
/// The path is cancellation, not error. The client hangs up, or a proxy in front
/// of this server times out and drops the request future mid-`await`. The
/// `Flight` guard still runs its `Drop`. RAII has no vote in that. So it stamps
/// the rate limit as though an attempt completed. The `Err` arm that would have
/// written `last_error` never ran.
///
/// Without an abandoned-fetch marker, the next request for the rotated `kid`
/// takes `Turn::TooSoon` during the cooldown. It finds nothing recorded against
/// the issuer, and concludes the *token* is bad. One disconnected client is
/// therefore enough to have a real session discarded at the next rotation.
#[tokio::test]
async fn an_abandoned_fetch_is_not_recorded_as_a_healthy_issuer() {
    let first = TestKey::generate("k1");
    let next = TestKey::generate("k2");
    let (stub, auth, iss) = harness(&first, Duration::from_secs(600)).await;

    stub.rotate(std::slice::from_ref(&next));
    stub.set_delay(STALL);

    // `warm_up` stamped `last_attempt` at start-up, so inside `min_fetch_gap`
    // an unknown `kid` takes `Turn::TooSoon` and never claims a flight — there
    // would be nothing to abandon. Wait the gap out first.
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let token = next.sign(&next.claims(&iss, AUDIENCE));
    let before = stub.jwks_requests();

    // Start the fetch, let it reach the network, then destroy it mid-flight.
    //
    // `select!` is doing real work here, not ceremony. A future does not run
    // merely by being pinned. The earlier shape — pin, sleep, drop — polled
    // nothing, opened no connection, and dropped a `Flight` that was never
    // claimed. `select!` polls the fetch until the timer wins, and the losing
    // branch is then dropped mid-`await`. That is byte-for-byte what a client
    // disconnect does to a request handler.
    let outcome = tokio::select! {
        result = auth.authenticate(&token) => Some(result),
        () = tokio::time::sleep(Duration::from_millis(400)) => None,
    };
    assert!(
        outcome.is_none(),
        "the fetch finished inside the window, so nothing was abandoned; raise \
         the stub delay or shorten this timer"
    );

    // Proof there was genuinely a flight to abandon. Without this the test
    // would silently pass by never exercising `Flight::drop` at all, which is
    // precisely how the first version of it was wrong.
    assert!(
        stub.jwks_requests() > before,
        "no JWKS request was made, so nothing was in flight to abandon; the gap \
         is mis-timed and this test would prove nothing"
    );

    // `select!` already dropped the fetch when its timer won. This wait only
    // lets the runtime finish unwinding the guard.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now a *different*, fully-live request arrives inside the cooldown. It
    // will not fetch — `min_fetch_gap` gates it — so all it has to go on is
    // what the abandoned attempt left behind.
    let err = auth
        .authenticate(&token)
        .await
        .expect_err("k2 is still not in any bundle this process holds");

    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "the previous attempt was abandoned, not answered; a live request must \
         not infer a healthy issuer from that and blame the token: {err:?}"
    );
    assert!(
        err.retryable(),
        "the token is valid and will verify once a fetch is allowed to finish: {err:?}"
    );

    // And it heals: let a fetch complete, and the same token works.
    stub.set_delay(Duration::ZERO);
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let claims = auth
        .authenticate(&token)
        .await
        .expect("a fetch that completes must clear the abandonment and land k2");
    assert_eq!(claims.sub, "user-123");
}

/// A parked `Turn::Busy` waiter must not pay the full timeout when the flight
/// it is waiting on has already finished.
///
/// The claim under test: `watch::Receiver::changed()` is edge-triggered, so a
/// bump that lands *before* the `await` is lost and the waiter sleeps for the
/// whole `policy.timeout`. It is not. `subscribe()` marks the version current
/// at subscribe time as seen, and `changed()` compares versions when polled. So
/// a bump that happens after subscribing and before the `await` is still
/// pending and returns immediately. The ordering in `key_for` is also critical
/// here. `Turn::Busy` is only handed out while `fetching` is true, so the
/// flight being watched is guaranteed outstanding at subscribe time and its
/// completion is guaranteed to bump. A bump can only be missed by having landed
/// *before* the subscribe, which `Turn::Busy`'s own precondition excludes. That
/// caller takes `Turn::Mine` or `Turn::TooSoon` instead.
///
/// The scenario is the one where the answer is "never". The waiter wants a `kid`
/// the issuer does not publish, so no bundle will ever satisfy it. It must fall
/// through to refusal on a *bounded* wait rather than a timeout.
///
/// **The `ttl` here is critical, and an earlier version of this test had it
/// wrong.** With a `ttl` the test never outlives, the bundle is still fresh, so
/// the `k1` caller returns from `key_for`'s fast path in microseconds and never
/// reaches `begin_flight`. It measured 250 µs against a 2 s stall. It cannot
/// own the flight, and nothing parks behind it. The phantom caller fetches for
/// itself, `elapsed` measures that fetch rather than a wake-up, and
/// `jwks_requests() == 1` is satisfied by the only caller that could fetch at
/// all. The test would have kept passing with `changed()` broken. A `ttl` the
/// sleep outlives pushes the `k1` caller past the fast path, so it wins the
/// flight and the phantom caller genuinely takes `Turn::Busy`.
#[tokio::test]
async fn a_busy_waiter_wakes_the_moment_its_flight_lands_not_at_the_timeout() {
    let first = TestKey::generate("k1");
    // Stale by the time the 1.2 s sleep below finishes, which is what puts the
    // `k1` caller into `begin_flight` instead of the fast path.
    let (stub, auth, iss) = harness(&first, Duration::from_millis(400)).await;

    // Long enough that a lost wake is unmistakable against the ~STALL the fetch
    // actually takes. Also short enough to keep the test honest about which
    // bound it measured.
    let long = Duration::from_secs(8);
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let phantom = TestKey::generate("phantom-never-published");
    let token = phantom.sign(&phantom.claims(&iss, AUDIENCE));

    stub.rotate(std::slice::from_ref(&first));
    stub.set_delay(STALL);
    let before = stub.jwks_requests();
    let started = tokio::time::Instant::now();

    // Owner of the flight: fetches, and bumps the generation when it lands.
    // Bound to a `let` because `authenticate` borrows the token and `join!`
    // holds both futures past the end of this statement.
    let owned = first.sign(&first.claims(&iss, AUDIENCE));
    let owner = auth.authenticate(&owned);
    // Parked behind it, for a `kid` no bundle will ever carry.
    let waiter = auth.authenticate(&token);

    // Finishing inside `long` is the whole assertion: reaching the tuple at
    // all means the waiter woke on the generation bump, not on a timer.
    let (owner_outcome, waiter_outcome) =
        tokio::time::timeout(long, async { tokio::join!(owner, waiter) })
            .await
            .expect("the waiter must not wait out the full timeout");
    owner_outcome.expect("k1 is published");

    let err = waiter_outcome.expect_err("the issuer does not publish this kid");
    assert!(
        matches!(err, AuthError::InvalidToken(_)),
        "an invented `kid` against a healthy issuer is the caller's problem: {err:?}"
    );
    // How long the pair took, which is the actual measurement: ~STALL means the
    // waiter woke on the bump, ~`long` means it slept out the timeout. `long` is
    // 8s and the fetch 2s, so the two are not confusable.
    let elapsed = started.elapsed();
    assert!(
        elapsed < long,
        "waited {elapsed:?}, which is the timeout, not the fetch"
    );

    assert_eq!(
        stub.jwks_requests() - before,
        1,
        "the waiter must have joined the owner's fetch rather than starting a \
         second one"
    );
    eprintln!("busy waiter resolved in {elapsed:?} (fetch {STALL:?}, cap {long:?})");
}

/// One fetch budget bounds everybody who is waiting, and a caller woken by a
/// *failed* fetch must still not be told its token is forged.
///
/// `key_for` bounds a parked waiter with `policy.timeout`. The theory is that
/// the fetch it waits for started earlier, is bounded by the same number, and so
/// settles first. That theory rests on reqwest's `timeout` being a *total*
/// deadline, held all the way through a streamed body rather than released when
/// the headers arrive. This is the provider that tests the weaker reading: it
/// answers nothing at all, so the fetch has to be ended by its own clock. If that
/// ever stopped being true, the flight would outlive the wait and the waiter's
/// lapse arm would start firing. Every request behind a rotation would then sit
/// through a second full budget before the crate refused it.
///
/// The label is the other half, and the half a caller feels. The waiter wants a
/// `kid` that the cached bundle does not name, and the refresh that would have
/// named it just failed. `key_for` has to answer `(bundle, failed refresh)` — a
/// provider's failure — rather than `(bundle, no such kid)`, because
/// `invalid_token` reads as terminal. A client that sees it discards the session.
/// That contradicts serving the stale keys in the first place.
#[tokio::test]
async fn a_provider_hanging_past_its_budget_refuses_the_waiter_as_an_outage() {
    // Both clocks, and the hang outruns them by an order of magnitude.
    const BUDGET: Duration = Duration::from_millis(600);
    const HANG: Duration = Duration::from_secs(6);

    let first = TestKey::generate("k1");
    let stub = StubIssuer::start_local(std::slice::from_ref(&first)).await;
    let iss = stub.iss();

    // A `ttl` the sleep below outlives, so the `k1` caller is the one that
    // notices the bundle is stale and takes the flight. `min_fetch_gap` is
    // irrelevant once a flight exists — it gates starting one, not joining it.
    let auth = Authenticator::start(
        AuthConfig::empty()
            .with_issuer(Issuer::discover(iss.clone(), [AUDIENCE]).expect("valid issuer"))
            .with_policy(CachePolicy {
                ttl: Duration::from_millis(400),
                min_fetch_gap: Duration::from_secs(1),
                timeout: BUDGET,
                ..CachePolicy::default()
            })
            .with_insecure_http(true),
    )
    .await
    .expect("start an authenticator against the stub issuer");

    auth.authenticate(&first.sign(&first.claims(&iss, AUDIENCE)))
        .await
        .expect("warm the key cache");

    // Past both clocks: the `ttl`, so the bundle reads stale, and
    // `min_fetch_gap`, whose 1 s floor is `CachePolicy`'s own guard against
    // forged tokens hammering an issuer. Inside that gap the owner would take
    // `Turn::TooSoon` and never start the flight this test is about.
    tokio::time::sleep(Duration::from_millis(1_300)).await;
    stub.set_delay(HANG);

    let phantom = TestKey::generate("phantom-never-published");
    let before = stub.jwks_requests();
    let started = Instant::now();

    // Spawned so it is unambiguously inside its own flight by the time the
    // waiter arrives, rather than racing the waiter for `begin_flight`.
    let owner = tokio::spawn({
        let auth = auth.clone();
        let token = first.sign(&first.claims(&iss, AUDIENCE));
        async move { auth.authenticate(&token).await }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let waiter_token = phantom.sign(&phantom.claims(&iss, AUDIENCE));
    let waiter = auth.authenticate(&waiter_token).await;
    let owner = owner.await.expect("the owner's request ran").err();

    let elapsed = started.elapsed();
    let fetches = stub.jwks_requests() - before;

    // The caller that already holds the key is served through the outage — by
    // the stale bundle, once its own fetch gave up on the provider.
    assert!(
        owner.is_none(),
        "a key this issuer published is still that issuer's key, outage or not: \
         {owner:?}"
    );

    let err = waiter.expect_err("nothing publishes this kid while the provider hangs");
    let AuthError::ProviderUnavailable(note) = err else {
        panic!(
            "a refresh that died of a timeout is the provider's failure, not a \
                verdict on the token; got {err:?}"
        );
    };
    assert!(
        note.contains("refresh"),
        "the note should say the refresh failed, which is the whole reason this is \
         a 503 and not a 401: `{note}`"
    );

    assert_eq!(
        fetches, 1,
        "the waiter should join the flight it woke on, not start a second one"
    );
    // A second hung fetch would land here at ~2 x BUDGET. So would a waiter
    // whose wake-up was missed and who then fetched for itself.
    assert!(
        elapsed < BUDGET * 2,
        "the pair took {elapsed:?}, which is more than the one {BUDGET:?} budget \
         they share"
    );

    eprintln!("hang {HANG:?}, budget {BUDGET:?}, pair resolved in {elapsed:?}");
}
