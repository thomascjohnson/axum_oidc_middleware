//! Configuration: the two `Issuer` constructors, and what `validate` refuses.
//!
//! `validate` is the only thing standing between a typo in a config file and
//! an authentication policy that is quietly weaker than the operator meant.
//! Each test here names one misconfiguration. It asserts that `validate`
//! refuses that misconfiguration at boot, in words that say which setting is
//! wrong. A deployment should not have to bisect its own config to find out
//! why the process will not start.

mod common;

use std::time::Duration;

use axum_oidc_middleware::{AuthConfig, AuthError, Authenticator, CachePolicy, Issuer};
use common::{StubIssuer, TestKey};

const AUDIENCE: &str = "my-api";
const URL: &str = "https://identity.example";

/// A configuration that is valid apart from whatever a test adds to it.
///
/// The issuer arrives naming its own audience, which is the only way to build
/// one that boots.
fn config() -> AuthConfig {
    AuthConfig::empty().with_issuer(Issuer::discover(URL, [AUDIENCE]).expect("valid issuer"))
}

/// The message `validate` produced, panicking if the config was accepted.
fn problem(config: &AuthConfig) -> String {
    match config.validate() {
        Err(AuthError::Configuration(reason)) => reason,
        Ok(()) => panic!("the configuration was accepted, but should not be"),
        Err(other) => panic!("expected a configuration error, got {other:?}"),
    }
}

// ── `Issuer` construction ────────────────────────────────────────────────────

/// An issuer identifier that is not a URL cannot be discovered from, and
/// cannot be reached at all. Both constructors refuse it where the mistake is
/// made rather than at the first request.
#[test]
fn an_issuer_that_is_not_a_url_is_refused_by_both_constructors() {
    let discover =
        Issuer::discover("identity.example", [AUDIENCE]).expect_err("no scheme is not a URL");
    assert!(
        discover.to_string().contains("identity.example"),
        "the error should name the issuer: {discover}"
    );

    let keys = url::Url::parse("https://identity.example/jwks.json").expect("parse a JWKS URL");
    let direct = Issuer::with_jwks_url("identity.example", keys, [AUDIENCE])
        .expect_err("no scheme is not a URL");
    assert!(
        direct.to_string().contains("not a URL"),
        "the same rule applies with an explicit JWKS URL: {direct}"
    );
}

/// A query or a fragment on an issuer identifier makes it a *redirect
/// target*, the shape an OAuth callback URL has. That is not an issuer.
/// Accepting one would mean comparing `iss` byte-for-byte against a value
/// that differs from the issuer's own published identifier only in a suffix.
/// Nobody meant that suffix to be part of it. The result: the crate rejects
/// the token for reasons nobody can read off the config.
#[test]
fn an_issuer_must_not_carry_a_query_or_a_fragment() {
    for iss in [
        "https://identity.example/callback?state=abc",
        "https://identity.example/#tenant",
    ] {
        let err = Issuer::discover(iss, [AUDIENCE]).expect_err("`iss` is not a redirect target");
        assert!(
            err.to_string().contains("query or fragment"),
            "`{iss}` should be refused for its suffix: {err}"
        );
    }

    // The same holds with a JWKS endpoint named directly. It is the issuer
    // identifier that is under inspection, not the key location.
    let keys = url::Url::parse("https://identity.example/jwks.json").expect("parse a JWKS URL");
    assert!(
        Issuer::with_jwks_url(
            "https://identity.example?tenant=a",
            keys.clone(),
            [AUDIENCE]
        )
        .expect_err("`iss` is not a query string")
        .to_string()
        .contains("query or fragment")
    );
    assert!(
        Issuer::with_jwks_url("https://identity.example#tenant", keys, [AUDIENCE])
            .expect_err("`iss` is not a fragment")
            .to_string()
            .contains("query or fragment")
    );
}

// ── Discovery under a path ───────────────────────────────────────────────────

/// RFC 8414 §3.1 appends `.well-known/openid-configuration` to the issuer's
/// path. A Keycloak realm *is* a path, `…/realms/demo`. Dropping the path
/// would send every realm's discovery request to `/`, where a different realm
/// or nothing at all answers. The trailing slash matters too. Without it, the
/// appended segment replaces the last path element instead of joining to it.
#[tokio::test]
async fn an_issuer_at_a_path_is_discovered_at_that_path() {
    let key = TestKey::generate("realm1");
    // `iss` is `http://127.0.0.1:PORT/realms/demo`, with discovery and JWKS
    // served beneath it.
    let stub = StubIssuer::start_local_at("/realms/demo", std::slice::from_ref(&key)).await;

    let auth = Authenticator::start(
        AuthConfig::empty()
            .with_issuer(Issuer::discover(stub.iss(), [AUDIENCE]).expect("valid issuer"))
            .with_insecure_http(true),
    )
    .await
    .expect("a realm at a path is discoverable at that path");

    // If the code dropped the path, discovery would answer 404 and `start`
    // would never return. This test proves that it found *this* realm's keys.
    // A token this realm signs authenticates.
    let claims = key.sign(&key.claims(&stub.iss(), AUDIENCE));
    let verified = auth
        .authenticate(&claims)
        .await
        .expect("the realm's own token authenticates");
    assert_eq!(verified.iss.as_str(), stub.iss());
    assert_eq!(verified.sub, "user-123");
}

// ── What `validate` refuses ──────────────────────────────────────────────────

#[test]
fn a_config_with_no_issuers_is_refused() {
    // This is not a locked-down deployment. It is a deployment that cannot
    // authenticate anything. It would say so with a 401 on every route, not
    // with a log line at boot.
    let err = problem(&AuthConfig::empty());
    assert!(err.contains("no trusted issuers"), "{err}");
}

#[test]
fn a_config_with_no_algorithms_is_refused() {
    // An empty algorithm set is an outage, not hardening. No signature can
    // pass.
    let err = problem(&config().with_algorithms([]));
    assert!(err.contains("no allowed signature algorithms"), "{err}");
}

#[test]
fn a_timeout_short_enough_to_always_fail_is_refused() {
    // 100ms is not a policy. It is a guarantee that a cold cache loses its
    // first request to any real identity provider across any real network.
    let too_small = CachePolicy {
        timeout: Duration::from_millis(50),
        ..CachePolicy::default()
    };
    let err = problem(&config().with_policy(too_small));
    assert!(err.contains("provider timeout"), "{err}");

    // The boundary itself is allowed. Exactly 100ms is slow, not absurd.
    let boundary = CachePolicy {
        timeout: Duration::from_millis(100),
        ..CachePolicy::default()
    };
    config()
        .with_policy(boundary)
        .validate()
        .expect("100ms is the floor, not under it");
}

#[test]
fn an_issuer_cannot_be_assembled_around_its_constructors() {
    // This test used to assemble an `Issuer` whose `iss` skipped `Url::parse`
    // through the public fields, to prove `validate` re-checks anyway. Struct
    // literals are closed now: `audiences` and `authorized_parties` are private,
    // and one private field is enough to refuse a literal from another module.
    // So both constructors always run their parse before an `Issuer` exists.
    //
    // The trade is real and is stated on `Issuer`: a host that assembled one
    // from its own config type now calls `discover` or `with_jwks_url`, both of
    // which take the audiences that used to be left out.
    AuthConfig::empty()
        .with_issuer(Issuer::discover(URL, [AUDIENCE]).expect("valid issuer"))
        .validate()
        .expect("the only reachable shape is a well-formed one");

    // What a caller can still get wrong is the set itself. Arity forces it to
    // be addressed; `[]` addresses it with nothing, and the constructor refuses
    // that rather than handing back an issuer that only fails at boot. So the
    // mistake surfaces on the line that made it.
    let silent = Issuer::discover(URL, Vec::<String>::new())
        .expect_err("naming no audience is not an issuer");
    let reason = silent.to_string();
    assert!(
        reason.contains("names no audiences") && reason.contains(URL),
        "the refusal should name the issuer that said nothing: {reason}"
    );
}

/// The one route the private audience list did **not** close.
///
/// 0.2.0 let a caller assign `issuer.iss = "identity.example".to_owned()`, which
/// left `validate` to notice the missing scheme at boot. That route is gone: the
/// field is private and typed, and the only way to obtain its type is
/// [`IssuerUrl::parse`], which refuses both a missing scheme and an empty
/// string. This test pins what replaced it — the value a constructor accepted is
/// what `iss()` returns, and there is no setter beside it to change that later.
///
/// The text is compared byte for byte, so a trailing slash still makes a
/// different issuer. That is the property a host's tokens depend on.
#[test]
fn the_issuer_text_is_settled_by_the_constructor() {
    let issuer = Issuer::discover(URL, [AUDIENCE]).expect("valid issuer");
    assert_eq!(issuer.iss().as_str(), URL);

    let slashed = Issuer::discover(format!("{URL}/"), [AUDIENCE]).expect("valid issuer");
    assert_eq!(slashed.iss().as_str(), format!("{URL}/"));
    assert_ne!(
        issuer.iss(),
        slashed.iss(),
        "a trailing slash is a different issuer, and the type must not merge them"
    );
}

#[test]
fn the_same_issuer_listed_twice_is_refused() {
    // Two entries for one `iss` mean two trust decisions about the same
    // provider. Those can disagree: different audiences, or one entry with a
    // JWKS URL and one without. Boot has to say which one the operator meant.
    let err = problem(
        &config()
            .with_issuer(Issuer::discover(URL, [AUDIENCE]).expect("valid issuer"))
            .with_issuer(Issuer::discover(URL, [AUDIENCE]).expect("valid issuer")),
    );
    assert!(
        err.contains("listed twice") && err.contains(URL),
        "the refusal should name the duplicated issuer: {err}"
    );
}

/// `validate` refuses cleartext on both halves of the trust chain. The message
/// names the flag that would have allowed it.
///
/// Setting that flag narrows cleartext to loopback. It does not switch the
/// transport check off. See
/// [`cleartext_on_a_public_host_stays_refused_when_the_flag_is_set`].
#[test]
fn cleartext_is_refused_unless_it_is_explicitly_allowed() {
    let http_issuer = AuthConfig::empty().with_issuer(
        Issuer::discover("http://identity.example", [AUDIENCE]).expect("valid issuer"),
    );

    let err = problem(&http_issuer);
    assert!(err.contains("requires https"), "{err}");
    assert!(
        err.contains("allow_insecure_http") && err.contains("http://identity.example"),
        "the refusal should name both the setting and the issuer: {err}"
    );

    // Same decision, taken once, applied to the key endpoint as well.
    let keys = url::Url::parse("http://identity.example/jwks.json").expect("parse a JWKS URL");
    let http_keys = AuthConfig::empty()
        .with_issuer(Issuer::with_jwks_url(URL, keys, [AUDIENCE]).expect("valid issuer"));

    let err = problem(&http_keys);
    assert!(err.contains("JWKS URL") && err.contains("https"), "{err}");

    // Setting the flag by name admits a stub issuer on this machine, which is
    // the use the flag exists for.
    loopback_config()
        .with_insecure_http(true)
        .validate()
        .expect("loopback http is allowed once asked for");
}

/// `allow_insecure_http` cannot name a host that answers for the trust anchors
/// in cleartext.
///
/// The flag used to be a global "distrust the transport" switch. Once it was
/// set, `http://identity.example` passed, and `https_only` in `src/http.rs`
/// turned off for the whole client. A service could set the flag for a loopback
/// stub in a test and ship that. Whoever sat on the path to that host then
/// picked the keys that decide who authenticates. The flag now relaxes the
/// transport and nothing else.
#[test]
fn cleartext_on_a_public_host_stays_refused_when_the_flag_is_set() {
    let err = problem(
        &AuthConfig::empty()
            .with_issuer(
                Issuer::discover("http://identity.example", [AUDIENCE]).expect("valid issuer"),
            )
            .with_insecure_http(true),
    );
    assert!(
        err.contains("not loopback") && err.contains("http://identity.example"),
        "the refusal should name the host and the limit: {err}"
    );
    assert!(
        err.contains("allow_insecure_http"),
        "the refusal should name the flag the operator set: {err}"
    );
    // The refusal still names the flag. The operator set it, and a message that
    // blames the scheme alone would send them looking for a typo.

    // The same limit covers the key endpoint on its own. An issuer that
    // publishes a cleartext `jwks_uri` off-box fails too.
    let keys = url::Url::parse("http://keys.example/jwks.json").expect("parse a JWKS URL");
    let err = problem(
        &AuthConfig::empty()
            .with_issuer(Issuer::with_jwks_url(URL, keys, [AUDIENCE]).expect("valid issuer"))
            .with_insecure_http(true),
    );
    assert!(
        err.contains("JWKS URL") && err.contains("not loopback"),
        "the refusal should name the key endpoint: {err}"
    );

    // A name that merely *looks* local is not loopback. `localhost.evil.example`
    // resolves wherever its DNS says it does.
    for host in [
        "localhost.evil.example",
        "127.0.0.1.evil.example",
        "evil.example",
    ] {
        let err = problem(
            &AuthConfig::empty()
                .with_issuer(
                    Issuer::discover(format!("http://{host}/realms/demo"), [AUDIENCE])
                        .expect("valid issuer"),
                )
                .with_insecure_http(true),
        );
        assert!(
            err.contains("not loopback"),
            "{host} is not loopback, so the config must be refused: {err}"
        );
    }
}

/// Every spelling of "this machine" that a stub issuer is bound to in practice
/// stays admissible, so the host test costs loopback tests nothing.
#[test]
fn cleartext_is_allowed_for_every_loopback_spelling() {
    for iss in [
        "http://127.0.0.1:43117/realms/demo",
        // The whole of `127.0.0.0/8` is loopback, not just `127.0.0.1`.
        "http://127.5.9.1:43117/realms/demo",
        "http://localhost:43117/realms/demo",
        "http://LOCALHOST:43117/realms/demo",
        "http://demo.localhost:43117/realms/demo",
        "http://[::1]:43117/realms/demo",
    ] {
        let config = AuthConfig::empty()
            .with_issuer(Issuer::discover(iss, [AUDIENCE]).expect("valid issuer"))
            .with_insecure_http(true);

        config
            .validate()
            .unwrap_or_else(|err| panic!("{iss} is loopback and must validate: {err}"));
    }

    // Setting the flag does not put the other rules to sleep. A config with no
    // issuer is still refused.
    let err = problem(&AuthConfig::empty().with_insecure_http(true));
    assert!(
        err.contains("no trusted issuers"),
        "an empty issuer list is still refused: {err}"
    );
}

/// `validate` refuses a URL with no host for its own reason, not for a host it
/// does not have.
///
/// `Issuer` does not look at the scheme, so a `file` URL reaches `validate`.
/// `is_loopback` answers `false` for a missing host, and the refusal has to
/// match that shape rather than blame a host that is not there.
#[test]
fn a_url_with_no_host_is_not_loopback() {
    let hostless = || {
        AuthConfig::empty().with_issuer(
            Issuer::discover("file:///var/lib/oidc/jwks.json", [AUDIENCE]).expect("valid issuer"),
        )
    };

    let err = problem(&hostless().with_insecure_http(true));
    assert!(
        err.contains("names no host") && err.contains("file"),
        "the refusal should say the URL names no host: {err}"
    );
    assert!(
        !err.contains("not loopback"),
        "the message should not blame a host this URL does not have: {err}"
    );
    assert!(
        err.contains("allow_insecure_http"),
        "the refusal should name the flag the operator set: {err}"
    );

    // With the flag off, the https rule answers first. For a `file` URL that
    // is the true reason, and the shorter one to read.
    let err = problem(&hostless());
    assert!(err.contains("requires https"), "{err}");
}

/// A loopback stub issuer with both halves cleartext, as a test harness builds
/// it: `iss` and `jwks_uri` on `127.0.0.1`.
fn loopback_config() -> AuthConfig {
    let keys =
        url::Url::parse("http://127.0.0.1:43117/realms/demo/jwks.json").expect("parse a JWKS URL");
    AuthConfig::empty().with_issuer(
        Issuer::with_jwks_url("http://127.0.0.1:43117/realms/demo", keys, [AUDIENCE])
            .expect("valid issuer"),
    )
}

#[test]
fn an_issuer_configured_with_an_empty_audience_is_refused() {
    // `Issuer::discover(URL, [""])` names a blank audience. No token ever
    // carries one, so every caller of that issuer is locked out by a setting
    // that reads as though it permitted something.
    let err = problem(&config().with_issuer(Issuer::discover(URL, [""]).expect("valid issuer")));
    assert!(
        err.contains("configured with an empty audience") && err.contains(URL),
        "the refusal should name the issuer whose audience is blank: {err}"
    );
}

/// Every problem is reported at once, rather than the first one found.
///
/// A config file with three mistakes should take one edit-and-restart cycle
/// to fix, not three. On a deployment where the process dies at boot, each
/// cycle is an outage window.
#[test]
fn validate_reports_every_problem_at_once() {
    let err = problem(
        &AuthConfig::empty()
            .with_issuer(
                Issuer::discover("http://identity.example", [AUDIENCE]).expect("valid issuer"),
            )
            .with_algorithms([])
            // One issuer, two problems: the audience it named is blank, and so
            // is the client it named. An empty *set* would be a third, but the
            // constructor refuses that one before `validate` ever sees it, so
            // this is the audience problem `validate` still owns.
            .with_issuer(
                Issuer::discover(URL, [""])
                    .expect("valid issuer")
                    .authorized_party(String::new()),
            ),
    );

    for expected in [
        "no allowed signature algorithms",
        "empty authorised party",
        "requires https",
        "configured with an empty audience",
    ] {
        assert!(err.contains(expected), "missing `{expected}` from: {err}");
    }
    assert!(
        err.split(';').count() >= 4,
        "the problems should be listed, not just the first one: {err}"
    );
}

// ── The defaults ─────────────────────────────────────────────────────────────

/// `Default` and `empty()` are the same config, so a caller that reaches for
/// `..Default::default()` cannot get a different starting point than the one
/// the docs describe.
#[test]
fn the_default_config_is_the_empty_config() {
    let default = AuthConfig::default();

    assert!(default.issuers.is_empty(), "nothing is trusted by default");
    assert!(
        default.all_audiences().is_empty(),
        "no audience is servable by default"
    );
    assert!(default.all_authorized_parties().is_empty());
    assert_eq!(default.leeway, 30);
    assert!(!default.allow_insecure_http);

    // `empty()` carries a usable policy, so a config built from the default
    // does not fail validation because of a field the caller never mentioned.
    let err = problem(&default);
    assert!(!err.contains("timeout"), "{err}");
    assert!(!err.contains("min_fetch_gap"), "{err}");
}
