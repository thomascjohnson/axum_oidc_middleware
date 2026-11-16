//! Errors from authentication, and how they render as HTTP responses.
//!
//! The client-facing rendering follows [RFC 6750 §3][rfc]: a rejected request
//! gets a `401` with a `WWW-Authenticate` header naming the failure, so an
//! OAuth client can tell "your token is no good" from "try again later".
//!
//! A failure of *our* dependency on the identity provider is deliberately
//! **not** a `401`: returning `401` for a Keycloak outage tells the client to
//! throw away a perfectly good token and log the user out. Those become `503`.
//!
//! [rfc]: https://datatracker.ietf.org/doc/html/rfc6750#section-3

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Why a request was not authenticated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// No `Authorization` header at all.
    #[error("missing bearer token")]
    MissingToken,

    /// An `Authorization` header that is not `Bearer` (e.g. `Basic`, or a bare
    /// token with no scheme).
    #[error("authorization header is not a bearer token")]
    NotBearer,

    /// The token was well-formed but is not trusted: bad signature, unknown or
    /// mismatched `iss`, missing or mismatched `aud`, expired, unknown `kid`,
    /// or a disallowed `alg`.
    ///
    /// The payload is a short, safe reason. It never contains the token itself
    /// and never contains key material.
    #[error("invalid token: {0}")]
    InvalidToken(String),

    /// The identity provider could not be consulted, or has no usable keys.
    /// The token may well be valid. This is our problem, not the caller's.
    #[error("identity provider unavailable: {0}")]
    ProviderUnavailable(String),

    /// Authentication is misconfigured. This surfaces at startup from
    /// [`Authenticator::start`](crate::Authenticator::start). Reaching it in a
    /// handler means the process started without a working configuration.
    #[error("authentication is misconfigured: {0}")]
    Configuration(String),
}

impl AuthError {
    /// The RFC 6750 `error` code for this failure, when it has one.
    fn rfc6750_code(&self) -> Option<&'static str> {
        match self {
            // The request itself was malformed: no usable credentials sent.
            Self::MissingToken | Self::NotBearer => Some("invalid_request"),
            Self::InvalidToken(_) => Some("invalid_token"),
            // A 503 is not an OAuth error, and RFC 6750 has no code for "our
            // identity provider is down". A `WWW-Authenticate` there would
            // invite the client to refresh a token that does not need
            // refreshing.
            Self::ProviderUnavailable(_) | Self::Configuration(_) => None,
        }
    }

    /// `true` when the caller should retry the same request unchanged, because
    /// nothing about their credentials is wrong.
    pub fn retryable(&self) -> bool {
        matches!(self, Self::ProviderUnavailable(_))
    }
}

/// Ceiling on a rendered `error_description`, in characters.
///
/// `WWW-Authenticate` is one header line, and intermediaries bound header
/// size. Nginx and Envoy fail the upstream. Cloudflare answers `431`. The
/// reasons built here interpolate values this crate does not control. The
/// worst of them is read *before* any signature check. Gate 1 of
/// `authenticate` refuses a disallowed `alg` while quoting the header.
/// `jsonwebtoken`'s `Header` carries a flattened `extras` map of arbitrary
/// JSON from that same unsigned header. An unauthenticated client can ask for
/// a response header of any size it likes by sending a disallowed `alg` beside
/// a large unknown parameter.
///
/// So the cap lives here, at the one place a reason becomes a field value, not
/// at each call site. Every current interpolation fits inside it with room to
/// spare. The next interpolation added is bounded because it passes through
/// this function, not because someone remembered to cap it.
pub(crate) const MAX_REASON_CHARS: usize = 256;

/// Sanitise a quoted-string for a `WWW-Authenticate` field value.
///
/// RFC 7235 §2.3 supplies the escaping of `"` and `\`. The filtering is the
/// part that keeps the header alive. It exists because of what `into_response`
/// does with the result: it calls `HeaderValue::from_bytes` and, on failure,
/// falls back to the bare `Bearer error=invalid_token`. That fallback is
/// all-or-nothing, so any single byte this layer cannot put in a field value
/// does not corrupt the reason. It deletes it.
///
/// Two classes of byte can do that, because `HeaderValue` admits only
/// printable ASCII and HTAB:
///
/// - **Control characters**, dropped outright. They cannot survive in a field
///   value under any spelling. No reason worth reading is made of them.
/// - **Non-ASCII**, replaced with `?` rather than dropped. Otherwise an IDN
///   realm, a provider's typographic quotes, or a display name in a non-Latin
///   script would take the whole description with them. A `?` keeps the
///   surrounding text — the path, the realm, the word that mattered — and marks
///   where something was lost. That beats both alternatives: dropping silently
///   welds the neighbouring words together, and keeping the byte loses
///   everything after it.
///
/// Above [`MAX_REASON_CHARS`] the value is truncated with a visible marker.
/// See that constant for why the cap is here rather than at the call sites.
///
/// Percent-encoding was the other candidate and is worse here. RFC 6750
/// defines no decoding for `error_description`, so a client would render
/// literal `%C3%A9` at a user.
fn quote(value: &str) -> String {
    // Budget-sized, not input-sized: `value` can be a 64 KiB attacker string,
    // and this runs on the rejection path of every unauthenticated request.
    let mut out = String::with_capacity(MAX_REASON_CHARS + 18);
    out.push('"');

    // The count is in characters *emitted*, not in characters consumed from
    // the input.
    //
    // Counting the input was a real bug, not a nicety. Control characters are
    // skipped without emitting anything. So an attacker who put
    // `MAX_REASON_CHARS` NULs in front of the payload burned the whole budget
    // on bytes that produce no output. The reason came back as literally
    // `""... [truncated]""`. Any value that reaches here from a token can do
    // this, since `kid`, `iss` and `aud` all do. The operator then gets a 401
    // whose description says nothing about a request they can no longer
    // diagnose at all. Unauthenticated input must not be able to censor the
    // explanation of its own rejection. That explanation is the one thing this
    // string exists to provide.
    let mut emitted = 0usize;
    for ch in value.chars() {
        if emitted >= MAX_REASON_CHARS {
            out.push_str("... [truncated]");
            break;
        }
        if ch.is_ascii_control() {
            // Skipped, and importantly *free*: it consumes no budget. So
            // flooding the input with controls cannot evict real content.
            continue;
        }
        if !ch.is_ascii() {
            // Replaced, never dropped: `kid: "user\u{7cfb}\u{7edf}-admin"` still
            // reads as `user??-admin`. It is not kept as ASCII because `out`
            // goes to `HeaderValue::from_bytes`. That call rejects non-ASCII
            // and takes the entire reason down with it, and with it the status
            // code's own description. Percent-encoding was rejected: RFC 6750
            // defines no decoding for the field, so it would ship bytes nothing
            // downstream can undo.
            out.push('?');
            emitted += 1;
            continue;
        }
        if ch == '"' || ch == '\\' {
            // Costs two of the budget, which errs toward telling the operator
            // less rather than more than they can trust to be the whole string.
            out.push('\\');
            emitted += 1;
        }
        out.push(ch);
        emitted += 1;
    }

    out.push('"');
    out
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::MissingToken | Self::NotBearer | Self::InvalidToken(_) => {
                StatusCode::UNAUTHORIZED
            }
            Self::ProviderUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Log at the boundary so no handler has to remember to. The reason is
        // kept. The token never is.
        match &self {
            Self::ProviderUnavailable(reason) => {
                tracing::warn!(reason, %status, "identity provider unavailable")
            }
            Self::Configuration(reason) => {
                tracing::error!(reason, %status, "authentication misconfigured")
            }
            other => tracing::debug!(reason = %other, %status, "request rejected"),
        }

        let mut response = (status, "").into_response();
        if let Some(code) = self.rfc6750_code() {
            let detail = match &self {
                Self::InvalidToken(reason) => format!(", error_description={}", quote(reason)),
                _ => String::new(),
            };
            // RFC 6750 says the `error` parameter on a response to an
            // unauthenticated request is optional but harmless. It is what
            // makes this debuggable from a client log.
            let value = format!("Bearer error={code}{detail}");
            // A reason is built partly from issuer-supplied text, which can
            // carry non-ASCII (an IDN realm, say). Header values cannot, so
            // degrade to the bare code rather than drop the header by
            // unwrapping or silently sending an invalid response.
            //
            // `unwrap_or`, not `unwrap_or_else`: the fallback is a `static` by
            // construction, so there is nothing to defer. Spelling it as a
            // value keeps the whole decision on lines this suite actually runs.
            // As a closure it was a second, unreachable copy of the same
            // answer. It was unreachable because `quote` emits ASCII only,
            // which `a_quoted_reason_is_always_a_legal_header_value` is the
            // test for.
            let fallback = HeaderValue::from_static("Bearer error=invalid_token");
            let header = HeaderValue::from_bytes(value.as_bytes()).unwrap_or(fallback);
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, header);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `WWW-Authenticate` a response carries, if any.
    fn challenge(error: AuthError) -> Option<String> {
        error
            .into_response()
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .map(|value| value.to_str().expect("ASCII by construction").to_owned())
    }

    // ── Our failure, not the caller's ────────────────────────────────────────

    #[test]
    fn a_provider_outage_is_a_503_and_never_a_challenge() {
        // A 401 here tells the client its token is bad. That is a lie: the
        // token may be perfectly good and Keycloak may simply be down. An
        // OAuth client that believes the 401 throws away a valid token and
        // sends the user through a full re-login. That turns a brief outage
        // into a stampede on the identity provider as it recovers.
        let error = AuthError::ProviderUnavailable("https://sso.example/jwks.json: 503".to_owned());
        assert!(error.retryable(), "the caller should retry unchanged");

        let response = AuthError::ProviderUnavailable("unreachable".to_owned()).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        assert_eq!(
            challenge(error),
            None,
            "a 503 must not carry `WWW-Authenticate`: RFC 6750 has no code for \"our \\
             identity provider is down\", and sending one invites the client to \"
             refresh a token that does not need refreshing"
        );
    }

    #[test]
    fn a_misconfiguration_is_a_500_and_never_a_challenge() {
        // Reaching this in a handler means the process started with a
        // configuration `validate` should have refused. It is the operator's
        // bug, not the caller's. So it must not read as either a bad token
        // (401) or a transient dependency failure (503, retryable).
        let error = AuthError::Configuration("no audience configured".to_owned());
        assert!(
            !error.retryable(),
            "retrying a misconfiguration cannot help"
        );

        let response =
            AuthError::Configuration("no audience configured".to_owned()).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            challenge(error),
            None,
            "a 500 is not an OAuth error and must not pretend to be one"
        );
    }

    // ── The caller's failure ─────────────────────────────────────────────────

    #[test]
    fn every_401_names_its_rfc_6750_code_and_only_a_bad_token_adds_a_description() {
        // The distinction a client acts on: `invalid_request` means fix how
        // you are sending the credential. `invalid_token` means get a new one.
        // Both are `retryable() == false`. Nothing short of different
        // credentials changes the answer.
        let cases = [
            (AuthError::MissingToken, "invalid_request"),
            (AuthError::NotBearer, "invalid_request"),
            (
                AuthError::InvalidToken("expired".to_owned()),
                "invalid_token",
            ),
        ];

        for (error, code) in cases {
            assert!(!error.retryable(), "{error} is not retryable");

            // Asserted before it is read, rather than through
            // `unwrap_or_else`, so there is no `panic!` arm sitting in a test
            // that can only ever walk past it. The name still arrives with the
            // failure.
            let challenge = challenge(error.clone());
            assert!(challenge.is_some(), "a 401 must always challenge: {error}");
            let challenge = challenge.expect("checked above");
            assert!(
                challenge.starts_with(&format!("Bearer error={code}")),
                "{error} should report `{code}`, got: {challenge}"
            );

            let has_description = challenge.contains("error_description");
            assert_eq!(
                has_description,
                matches!(error, AuthError::InvalidToken(_)),
                "only a bad token has a reason to describe: {challenge}"
            );
        }
    }

    #[test]
    fn a_control_character_does_not_cost_the_client_the_whole_reason() {
        // The property under test is *survival*, not escaping. `into_response`
        // builds the challenge with `HeaderValue::from_bytes` and falls back to
        // the bare `Bearer error=invalid_token` when that fails. A CTL makes it
        // fail, so before the filter a single newline did not corrupt the
        // message. It deleted it. Asserting on the rendered header is the only
        // way to see that difference, which is why this does not stop at `quote`.
        let err = AuthError::InvalidToken("signature mismatch\nissuer https://x".to_owned());
        let response = err.into_response();
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("a 401 must always carry a challenge")
            .to_str()
            .expect("the challenge is ASCII by construction after filtering");

        assert!(
            challenge.contains("signature mismatch") && challenge.contains("issuer https://x"),
            "the reason was lost rather than sanitised: {challenge}"
        );
        assert!(
            !challenge.contains('\n') && !challenge.contains('\r'),
            "a CTL in a field value makes `HeaderValue::from_bytes` fail, which \
             silently discards the description: {challenge:?}"
        );
    }

    /// `quote` never emits a byte a header value cannot carry.
    ///
    /// This is the invariant `into_response` rests on. That code builds
    /// `Bearer error=<code>[, error_description=<quoted>]` and calls
    /// `HeaderValue::from_bytes`. If the value is rejected, it falls back to
    /// the bare code. That fallback is unreachable while `quote` emits ASCII
    /// only, since the `Bearer error=` prefix and every `rfc6750_code` are
    /// ASCII already. So the fallback is not tested, because it cannot be
    /// reached. *This* is tested, because it is the reason. Should a future
    /// edit let one non-ASCII byte through, the failure lands here. It reads as
    /// "the description was silently dropped from a client's 401". It does not
    /// land in the response path, where it would look like nothing at all.
    ///
    /// The first case is the whole Latin-1 block in one string. It is worth the
    /// bulk because it is exactly where `is_ascii()` stops protecting you.
    /// U+0080 ..U+00FF holds the C1 controls, which `is_ascii_control` does not
    /// cover the same way the C0 range is covered. It also holds the accented
    /// letters an IDN realm would actually contain.
    #[test]
    fn a_quoted_reason_is_always_a_legal_header_value() {
        let latin1: String = (0u8..=0xff).map(char::from).collect();

        for reason in [
            latin1.as_str(),
            "",
            "https://⚡.example/realms/démo",
            "user\u{7cfb}\u{7edf}-admin",
            "\u{1f600} emoji and CJK",
            "\r\n set-cookie: session=abc\u{0}\u{1b}[31m",
            r#"a "_quote" and a \ backslash"#,
            &"x".repeat(MAX_REASON_CHARS * 3),
        ] {
            let quoted = quote(reason);
            assert!(
                quoted.is_ascii(),
                "`quote` emitted a non-ASCII byte, which would take the whole \
                 `WWW-Authenticate` header with it: {reason:?} -> {quoted:?}"
            );

            // The exact expression `into_response` builds, so this tests the
            // composition and not just the helper.
            let value = format!("Bearer error=invalid_token, error_description={quoted}");
            assert!(
                HeaderValue::from_bytes(value.as_bytes()).is_ok(),
                "this value would be rejected by `from_bytes`, so the client would \
                 get the bare code and lose the reason: {value:?}"
            );
        }
    }

    #[test]
    fn quotes_and_backslashes_are_still_escaped() {
        // The pre-existing half of `quote`, pinned so the CTL filter cannot be
        // the only thing a future edit remembers.
        let quoted = quote(r#"he said "no" \ done"#);
        assert_eq!(quoted, r#""he said \"no\" \\ done""#);
    }

    #[test]
    fn every_ascii_control_character_is_dropped() {
        // Not just `\n` and `\r`: `HeaderValue` rejects the whole C0 range and
        // DEL, so any one of them would take the header with it. Tab is
        // included. RFC 7230 forbids it inside a field value too.
        for code in 0u8..=0x1f {
            let dirty = format!("before{}after", code as char);
            let clean = quote(&dirty);
            assert!(
                !clean.contains(char::from(code)),
                "U+{code:02X} survived the filter: {clean:?}"
            );
            assert!(
                clean.contains("before") && clean.contains("after"),
                "the readable part must be kept: {clean:?}"
            );
        }
        assert!(!quote("a\u{7f}b").contains('\u{7f}'));
    }

    #[test]
    fn non_ascii_survives_as_a_marker_instead_of_taking_the_reason_with_it() {
        // The case that used to be a silent total loss. An IDN realm is legal
        // in an issuer URL and a provider's `error_description` routinely
        // carries typographic quotes. Both are non-ASCII, both made
        // `from_bytes` fail, and the fallback is the bare code with no
        // description at all.
        let err = AuthError::InvalidToken("realm caf\u{e9}/api \u{201c}expired\u{201d}".to_owned());
        let response = err.into_response();
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("a 401 must always carry a challenge")
            .to_str()
            .expect("sanitised to ASCII")
            .to_owned();

        assert!(
            challenge.contains("api"),
            "the ASCII around the non-ASCII must be kept, not discarded with it: \
             {challenge}"
        );
        assert!(
            challenge.contains("expired"),
            "the word the caller needs: {challenge}"
        );
        assert!(
            challenge.contains("caf?") && challenge.contains("?expired"),
            "the loss should be visible in place, not welded shut: {challenge}"
        );
        assert!(
            challenge.is_ascii(),
            "a non-ASCII byte makes `from_bytes` fail and the whole description \
             is replaced by the bare code: {challenge:?}"
        );
    }

    #[test]
    fn an_unbounded_reason_is_truncated_not_forwarded_whole() {
        // The unauthenticated vector, and the reason the cap is central rather
        // than per-call-site. Gate 1 quotes the JWS header of a token that has
        // not been verified, and `Header.extras` is arbitrary JSON from that
        // same unsigned header. So a client sends `alg: HS256` next to a large
        // unknown parameter and the response header grows to whatever size it
        // asked for. Intermediaries fail upstream long before 64 KiB.
        let padded = format!("alg={{\"x\":\"{}\"}}", "a".repeat(64 * 1024));
        let response = AuthError::InvalidToken(padded).into_response();
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .expect("a 401 must always carry a challenge")
            .to_str()
            .expect("sanitised to ASCII")
            .to_owned();

        assert!(
            challenge.len() < 1_024,
            "a 64 KiB reason produced a {} byte response header",
            challenge.len()
        );
        assert!(
            challenge.contains("truncated"),
            "the truncation has to be visible, or a reader chases a message that \
             looks complete: {challenge}"
        );
    }

    #[test]
    fn leading_control_characters_cannot_censor_the_reason() {
        // The regression this exists for: a budget counted against the *input*
        // let unauthenticated bytes delete the operator's explanation entirely.
        let masked = format!("{}tenant mismatch on acme", "\0".repeat(MAX_REASON_CHARS));
        let quoted = quote(&masked);
        assert!(
            quoted.contains("tenant mismatch on acme"),
            "NULs must not evict real content, got {quoted}"
        );
        assert!(
            !quoted.contains("truncated"),
            "nothing here is over budget: {quoted}"
        );
    }

    #[test]
    fn the_emitted_budget_bounds_the_header_it_feeds() {
        // Multi-byte input is measured in code points and rendered as `?`. So
        // the cap is the character bound, and, because every emitted byte is
        // ASCII, the byte bound the header needs. Asserted rather than assumed:
        // the earlier version of this test only checked `from_utf8`. The
        // ASCII-only replacement made that unconditionally true, so it proved
        // nothing.
        let wide = "\u{7cfb}".repeat(MAX_REASON_CHARS * 2);
        let quoted = quote(&wide);
        let body = &quoted[1..quoted.len() - "... [truncated]\"".len()];
        assert_eq!(
            body.chars().count(),
            MAX_REASON_CHARS,
            "budget must be exact"
        );
        assert!(
            body.bytes().all(|byte| byte.is_ascii()),
            "must be header-safe: {quoted}"
        );
        assert!(
            quoted.ends_with("... [truncated]\""),
            "must say so: {quoted}"
        );
        assert!(
            HeaderValue::from_bytes(quoted.as_bytes()).is_ok(),
            "a reason that cannot become a header reports nothing at all"
        );
    }

    #[test]
    fn a_short_reason_survives_unescaped_apart_from_the_sanitising() {
        // Raw string, because the value under test is itself quoted and
        // escaped. A second layer of `\"` in a normal literal stops being
        // readable.
        let quoted = quote("bad kid \"k\u{00e9}\"");
        assert_eq!(quoted, r#""bad kid \"k?\"""#);
    }

    #[test]
    fn ordinary_text_is_untouched() {
        assert_eq!(quote("a b c!d/e"), "\"a b c!d/e\"");
    }
}
