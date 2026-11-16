//! Axum integration: read the bearer token, verify it, hand the claims to a
//! handler.

use axum::extract::{FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::claims::Claims;
use crate::error::AuthError;
use crate::validator::Authenticator;

/// Extract the credential from an `Authorization` header.
///
/// The code matches the scheme case-insensitively, because RFC 7235 §2.1 says
/// the scheme is case-insensitive. It does not alter the token.
///
/// The error variants carry a distinction the middlewares depend on:
/// [`AuthError::MissingToken`] means *no header at all*, which an optional
/// route may serve anonymously. Every other rejection means a credential was
/// offered, and must not be read as absence. The rejections are: a foreign
/// scheme, a `Bearer` with nothing after it, a value holding two tokens, and a
/// non-UTF-8 header.
fn bearer(headers: &HeaderMap) -> Result<&str, AuthError> {
    let raw = headers
        .get(AUTHORIZATION)
        .ok_or(AuthError::MissingToken)?
        .to_str()
        .map_err(|_| AuthError::NotBearer)?;

    // Whitespace separates the scheme and the credential, and which whitespace
    // varies by transport. RFC 7235 §2.1 spells the separator `1*SP`. But RFC
    // 7230 admits HTAB as blank-within-a-field, the h2 codec does not normalise
    // what it hands over, and intermediaries fold one into the other. Splitting
    // on U+0020 alone made `Bearer\t<token>` a single unrecognised scheme. The
    // code then refused a credential that verifies perfectly with "not a bearer
    // token" — a stated reason that is simply false.
    //
    // Accepting HTAB widens nothing that matters: the credential still has to
    // carry a signature from a trusted key. What it removes is a rejection that
    // misdescribes itself.
    let mut parts = raw
        .trim_start_matches(|c: char| c.is_ascii_whitespace())
        .splitn(2, |c: char| c.is_ascii_whitespace());
    let scheme = parts.next().unwrap_or_default();

    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(AuthError::NotBearer);
    }

    // Whitespace at either end of the credential is framing, and none of it is
    // part of the credential. HTTP/1.1 field values arrive stripped of optional
    // whitespace because `httparse` removes it. The h2 codec hands the field
    // line over as received, so a valid token reaches this as `abc `. The same
    // is true on the leading side once the split is on whitespace-in-general:
    // `Bearer  <token>` yields ` <token`. Trimming one end and not the other
    // makes `Bearer abc ` succeed while `Bearer  abc` fails. That is a worse
    // outcome than either policy applied evenly.
    //
    // Whitespace *inside* the credential stays malformed. A JWT is three
    // base64url segments and two dots, so no whitespace is ever part of one. An
    // interior space or tab means a folded or doubled header. No framing rule
    // accounts for that, and it must never be read as one credential.
    match parts.next() {
        Some(part) => {
            let token = part.trim_matches(|c: char| c.is_ascii_whitespace());
            if token.is_empty() || token.chars().any(|c| c.is_ascii_whitespace()) {
                Err(AuthError::NotBearer)
            } else {
                Ok(token)
            }
        }
        None => Err(AuthError::NotBearer),
    }
}

/// Verify the bearer credential in `headers`, if the request carries one.
///
/// This is the single place where both middlewares do their work, so the two
/// can never disagree about what a token means. `Ok(None)` means *only* "there
/// was no `Authorization` header at all", which is the one unauthenticated
/// case a route may choose to serve.
///
/// A header that is present and unusable is an `Err`, never `Ok(None)`.
/// `bearer` reports [`AuthError::MissingToken`] exactly when the header is
/// absent, and every other defect arrives as a different variant and
/// propagates. The defects are: foreign scheme, no token after `Bearer`, two
/// values in one header, and a failed verification. Returning `Ok(None)` there
/// would turn a client's broken credential into a silent downgrade to the
/// anonymous code path.
async fn verify(auth: &Authenticator, headers: &HeaderMap) -> Result<Option<Claims>, AuthError> {
    let token = match bearer(headers) {
        Ok(token) => token,
        Err(AuthError::MissingToken) => return Ok(None),
        Err(err) => return Err(err),
    };

    let claims = auth.authenticate(token).await?;

    tracing::trace!(
        subject = %claims.log_id(),
        aud = ?claims.aud,
        exp = claims.exp,
        "authenticated"
    );

    Ok(Some(claims))
}

/// Axum middleware that requires a valid bearer token.
///
/// On success the verified [`Claims`] are stored in the request extensions for
/// [`AuthUser`] to pick up. On failure the request never reaches the handler:
/// the [`AuthError`] converts itself into a `401` or `503` with
/// `WWW-Authenticate`, per `error` module docs.
///
/// Use it when every route under the layer takes [`AuthUser`]. Where a route
/// must also serve anonymous callers, use [`optional_auth`] and mark the routes
/// that still need a caller by taking [`AuthUser`]. The extractor answers the
/// same `401` for a request the middleware let through anonymously.
///
/// Layer it on a sub-router holding only the protected routes, then merge.
/// `route_layer` guards every route already registered on *that* router. So
/// applying it to a router that also has `/healthz` or `/doc` locks those too:
///
/// ```no_run
/// use axum::{middleware, routing::{get, post}, Router};
/// use axum_oidc_middleware::require_auth;
///
/// # async fn example(auth: axum_oidc_middleware::Authenticator) -> Router {
/// Router::new()
///     .route("/healthz", get(health))          // public: outside the layer
///     .merge(
///         Router::new()
///             .route("/hello", post(hello))
///             .route_layer(middleware::from_fn_with_state(auth, require_auth)),
///     )
/// # }
/// # async fn health() -> &'static str { "ok" }
/// # async fn hello(user: axum_oidc_middleware::AuthUser) -> String { user.0.sub }
/// ```
pub async fn require_auth(
    State(auth): State<Authenticator>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let claims = verify(&auth, request.headers())
        .await?
        // The route demanded a caller and there was no header to make one
        // from. This is the same rejection `bearer` would have raised.
        .ok_or(AuthError::MissingToken)?;

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// Axum middleware that verifies a bearer token *when there is one*.
///
/// The complement of [`require_auth`], for a router where some callers are
/// anonymous and some are not. Three outcomes, and only the first is
/// anonymous:
///
/// - **No `Authorization` header.** The layer inserts nothing, the handler
///   runs, and [`OptionalAuthUser`] yields `None`. This is what makes the
///   middleware optional.
/// - **A valid bearer token.** The layer inserts the verified [`Claims`], and
///   [`OptionalAuthUser`] yields `Some`.
/// - **A token that is present and does not verify.** The crate rejects it
///   exactly as [`require_auth`] does — `401` with a `WWW-Authenticate`
///   `invalid_token`/`invalid_request` challenge, or `503` when the identity
///   provider is unreachable. It never becomes `None`.
///
/// The asymmetry is the whole design: *absent* is optional, *invalid* is not.
/// A caller who sends a credential expects it to count. If the layer quietly
/// treats that caller as anonymous, they see a weaker answer with a `200` on
/// it. Nothing in their client tells them their token stopped working. See
/// `verify` in this module for which defects count as present-but-invalid. In
/// short, anything other than a missing header: a mangled `Authorization:
/// Bearer` and a `Basic` credential are both `401`s.
///
/// ```no_run
/// use axum::{middleware, routing::{get, post}, Router};
/// use axum_oidc_middleware::{AuthUser, OptionalAuthUser, optional_auth};
///
/// # async fn example(auth: axum_oidc_middleware::Authenticator) -> Router {
/// Router::new()
///     // Serves both: attributed when a token is sent, anonymous when not.
///     .route("/hello", post(hello))
///     // Needs a caller whatever the client tried to send.
///     .route("/audit", get(audit))
///     .route_layer(middleware::from_fn_with_state(auth, optional_auth))
/// # }
/// # async fn hello(user: OptionalAuthUser) -> String {
/// #     user.0.map(|c| c.sub).unwrap_or_else(|| "anonymous".to_owned())
/// # }
/// # async fn audit(user: AuthUser) -> String { user.0.sub }
/// ```
pub async fn optional_auth(
    State(auth): State<Authenticator>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    // `?`, not a match on the error: a bad token aborts here with the same
    // rejection `require_auth` would have produced.
    let claims = verify(&auth, request.headers()).await?;

    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }

    Ok(next.run(request).await)
}

/// A verified caller. Rejects the request when there are no claims.
///
/// Take this on every route that must not run anonymously. Behind
/// [`require_auth`] it is a statement of intent: the middleware already
/// rejected anything without a good token. Behind [`optional_auth`] it is the
/// per-route switch: an anonymous request is stopped here, with the same `401`
/// and challenge, while [`OptionalAuthUser`] routes keep serving it.
#[derive(Debug, Clone)]
pub struct AuthUser(pub Claims);

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(claims) = parts.extensions.get::<Claims>().cloned() {
            return Ok(AuthUser(claims));
        }

        // `debug!`, not the `warn!` that "a route taking `AuthUser` has no
        // auth layer in front of it" genuinely deserves. That is a real
        // misconfiguration and worth surfacing. The trouble is that the two
        // cases look the same from in here. A missing extension means one of
        // two things. Either the layer was never applied, or `optional_auth`
        // correctly let an anonymous request reach a route that then demanded a
        // caller. The second is ordinary, expected traffic, and the client
        // starts it. So a `warn!` here is one unbounded log line per request for
        // anyone who can open a socket. This is the same reasoning that keeps
        // `validator`'s unusable-`kid` log at debug. The `401` this returns
        // already carries the reason to the caller. That is the half someone has
        // to act on.
        tracing::debug!(
            path = %parts.uri.path(),
            "AuthUser requested with no verified claims in scope"
        );
        Err(AuthError::MissingToken)
    }
}

/// The caller, if this request brought one.
///
/// For routes that behave differently for anonymous callers. Pair it with
/// [`optional_auth`], which owns both halves of the contract:
///
/// - **absent** — no `Authorization` header, so nothing was inserted and this
///   yields `None`. That is the case the route is expected to serve.
/// - **present and valid** — [`Claims`] are inserted and this yields `Some`.
/// - **present and invalid** — the middleware answered `401` and the handler
///   never ran, so this never sees a bad token. Ignoring one instead would let
///   a client silently fall through to the weaker code path.
///
/// This extractor never rejects. It only reports what arrived. Deciding whether
/// an anonymous caller may proceed is the route's job. Behind
/// [`require_auth`] every request has claims, so this is always `Some` there.
/// For an optional route on a server that requires a token everywhere, take
/// [`AuthUser`] instead and let it say `401`.
#[derive(Debug, Clone)]
pub struct OptionalAuthUser(pub Option<Claims>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.extensions.get::<Claims>().cloned()))
    }
}

/// The `Authorization` header value to attach to a request, for tests and
/// clients that need to build one by hand.
pub fn authorization(token: &str) -> HeaderValue {
    HeaderValue::from_maybe_shared(format!("Bearer {token}"))
        // `Bearer ` plus a token is ASCII by construction from `&str`. A caller
        // could smuggle non-UTF-8 through the ownership path of
        // `from_maybe_shared`, but not through this path.
        .expect("an ASCII bearer header is always a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bearer` is private, and the distinction it makes decides behaviour two
    /// levels up: `verify` reads `MissingToken` as "serve anonymously" and
    /// every other variant as "reject". So the tests call it here rather than
    /// through a router.
    ///
    /// A router cannot reach the case that matters. Over HTTP/1.1 `httparse`
    /// strips optional whitespace from a field value before this code sees it.
    /// So a token sent with a trailing space arrives already trimmed, and the
    /// test passes with or without the fix. The h2 codec does not trim, which
    /// is the entire reason the trim exists. Driving a real server would
    /// therefore prove nothing. Calling `bearer` with the value h2 would
    /// deliver is the only non-vacuous way to cover it.
    fn authorized(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(value).expect("a legal header value"),
        );
        headers
    }

    #[test]
    fn a_token_with_trailing_whitespace_is_still_a_token() {
        // What hyper's h2 codec hands over for `Authorization: Bearer abc `.
        // Rejecting this is a `401` against a perfectly good credential. It
        // only bites once a client stops using HTTP/1.1.
        let headers = authorized("Bearer abc ");
        let token = bearer(&headers).expect("a valid token, framed loosely");
        assert_eq!(
            token, "abc",
            "the framing is trimmed, the token is not: {token}"
        );
    }

    #[test]
    fn a_token_with_trailing_tab_or_newline_run_is_still_a_token() {
        // `is_ascii_whitespace`, not "a space": h2 field lines can carry any
        // of these and none of them is part of a credential.
        for raw in ["Bearer abc\t", "Bearer abc \u{20} "] {
            let headers = authorized(raw);
            // One assertion over the whole `Result`, so there is no `panic!`
            // arm for the happy path to walk past. A refusal still arrives as
            // `Err(..)` with the `AuthError` intact, which is the half that
            // tells an operator what `bearer` actually objected to.
            assert_eq!(
                bearer(&headers).as_deref(),
                Ok("abc"),
                "`{raw}` should yield the bare token"
            );
        }
    }

    #[test]
    fn no_header_is_absence_rather_than_a_malformed_credential() {
        // The one case `optional_auth` may serve anonymously. Everything else
        // a client manages to send is a credential it offered, and must be a
        // rejection rather than a silent downgrade.
        let headers = HeaderMap::new();
        assert!(matches!(bearer(&headers), Err(AuthError::MissingToken)));
    }

    #[test]
    fn a_foreign_scheme_is_not_an_absent_credential() {
        let headers = authorized("Basic dXNlcjpwYXNz");
        assert!(matches!(bearer(&headers), Err(AuthError::NotBearer)));
    }

    #[test]
    fn whitespace_inside_a_token_is_refused_whatever_it_is() {
        // The gap a `contains(' ')` guard left open, and the half of the fix
        // that is a genuine refusal. `splitn` breaks on U+0020 only. So a tab
        // inside the credential rode straight through into the decoder, where
        // it surfaced as a base64 failure pointing at the caller's signature.
        // A JWT is base64url and dots, so no whitespace is ever part of one and
        // there is nothing to be lenient about here.
        //
        // Vertical tab and form feed are deliberately absent: `HeaderValue`
        // rejects every CTL but HTAB at its own construction, so those never
        // reach this function. Tab is the reachable non-space case, and the one
        // the `contains(' ')` guard missed.
        for raw in ["Bearer abc\tdef", "Bearer a b c", "Bearer abc\tdef\tghi"] {
            let headers = authorized(raw);
            assert!(
                matches!(bearer(&headers), Err(AuthError::NotBearer)),
                "`{raw:?}` has whitespace inside the credential and must be
                 refused at the boundary, not handed to the decoder"
            );
        }
    }

    #[test]
    fn a_whitespace_only_credential_is_absence_of_token_not_a_token() {
        // `Bearer ` with nothing usable after it. Returning `MissingToken`
        // here would let a client that dropped its token mid-flight slip into
        // the anonymous path. `NotBearer` keeps it a rejection.
        for raw in ["Bearer ", "Bearer  ", "Bearer \t", "Bearer \t \t"] {
            let headers = authorized(raw);
            assert!(
                matches!(bearer(&headers), Err(AuthError::NotBearer)),
                "`{raw:?}` offered a credential and failed to supply one"
            );
        }
    }

    #[test]
    fn a_token_padded_on_either_end_is_still_a_token() {
        // `trim_matches`, not `trim_end_matches`. Framing whitespace is
        // framing whichever end it sits on. The h2 case that motivated the trim
        // has a leading twin. `splitn` splits on U+0020 alone, so
        // `Bearer \tabc` arrives as `\tabc` with no literal space anywhere in
        // it. Under the old guard that was accepted *with the tab attached*.
        // Making the interior rule about whitespace in general is what lets the
        // code trim both ends, instead of mangling one.
        //
        // The reviewer proposed refusing this case. Trimming it is the
        // consistent call, since it is the same defect as the trailing one
        // that is deliberately honoured. Refusing leading framing while
        // accepting trailing would mean `Bearer  abc ` fails but
        // `Bearer abc ` works.
        for raw in [
            "Bearer  abc",
            "Bearer abc ",
            "Bearer  abc  ",
            "Bearer \tabc",
            "Bearer abc\t",
        ] {
            let headers = authorized(raw);
            // As above: one assertion, no never-taken `panic!` arm.
            assert_eq!(
                bearer(&headers).as_deref(),
                Ok("abc"),
                "`{raw:?}` should yield the bare token"
            );
        }
    }

    #[test]
    fn a_tab_as_the_only_separator_is_still_a_bearer_credential() {
        // RFC 7235 spells the separator `1*SP`, so refusing this is defensible
        // on a strict reading. But RFC 7230 admits HTAB as blank within a field,
        // and h2 does not normalise it. The refusal that resulted said "not a
        // bearer token" about a token that is one and verifies. A wrong reason
        // is the actual defect here. Accepting costs nothing, since the
        // signature still has to hold.
        for raw in ["Bearer\tabc", "Bearer\t\tabc"] {
            let headers = authorized(raw);
            // As above.
            assert_eq!(
                bearer(&headers).as_deref(),
                Ok("abc"),
                "`{raw:?}` is a bearer credential"
            );
        }
    }

    #[test]
    fn the_scheme_is_matched_case_insensitively() {
        // RFC 7235 §2.1. The token is returned untouched either way.
        for raw in ["bearer abc", "BEARER abc", "BeArEr abc"] {
            let headers = authorized(raw);
            // As above. The scheme's case must not reach the token either way.
            assert_eq!(
                bearer(&headers).as_deref(),
                Ok("abc"),
                "`{raw}` should yield the bare token whatever the scheme's case"
            );
        }
    }

    /// The whole separator matrix, as one table.
    ///
    /// RFC 7230 allows SP or HTAB as `OWS` and says a recipient SHOULD reject
    /// whitespace *inside* a field value. RFC 7519 §2.1 fixes the grammar as
    /// `scheme 1*SP b64token`, which admits no second separator at all. The two
    /// pull opposite ways, so the ruling applied by `bearer` is stated once and
    /// pinned here:
    ///
    /// - Whitespace at either end of the credential is framing from a proxy or
    ///   a hand-written curl. It gets trimmed.
    /// - Whitespace inside the credential means the value is not one token.
    /// - A scheme that is not `Bearer` is refused rather than guessed at.
    ///
    /// CR and LF are absent from both lists deliberately. They cannot reach
    /// this function: the `http` crate rejects them when the `HeaderValue` is
    /// built. That is header-injection defence happening one layer down. It is
    /// worth knowing that this is *not* this function's job, before someone
    /// adds a CR case here and wonders why it never runs.
    #[test]
    fn separators_between_scheme_and_credential_are_ruled_not_guessed() {
        let accepted: &[&str] = &[
            "Bearer abc",
            "Bearer  abc",
            "Bearer \t abc",
            "Bearer\tabc",
            "Bearer\t\tabc",
            "bearer abc",
            "  Bearer abc  ",
        ];
        let refused: &[&str] = &[
            "Bearer",
            "Bearer ",
            "Bearer\t",
            "Bearer a b",
            "Basic abc",
            "bearer",
            "\t",
            " ",
            "",
        ];

        for raw in accepted {
            let headers = authorized(raw);
            assert_eq!(
                bearer(&headers).as_deref(),
                Ok("abc"),
                "should accept {raw:?}"
            );
        }
        for raw in refused {
            let headers = authorized(raw);
            assert!(
                matches!(bearer(&headers), Err(AuthError::NotBearer)),
                "should refuse {raw:?}, got {:?}",
                bearer(&headers)
            );
        }
    }
}
