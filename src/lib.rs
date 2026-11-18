// A broken link in user-facing docs is a wrong pointer in the only place a
// caller is looking. Unlike a broken link in a test, nothing fails when one is
// introduced. Four accumulated quietly that way. `warn` is rustdoc's default.
// This attribute makes `cargo doc` fail instead. Downgrade it if it blocks a
// release.
#![deny(rustdoc::broken_intra_doc_links)]
// There is no `unsafe` in this crate today, and nothing here needs any. The
// tempting places are zero-copy JWT parsing and base64 hot paths. That is
// precisely where a memory bug would stop being a crash and start being a
// forged token. `forbid` rather than `deny` so the next contributor cannot
// reopen it locally with an attribute the way `deny` allows.
#![forbid(unsafe_code)]
//! Bearer-token authentication for Axum against one or more OIDC issuers.
//! Google, Keycloak, and Entra ID work, and so does anything else that
//! publishes JWKS.
//!
//! # What this is
//!
//! A **resource server**: it verifies tokens that something else asked for. Your
//! frontend or another service does the redirect dance with Google and sends
//! the result here as `Authorization: Bearer <jwt>`. Nothing in this crate
//! performs a login redirect, holds a session, or issues a cookie. If you need
//! that, this is the wrong layer.
//!
//! # Quick start
//!
//! ```no_run
//! use axum_oidc_middleware::{AuthConfig, AuthUser, Authenticator, Issuer, require_auth};
//! use axum::{middleware, routing::post, Router};
//!
//! # async fn example() -> Result<Router, axum_oidc_middleware::AuthError> {
//! // Each issuer names the audiences its own tokens may carry. There is no
//! // deployment-wide audience list to inherit, and no way to build an issuer
//! // that has not answered the question.
//! let config = AuthConfig::empty().with_issuers([
//!     // Google never makes an `azp` claim, so this issuer names no client. Its
//!     // `azp` gate is off — and off for this issuer alone.
//!     Issuer::discover("https://accounts.google.com", ["myaudience"])?,
//!     // In a stock Keycloak realm, `aud` is "account" for every API, so name
//!     // the client here too. This crate enforces `azp` in addition to the
//!     // audience, never instead of it. Named on the issuer because a client id
//!     // is unique within a realm, not across realms: the `myclient` in this
//!     // realm is not the `myclient` in any other.
//!     Issuer::discover("https://sso.example.com/realms/sagaci", ["myaudience"])?
//!         .authorized_party("myclient")?,
//! ]);
//!
//! // This call fails now if an issuer is unreachable or its keys will not load.
//! let auth = Authenticator::start(config).await?;
//!
//! let app = Router::new()
//!     .route("/hello", post(handler))
//!     // Keep public routes outside this layer.
//!     .route_layer(middleware::from_fn_with_state(auth, require_auth));
//!
//! async fn handler(user: AuthUser) -> String {
//!     format!("hello {}", user.0.log_id())
//! }
//! # Ok(app)
//! # }
//! ```
//!
//! # Runnable examples
//!
//! `cargo run --example protected_api` starts a mock OIDC issuer on loopback,
//! protects a route with [`require_auth`], and sends five requests at it,
//! printing the status and the RFC 6750 challenge for each. Three of them are
//! correctly signed by the issuer's own key and still have to be refused.
//! `cargo run --example optional_auth` does the same for [`optional_auth`]: a
//! route that takes an anonymous caller beside one that refuses it under the
//! same layer. Neither example needs a client ID or a network connection, and
//! CI runs both. `quickstart` is the deployment-shaped server behind
//! `OIDC_ISSUERS` and `OIDC_AUDIENCE`.
//!
//! # Requiring a caller, or allowing one
//!
//! Two middlewares use one verification path ([`require_auth`],
//! [`optional_auth`]). They differ in exactly one thing: what happens when a
//! request arrives with **no `Authorization` header**.
//!
//! ```no_run
//! use axum::{middleware, routing::post, Router};
//! use axum_oidc_middleware::{AuthUser, OptionalAuthUser, optional_auth};
//!
//! # async fn example(auth: axum_oidc_middleware::Authenticator) -> Router {
//! Router::new()
//!     // Attributed when a token is sent, anonymous when none is.
//!     .route("/hello", post(hello))
//!     // This route still needs a caller. The extractor decides this one, not
//!     // the layer.
//!     .route("/audit", post(audit))
//!     .route_layer(middleware::from_fn_with_state(auth, optional_auth))
//! # }
//!
//! // `OptionalAuthUser` reads what the layer left behind: `Some` for a good
//! // token, `None` when there was no header, never a bad one.
//! async fn hello(user: OptionalAuthUser) -> String {
//!     user.0.map(|c| c.log_id()).unwrap_or_else(|| "anonymous".to_owned())
//! }
//!
//! async fn audit(user: AuthUser) -> String {
//!     user.0.log_id()
//! }
//! ```
//!
//! An *absent* token is optional. An *invalid* token is not. `optional_auth`
//! rejects a token that is present and fails verification. It returns the same
//! `401` and `WWW-Authenticate` that `require_auth` gives. It never swallows a
//! bad token into `None`. A client whose token has quietly stopped working
//! would otherwise see the anonymous answer with a `200` on it. That is the
//! downgrade this split exists to prevent. A handler that must not run
//! anonymously says so by taking [`AuthUser`], and the extractor answers it
//! with `401`.
//!
//! So a route has three honest shapes:
//!
//! - [`AuthUser`] behind [`require_auth`]: always attributed.
//! - [`OptionalAuthUser`] behind [`optional_auth`]: both, per request.
//! - Neither, outside every layer: genuinely public. No token is read at all,
//!   and a valid one is discarded.
//!
//! # Effects on the host process
//!
//! One thing here reaches outside your router, and it is worth knowing before
//! you embed this crate in a binary that has its own opinions about TLS.
//!
//! [`Authenticator::start`] installs `ring` as the **process-wide default rustls
//! crypto provider**. `reqwest` is depended on here through `rustls-no-provider`,
//! which selects no crypto backend at all, and `reqwest::Client` panics when
//! nothing is in place by the time it is built. The JWKS request is the first
//! HTTPS request most deployments make, so the crate owns that install rather
//! than leaving a panic for whatever code reaches HTTP next.
//!
//! Two properties make it safe to embed:
//!
//! - **First writer wins, and you are always the first writer.** The install is
//!   idempotent and an already-installed provider is left in place. If your
//!   binary prefers `aws-lc-rs`, install it before calling
//!   [`Authenticator::start`] and this crate uses yours, including for its own
//!   discovery and JWKS fetches.
//! - **It happens at startup, never on the request path.** The provider is
//!   settled by the time `start` returns.
//!
//! Nothing else is global. No background task is spawned, so a JWKS refresh runs
//! on the request that needed it, coalesced and rate-limited rather than
//! fire-and-forget. No environment variable is read or written.
//!
//! For logs, the crate emits [`tracing`](https://docs.rs/tracing) events and
//! never the credential: no `Authorization` value and no signature appears in a
//! log line at any level. What `TRACE` does carry is `sub`@`iss`, `aud`, and
//! `exp`, which makes trace-level output as sensitive as your access logs, and
//! [`Claims::log_id`] exists precisely so that is the most identifying thing
//! there is.
//!
//! # Verification order
//!
//! Order matters, so it is fixed in
//! [`Authenticator::authenticate`](crate::Authenticator::authenticate):
//!
//! 1. **`alg` must be an accepted asymmetric algorithm.** This crate rejects
//!    `none` and every HMAC variant before any key is consulted. HMAC is not
//!    reachable at all, because [`SignatureAlgorithm`] cannot express it. That
//!    is what makes algorithm confusion impossible rather than unlikely.
//!    Algorithm confusion forges an `HS256` token signed with the issuer's
//!    public key as the secret. Accepting `ES256` or `EdDSA` widens which
//!    *asymmetric* algorithms can be tried. It cannot widen the families, and
//!    an RSA key is no more reachable from an `ES256` header than an HMAC
//!    secret is. Step 4 narrows further from here, per key.
//! 2. **The claimed `iss` selects a trust bundle.** This crate reads `iss`
//!    unverified and uses it only to choose which public keys to try. It
//!    proves nothing by itself.
//! 3. **`iss` and `kid` must name exactly one key.** There is no try-all-keys
//!    search, and no fallback to the first key when `kid` is missing. An
//!    unknown `kid` triggers one rate-limited refresh, which is how key
//!    rotation is caught. Which key *types* can be named is its own allowlist,
//!    fixed by [`SignatureAlgorithm`]. This crate rejects a JWK by type before
//!    it turns the JWK into a key. A JWK is never admitted because it happened
//!    to parse.
//! 4. **Verify the signature, then `exp`/`nbf`, `iss`, and `aud`.** The
//!    algorithms offered to the verifier are `configured` intersected with the
//!    family of the selected key. `jsonwebtoken` cannot test one key against
//!    a list that spans families. Without the intersection, an issuer that
//!    published both an RSA and an EC JWK, or one mid-rotation, would have
//!    every token rejected. The set only ever shrinks: whatever reaches
//!    `decode` was already permitted by step 1. This crate compares `iss` with
//!    the issuer that actually verified the signature, so step 2 can never be
//!    a way to launder a wrong issuer.
//! 5. **`azp` narrows further, per issuer, if that issuer configures it.**
//!    [`Issuer::authorized_parties()`] names the clients accepted *from that
//!    issuer*, looked up under the verified `iss`. In a stock Keycloak realm
//!    `aud` is `"account"` for every API, so `azp` is what names the client
//!    there. It runs after `aud` and never instead of it, so it can only shrink
//!    the accepted set: a token here must name a trusted resource in `aud`
//!    **and** a trusted client in `azp`. The per-issuer reasoning, and the swap
//!    one shared list would allow, are on that field.
//!
//! Both middlewares run this same sequence, unchanged, on every token they are
//! given. [`optional_auth`] does not weaken it. It only declines to demand a
//! token.
//!
//! # Deliberate limits
//!
//! - **HTTPS only** for issuers and for JWKS endpoints. These answers establish
//!   trust. `allow_insecure_http` relaxes the transport for a loopback host
//!   only: `127.0.0.0/8`, `::1`, `localhost`. A cleartext issuer on any other
//!   host stays refused, even with the flag set. Whoever answers for that host
//!   picks the keys that authenticate your users.
//! - **Asymmetric keys of an allowlisted type.** The accepted keys are:
//!   - `kty: RSA` for `RS256`, `RS384`, `RS512`, and `PS256`.
//!   - `kty: EC` on P-256 or P-384 for `ES256` and `ES384`.
//!   - `kty: OKP` on Ed25519 for `EdDSA`.
//!
//!   The EC and OKP families work only when you name them in
//!   [`AuthConfig::algorithms`]. The default remains RS256 alone.
//! - Refused, key by key and logged:
//!   - `oct`. A symmetric key in the trust bundle is the HMAC leg of algorithm
//!     confusion. No later `alg` rule can rescue a bundle that contains one.
//!   - `use: enc`. An encryption key is a different key for a different
//!     purpose.
//!   - A JWK whose `alg` is present and unconfigured.
//!   - `kty: EC` on P-521. No algorithm in this crate can use it.
//!
//!   Unusable keys are skipped, not fatal. One bad entry must not cost an
//!   issuer its good keys.
//! - **`kid` is required.** An issuer that omits `kid` cannot be supported
//!   without the search this crate refuses to do.
//! - **No audience validation switch, and no audience default.** Every issuer
//!   names at least one audience before the process will start. A token minted
//!   for another client of the same issuer is not yours to accept, and an issuer
//!   that named nothing is not a policy — so it is refused rather than read as
//!   "everything you serve".
//! - **`azp` is opt-in per issuer, and empty means that issuer's gate is off.**
//!   An empty list is "any client *from this issuer*", not "no client". It is
//!   off for that issuer alone, which is what an issuer that never emits `azp`
//!   needs: Google does not, and a gate it can never satisfy is an outage. When
//!   an issuer does configure the gate, this crate rejects a token from that
//!   issuer that lacks `azp`. Otherwise an omitted claim would defeat the gate.

/// Compiles the README's quick-start example. Nothing else does.
///
/// The README is not included in the crate's own docs. So its `use` lines are a
/// copy of the crate name that no build tests. That is the same kind of problem
/// as a hard-coded string. The renaming of this crate proved it: the examples
/// still said `oidc_auth` afterwards and stayed green. `cfg(doctest)` keeps the
/// type out of the library and out of the docs. The block is `no_run`, so this
/// asserts that the example compiles, not that it reaches Google.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

mod claims;
mod config;
mod error;
mod extract;
mod http;
mod jwks;
mod types;
mod validator;

pub use claims::Claims;
pub use config::{AuthConfig, Issuer, SignatureAlgorithm};
pub use error::AuthError;
pub use extract::{AuthUser, OptionalAuthUser, authorization, optional_auth, require_auth};
pub use jwks::CachePolicy;
pub use types::{Audience, AuthorizedParty, IssuerUrl};
pub use validator::Authenticator;
