//! An OIDC issuer on loopback, so the examples never need a real identity
//! provider or a network connection.
//!
//! `tests/common/mod.rs` already contains a stub issuer with far more control
//! than these examples need: rotation, failing responses, delayed responses,
//! HMAC forgeries. It is deliberately not reused here. Integration tests and
//! examples are separate targets, so sharing it means a `#[path]` module that
//! drags a reader of the documentation into test scaffolding that exists to
//! break things. This file is the subset that a working deployment needs to
//! look like: one RSA key, one realm, discovery, JWKS.
//!
//! Each example uses a different part of this, so an item that looks unused is
//! used by one of them.
#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rand::rngs::OsRng;
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// The audience every example issues its tokens for, and every example
/// configures as the required one.
pub const AUDIENCE: &str = "example-api";

/// The subject in every token these examples mint.
pub const SUBJECT: &str = "user-123";

const KID: &str = "demo-key-1";
const REALM: &str = "/realms/demo";
const KEY_BITS: usize = 2048;

/// An RSA key pair that can both publish a JWK and mint tokens, which is the
/// whole of what an issuer does.
pub struct SigningKey {
    private_pem: Vec<u8>,
    jwk: serde_json::Value,
}

impl SigningKey {
    /// Generate a fresh RSA-2048 key pair.
    ///
    /// 2048 rather than 4096 because these examples run in CI on every push,
    /// and key generation dominates their wall-clock time.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, KEY_BITS)
            .expect("the OS provides enough randomness for a 2048-bit RSA key");
        let public = private.to_public_key();
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("serialise the private key to PKCS#8 PEM")
            .as_bytes()
            .to_vec();

        // `n` and `e` are base64url without padding, which is the JOSE
        // convention rather than the PEM one, so it is worth stating once here.
        let encode_part = |value: &BigUint| URL_SAFE_NO_PAD.encode(value.to_bytes_be());
        let jwk = json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": encode_part(public.n()),
            "e": encode_part(public.e()),
        });

        Self { private_pem, jwk }
    }

    /// Mint a token that this issuer's keys will verify.
    ///
    /// `iss` and `aud` are arguments rather than constants because the
    /// interesting demonstration is a token that is valid *except* for one of
    /// them.
    pub fn token(&self, iss: &str, aud: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_owned());
        header.typ = Some("JWT".to_owned());

        let now = now_seconds();
        let claims = json!({
            "iss": iss,
            "sub": SUBJECT,
            "aud": aud,
            "iat": now,
            // One hour, so a run that starts near a clock boundary still passes.
            "exp": now + 3600,
            "email": "user@example.com",
            "email_verified": true,
        });

        let key = EncodingKey::from_rsa_pem(&self.private_pem)
            .expect("a PKCS#8 RSA key this crate serialised itself");
        encode(&header, &claims, &key).expect("encode an RS256 token")
    }
}

/// A running mock issuer, bound to an ephemeral loopback port.
pub struct MockIssuer {
    iss: String,
    state: Arc<IssuerState>,
    server: JoinHandle<()>,
}

struct IssuerState {
    iss: String,
    base_url: String,
    jwks_url: String,
    keys: RwLock<Vec<serde_json::Value>>,
}

impl MockIssuer {
    /// Serve discovery and JWKS for `iss = http://127.0.0.1:<port>/realms/demo`.
    /// The OS picks the port. That is why the examples read the issuer string
    /// from here instead of configuring a fixed one first.
    pub async fn start(key: &SigningKey) -> Self {
        // Bind first. The discovery document advertises `jwks_uri`, and both
        // that value and the issuer string depend on the bound address. Neither
        // exists until bind returns.
        let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
            .await
            .expect("bind an ephemeral loopback port");
        let SocketAddr::V4(addr) = listener.local_addr().expect("read the bound address") else {
            unreachable!("this listener is bound to IPv4 loopback");
        };

        let base_url = format!("http://{addr}");
        let iss = format!("{base_url}{REALM}");
        let state = Arc::new(IssuerState {
            iss: iss.clone(),
            base_url: base_url.clone(),
            jwks_url: format!("{base_url}{REALM}/jwks.json"),
            keys: RwLock::new(vec![key.jwk.clone()]),
        });

        let app = Router::new()
            .route(
                &format!("{REALM}/.well-known/openid-configuration"),
                axum::routing::get(discovery),
            )
            .route(&format!("{REALM}/jwks.json"), axum::routing::get(jwks))
            .with_state(Arc::clone(&state));

        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("the mock issuer keeps serving");
        });

        Self { iss, state, server }
    }

    /// The exact `iss` value this issuer publishes, and the value you pass to
    /// [`axum_oidc_middleware::Issuer::discover`].
    ///
    /// It has to match byte for byte. The crate treats
    /// `https://host/realms/x` and `https://host/realms/x/` as two different
    /// issuers. So nothing here trusts a trailing slash.
    pub fn iss(&self) -> &str {
        &self.iss
    }

    /// Remove every key from the JWKS document, so a later token cannot verify.
    ///
    /// The crate refuses to start against an issuer that publishes no usable
    /// keys, so this only makes sense after startup.
    pub fn withhold_keys(&self) {
        self.state.withhold();
    }

    /// Serve a JWKS document that contains a key for some *other* key pair.
    ///
    /// This is rotation without the ceremony of a second key: a token minted
    /// before the call stops verifying.
    pub fn rotate(&self) {
        let replacement = SigningKey::generate();
        self.state.replace(vec![replacement.jwk.clone()]);
    }
}

impl Drop for MockIssuer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl IssuerState {
    fn withhold(&self) {
        *self
            .keys
            .write()
            .expect("no example panics while holding the key list") = Vec::new();
    }

    fn replace(&self, keys: Vec<serde_json::Value>) {
        *self
            .keys
            .write()
            .expect("no example panics while holding the key list") = keys;
    }
}

/// The crate reads only `issuer` and `jwks_uri`. The other fields sit here so
/// that a reader who compares this document against a real one sees a document
/// that looks right.
async fn discovery(State(state): State<Arc<IssuerState>>) -> impl IntoResponse {
    axum::Json(json!({
        "issuer": state.iss,
        "jwks_uri": state.jwks_url,
        "authorization_endpoint": format!("{}/authorize", state.base_url),
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid", "email", "profile"],
    }))
}

async fn jwks(State(state): State<Arc<IssuerState>>) -> Response {
    let keys = state
        .keys
        .read()
        .expect("no example panics while holding the key list")
        .clone();
    // A 200 with an empty `keys` array is a legitimate answer from a real
    // issuer mid-rotation, and the crate has to treat it as one.
    axum::Json(json!({ "keys": keys })).into_response()
}

/// Re-exported so an example can build a token whose expiry it controls.
pub fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is past 1970")
        .as_secs() as i64
}

/// Bind an ephemeral loopback port and serve `app` there. Return the address
/// the OS chose, and the task to abort when the example ends.
///
/// The port is ephemeral, not fixed. Two of these run in one process: the mock
/// issuer and the API under it. A fixed port would make the second one depend on
/// whether something else on the machine already owns that port.
pub async fn serve(app: Router) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
        .await
        .expect("bind an ephemeral loopback port");
    let addr = listener.local_addr().expect("read the bound address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the example server keeps serving");
    });
    (addr, server)
}

/// The status a request gets back with no credential at all.
pub const UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;
