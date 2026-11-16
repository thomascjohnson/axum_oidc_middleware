//! A stub OIDC issuer on loopback, and helpers to mint tokens against it.
//!
//! This is a real HTTP server, not a mock. It exercises discovery, JWKS
//! fetching, caching, and the rotation refresh over the same code paths
//! production uses. `axum` and `tokio` are already dependencies, so this needs
//! no test framework beyond what the workspace already carries.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, RwLock};
use std::time::{Duration, Instant};

use axum::response::IntoResponse as _;
use axum_oidc_middleware::Authenticator;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use jsonwebtoken::{EncodingKey, Header};
use p256::ecdsa::SigningKey as P256SigningKey;
use p384::ecdsa::SigningKey as P384SigningKey;
use rand::rngs::OsRng;
// `rsa`, `p256` and `p384` all re-export the same `pkcs8` traits, so one set of
// imports serialises every key type here.
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey};

/// Test keys are 2048-bit. Generation takes a fraction of a second, and every
/// test below shares one key except where rotation is the subject.
const KEY_BITS: usize = 2048;

/// One signing key, in every form a test needs.
///
/// RSA, ECDSA on P-256/P-384, and Ed25519. These are the shapes a JWKS
/// carries, because the subject of the EC tests is precisely that each `kty`
/// publishes different components. This is modelled as an enum rather than a
/// struct of `Option`s, so a `TestKey` cannot accidentally publish `kty: EC`
/// with an RSA `n` and no coordinates. That shape is still reachable, but only
/// on purpose, through [`TestKey::jwk_with_kty`].
#[derive(Clone)]
pub struct TestKey {
    pub kid: String,
    material: Material,
}

/// The key pair behind a [`TestKey`], and the JWK components it implies.
#[derive(Clone)]
enum Material {
    /// `n`/`e` unpadded base64url. `public` is SPKI DER. These are the bytes
    /// an algorithm-confusion attacker uses as an HMAC "secret".
    Rsa {
        private_pem: Vec<u8>,
        n: String,
        e: String,
        public: Vec<u8>,
    },
    /// `crv`/`x`/`y` as RFC 7518 §6.2 spells them. `public` is the
    /// uncompressed SEC1 point. A verifier parses this out of those
    /// coordinates, and it plays the same "public key as secret" role for an
    /// EC bundle.
    Ec {
        private_pem: Vec<u8>,
        alg: jsonwebtoken::Algorithm,
        crv: &'static str,
        x: String,
        y: String,
        public: Vec<u8>,
    },
    /// `public` is the bare 32-byte Ed25519 key, which doubles as JWK `x`.
    Ed25519 {
        private_pem: Vec<u8>,
        public: Vec<u8>,
    },
}

impl TestKey {
    /// Generate a fresh RSA key pair. This is the shape every existing test
    /// signs with.
    pub fn generate(kid: &str) -> Self {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, KEY_BITS).expect("generate an RSA key");
        let public = private.to_public_key();

        let pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("serialise the private key to PKCS#8 PEM");

        let encode = |value: &BigUint| URL_SAFE_NO_PAD.encode(value.to_bytes_be());

        Self {
            kid: kid.to_owned(),
            material: Material::Rsa {
                private_pem: pem.as_bytes().to_vec(),
                n: encode(public.n()),
                e: encode(public.e()),
                public: public
                    .to_public_key_der()
                    .expect("serialise the public key to SPKI DER")
                    .as_ref()
                    .to_vec(),
            },
        }
    }

    /// Generate a P-256 key pair, for `ES256`.
    pub fn generate_es256(kid: &str) -> Self {
        let private = P256SigningKey::random(&mut OsRng);
        Self::ec(
            kid,
            jsonwebtoken::Algorithm::ES256,
            "P-256",
            private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("serialise the private key to PKCS#8 PEM")
                .as_bytes()
                .to_vec(),
            private.verifying_key().to_encoded_point(false).as_ref(),
        )
    }

    /// Generate a P-384 key pair, for `ES384`.
    pub fn generate_es384(kid: &str) -> Self {
        let private = P384SigningKey::random(&mut OsRng);
        Self::ec(
            kid,
            jsonwebtoken::Algorithm::ES384,
            "P-384",
            private
                .to_pkcs8_pem(LineEnding::LF)
                .expect("serialise the private key to PKCS#8 PEM")
                .as_bytes()
                .to_vec(),
            private.verifying_key().to_encoded_point(false).as_ref(),
        )
    }

    /// Assemble an EC key from its PKCS#8 PEM and its uncompressed SEC1 public
    /// point, which is the one shape both curves' crates agree on.
    ///
    /// The point is split by hand rather than asked for `x`/`y`. The accessors
    /// return `Option` because a compressed point has no `y`. Every point here
    /// came from `to_encoded_point(false)`, so the format is known:
    /// `0x04 || x || y`, two field-sized halves. That is RFC 5480 §2.2, and the
    /// same bytes RFC 7518 §6.2 base64url-encodes into `x` and `y`.
    fn ec(
        kid: &str,
        alg: jsonwebtoken::Algorithm,
        crv: &'static str,
        private_pem: Vec<u8>,
        point: &[u8],
    ) -> Self {
        let (_, coordinates) = point.split_first().expect("a SEC1 point is not empty");
        assert_eq!(
            coordinates.len() % 2,
            0,
            "{crv} point is not an uncompressed pair of coordinates"
        );
        let (x, y) = coordinates.split_at(coordinates.len() / 2);

        Self {
            kid: kid.to_owned(),
            material: Material::Ec {
                private_pem,
                alg,
                crv,
                x: URL_SAFE_NO_PAD.encode(x),
                y: URL_SAFE_NO_PAD.encode(y),
                public: point.to_vec(),
            },
        }
    }

    /// Generate an Ed25519 key pair, for `EdDSA`.
    pub fn generate_ed25519(kid: &str) -> Self {
        let private = Ed25519SigningKey::generate(&mut OsRng);
        let public = private.verifying_key().as_bytes().to_vec();

        Self {
            kid: kid.to_owned(),
            material: Material::Ed25519 {
                private_pem: private
                    .to_pkcs8_pem(LineEnding::LF)
                    .expect("serialise the private key to PKCS#8 PEM")
                    .as_bytes()
                    .to_vec(),
                public,
            },
        }
    }

    /// The algorithm this key signs with, and the `alg` its JWK claims.
    pub fn alg(&self) -> jsonwebtoken::Algorithm {
        match &self.material {
            Material::Rsa { .. } => jsonwebtoken::Algorithm::RS256,
            Material::Ec { alg, .. } => *alg,
            Material::Ed25519 { .. } => jsonwebtoken::Algorithm::EdDSA,
        }
    }

    /// The private half, as PEM. Only the HMAC forgeries use it as a plain
    /// byte string. Real signing goes through [`Self::sign_with_alg`].
    fn private_pem(&self) -> &[u8] {
        match &self.material {
            Material::Rsa { private_pem, .. }
            | Material::Ec { private_pem, .. }
            | Material::Ed25519 { private_pem, .. } => private_pem,
        }
    }

    /// The public half as the bytes a verifier would have to work with. RSA:
    /// SPKI DER. EC: an uncompressed SEC1 point. Ed25519: the bare key.
    fn public_bytes(&self) -> &[u8] {
        match &self.material {
            Material::Rsa { public, .. }
            | Material::Ec { public, .. }
            | Material::Ed25519 { public, .. } => public,
        }
    }

    /// This key as a JWK entry in a JWKS document, in the shape its own `kty`
    /// requires.
    pub fn jwk(&self) -> serde_json::Value {
        let alg = alg_name(self.alg());

        match &self.material {
            Material::Rsa { n, e, .. } => serde_json::json!({
                "kty": "RSA",
                "use": "sig",
                "alg": alg,
                "kid": self.kid,
                "n": n,
                "e": e,
            }),
            Material::Ec { crv, x, y, .. } => serde_json::json!({
                "kty": "EC",
                "use": "sig",
                "alg": alg,
                "kid": self.kid,
                "crv": crv,
                "x": x,
                "y": y,
            }),
            Material::Ed25519 { public, .. } => serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": alg,
                "kid": self.kid,
                "x": URL_SAFE_NO_PAD.encode(public),
            }),
        }
    }

    /// A copy of this key's JWK with `kid` changed, for "issuer published a
    /// key we have never seen" tests.
    pub fn jwk_as(&self, kid: &str) -> serde_json::Value {
        let mut jwk = self.jwk();
        jwk["kid"] = serde_json::Value::String(kid.to_owned());
        jwk
    }

    /// This key's JWK with `kty` replaced, e.g. `"oct"` or `"EC"`, to verify
    /// unusable key types are skipped rather than trusted. The components stay
    /// whatever the real key has, and that is the point. This is the incoherent
    /// JWK a broken provider publishes.
    pub fn jwk_with_kty(&self, kty: &str) -> serde_json::Value {
        let mut jwk = self.jwk();
        jwk["kty"] = serde_json::Value::String(kty.to_owned());
        jwk
    }

    /// This key's JWK with `crv` replaced, e.g. `"P-521"` on a P-256 key, for
    /// keys on a curve no accepted algorithm can use.
    pub fn jwk_with_crv(&self, crv: &str) -> serde_json::Value {
        let mut jwk = self.jwk();
        jwk["crv"] = serde_json::Value::String(crv.to_owned());
        jwk
    }

    /// Sign `claims` with this key's own algorithm.
    pub fn sign(&self, claims: &serde_json::Value) -> String {
        self.sign_with_alg(claims, self.alg())
    }

    /// Sign `claims` with an arbitrary algorithm.
    ///
    /// `HS256` here is keyed with the *private* PEM, so it produces a token no
    /// public key could ever verify. That is a second, independent test that the
    /// HMAC family is unreachable, whatever bytes acted as the secret. Any other
    /// algorithm must be one this key's family can perform. Asking a P-256 key
    /// for `ES384` fails loudly rather than quietly minting a token that would
    /// make the wrong thing pass.
    pub fn sign_with_alg(
        &self,
        claims: &serde_json::Value,
        alg: jsonwebtoken::Algorithm,
    ) -> String {
        let mut header = Header::new(alg);
        header.kid = Some(self.kid.clone());
        header.typ = Some("JWT".to_owned());

        if alg == jsonwebtoken::Algorithm::HS256 {
            return jsonwebtoken::encode(
                &header,
                claims,
                &EncodingKey::from_secret(self.private_pem()),
            )
            .expect("encode a token");
        }

        let key = match &self.material {
            Material::Rsa { private_pem, .. } => EncodingKey::from_rsa_pem(private_pem),
            Material::Ec { private_pem, .. } => EncodingKey::from_ec_pem(private_pem),
            Material::Ed25519 { private_pem, .. } => EncodingKey::from_ed_pem(private_pem),
        }
        .expect("encoding key for this algorithm");

        jsonwebtoken::encode(&header, claims, &key).expect("encode a token")
    }

    /// Sign `claims` under a header carrying arbitrary extra members.
    ///
    /// `raw_token` cannot produce these. A JWS signature covers the header as
    /// well as the payload. So bolting a member onto a header that was not
    /// signed with it present yields `InvalidSignature`, and the test measures
    /// the wrong thing. The header here is genuinely the one that was signed,
    /// which is what makes a `crit` or unknown-member test mean anything.
    ///
    /// The `Header` is deserialised from JSON rather than assembled field by
    /// field. Its unrecognised members live in a flattened `extras` map. So
    /// JSON is the shape that reaches every part of it, including `crit`,
    /// without naming `Extras` at the call site.
    pub fn sign_with_header(
        &self,
        claims: &serde_json::Value,
        extra_header: serde_json::Value,
    ) -> String {
        let mut json = serde_json::json!({
            "alg": alg_name(self.alg()),
            "typ": "JWT",
            "kid": self.kid,
        });
        if let (Some(object), Some(extra)) = (json.as_object_mut(), extra_header.as_object()) {
            for (key, value) in extra {
                object.insert(key.clone(), value.clone());
            }
        }

        let header: Header = serde_json::from_value(json).expect("a header jsonwebtoken can parse");
        let key = match &self.material {
            Material::Rsa { private_pem, .. } => EncodingKey::from_rsa_pem(private_pem),
            Material::Ec { private_pem, .. } => EncodingKey::from_ec_pem(private_pem),
            Material::Ed25519 { private_pem, .. } => EncodingKey::from_ed_pem(private_pem),
        }
        .expect("encoding key for this algorithm");

        jsonwebtoken::encode(&header, claims, &key).expect("encode a token")
    }

    /// `HS256` using the *public* key as the HMAC secret.
    ///
    /// This is the canonical confusion forgery. A verifier that accepts both
    /// `RS256` and `HS256` will verify that HMAC using the public key it
    /// already trusts, which is not a secret at all. This works for every key
    /// type, and that is the point. Accepting EC or Ed25519 must not make this
    /// family reachable either.
    pub fn forge_hs256_with_public_key(&self, claims: &serde_json::Value) -> String {
        let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(self.kid.clone());
        header.typ = Some("JWT".to_owned());

        jsonwebtoken::encode(
            &header,
            claims,
            &EncodingKey::from_secret(self.public_bytes()),
        )
        .expect("encode the forged token")
    }

    /// Claims for `iss`/`aud`, valid for an hour from now.
    pub fn claims(&self, iss: &str, aud: &str) -> serde_json::Value {
        let now = now();
        serde_json::json!({
            "iss": iss,
            "sub": "user-123",
            "aud": aud,
            "exp": now + 3600,
            "iat": now,
            "email": "user@example.com",
            "email_verified": true,
        })
    }
}

/// The `alg` string a JWK or JWS header carries for an algorithm.
///
/// `jsonwebtoken` has no `Display` for `Algorithm`. `KeyAlgorithm` is its
/// JWK-side spelling of the same set, and it does have one. So the name here is
/// the library's own, not a table this harness maintains.
fn alg_name(alg: jsonwebtoken::Algorithm) -> String {
    jsonwebtoken::jwk::KeyAlgorithm::from(alg).to_string()
}

/// Compact JWS assembled by hand, for headers no encoder will build.
///
/// `signature` is inserted verbatim, so an empty string yields the
/// `alg: none` shape (`xxx.yyy.`) that naive verifiers accept as valid.
pub fn raw_token(
    header: &serde_json::Value,
    claims: &serde_json::Value,
    signature: &str,
) -> String {
    let encode = |value: &serde_json::Value| {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serialise a JSON segment"))
    };
    format!("{}.{}.{signature}", encode(header), encode(claims))
}

/// Seconds since the Unix epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is past 1970")
        .as_secs() as i64
}

/// State the stub issuer serves, mutable mid-test to simulate rotation.
#[derive(Default)]
struct StubState {
    /// Issuer the discovery document reports.
    issuer: String,
    /// Where the stub actually listens, so `jwks_uri` is reachable even when
    /// `issuer` is an `https://` identifier that does not resolve here.
    base_url: String,
    /// Path prefix both endpoints are served under, `""` for the root. A
    /// Keycloak realm advertises its metadata at
    /// `/realms/<name>/.well-known/…`. So an issuer whose `iss` carries a path
    /// has to be discoverable at that path or the client cannot reach it at
    /// all.
    prefix: String,
    /// Keys published at `/jwks.json`.
    keys: Vec<serde_json::Value>,
    /// When true, both endpoints answer 500, simulating an issuer outage.
    failing: bool,
    /// How long `/jwks.json` parks before answering. A slow provider is a
    /// different failure from a dead one. The read path has to stay fast while
    /// a refresh is stuck.
    jwks_delay: Duration,
    /// Verbatim body for `/jwks.json`, bypassing the JSON encoder.
    ///
    /// A key endpoint can answer in ways that are not a key set. An upstream
    /// proxy puts its HTML error page behind a `200`. The document can arrive
    /// truncated, or as a JSON value that is not an object. `axum::Json` cannot
    /// serialise those, and they are exactly the responses the client has to
    /// survive.
    jwks_body: Option<String>,
    /// Verbatim body for `/.well-known/openid-configuration`, same reasoning.
    discovery_body: Option<String>,
    /// Hits on `/jwks.json`, so a test can tell a fetch that is in flight from
    /// one that was never attempted.
    jwks_requests: AtomicUsize,
}

/// A running stub issuer. Aborts its server when dropped.
pub struct StubIssuer {
    base_url: String,
    state: Arc<RwLock<StubState>>,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl StubIssuer {
    /// Start, reporting itself as the issuer.
    ///
    /// Use this for discovery tests. The client fetches
    /// `<iss>/.well-known/openid-configuration` over the network, so `iss` has
    /// to be the address this stub actually answers on. The port is only known
    /// after binding, which is why binding happens before the state exists.
    pub async fn start_local(keys: &[TestKey]) -> Self {
        Self::bind(None, "", keys).await.0
    }

    /// Start, serving both endpoints under `prefix`, and report the issuer as
    /// its own address *plus* that prefix.
    ///
    /// Use this for an issuer whose identifier carries a path, such as a
    /// Keycloak realm at `http://host/realms/demo`. RFC 8414 puts the discovery
    /// document under that path. So this is the only way to exercise an issuer
    /// whose `iss` is not at the root of its host.
    pub async fn start_local_at(prefix: &str, keys: &[TestKey]) -> Self {
        Self::bind(None, prefix, keys).await.0
    }

    /// Start, reporting a fixed issuer identifier.
    ///
    /// Use this for tests where `iss` must be a specific value that is *not*
    /// this server, such as an `https://` identifier, or a deliberately wrong
    /// one. The discovery document still advertises `jwks_uri` on the live
    /// loopback address, so the keys remain reachable.
    pub async fn start(iss: &str, keys: &[TestKey]) -> Self {
        Self::bind(Some(iss), "", keys).await.0
    }

    /// Bind a loopback port and serve. `iss` defaults to the bound address,
    /// plus `prefix` when one is given.
    async fn bind(iss: Option<&str>, prefix: &str, keys: &[TestKey]) -> (Self, String) {
        // A prefix that does not start with `/` would build a URL like
        // `http://127.0.0.1:PORTrealms`. That fails in the confusing place,
        // the request, rather than here, where it names the mistake.
        assert!(
            prefix.is_empty() || prefix.starts_with('/'),
            "stub prefix must be empty or start with `/`, got `{prefix}`"
        );
        // Bind first. The bound address has to be inside the state, because the
        // discovery document advertises `jwks_uri` from it. Also, an issuer
        // naming this server cannot exist before the OS picks a port.
        let listener = tokio::net::TcpListener::bind((IpAddr::from([127, 0, 0, 1]), 0))
            .await
            .expect("bind a loopback port");
        let SocketAddr::V4(addr) = listener.local_addr().expect("read the bound address") else {
            unreachable!("bound over IPv4 loopback")
        };
        let base_url = format!("http://{addr}");
        let issuer = iss
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{base_url}{prefix}"));

        let state = Arc::new(RwLock::new(StubState {
            issuer: issuer.clone(),
            base_url: base_url.clone(),
            prefix: prefix.to_owned(),
            keys: keys.iter().map(TestKey::jwk).collect(),
            failing: false,
            jwks_delay: Duration::ZERO,
            jwks_body: None,
            discovery_body: None,
            jwks_requests: AtomicUsize::new(0),
        }));

        // The two endpoints at the root, and again under the prefix. The root
        // pair is always registered. A test that binds a prefix still reaches
        // `/jwks.json` from the discovery document it is served. The prefixed
        // pair is skipped when the prefix is empty, which would otherwise
        // register the same path twice and panic in `axum`.
        let mut app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(discovery),
            )
            .route("/jwks.json", axum::routing::get(jwks));

        if !prefix.is_empty() {
            app = app
                .route(
                    &format!("{prefix}/.well-known/openid-configuration"),
                    axum::routing::get(discovery),
                )
                .route(&format!("{prefix}/jwks.json"), axum::routing::get(jwks));
        }

        let app = app.with_state(state.clone());

        let server = tokio::spawn(async move {
            // A panicking handler would otherwise vanish silently and every
            // later request would hang instead of failing.
            if let Err(err) = axum::serve(listener, app).await {
                panic!("stub issuer stopped: {err}");
            }
        });

        (
            Self {
                base_url,
                state,
                server: Some(server),
            },
            issuer,
        )
    }

    /// The issuer identifier, matching what discovery reports.
    pub fn iss(&self) -> String {
        self.state.read().expect("read stub state").issuer.clone()
    }

    /// Where the stub actually listens.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Absolute JWKS URL, for `Issuer::with_jwks_url`.
    pub fn jwks_url(&self) -> url::Url {
        url::Url::parse(&format!("{}/jwks.json", self.base_url)).expect("parse the stub JWKS URL")
    }

    /// Replace the published keys. This is the rotation test.
    pub fn rotate(&self, keys: &[TestKey]) {
        let mut state = self.state.write().expect("write stub state");
        state.keys = keys.iter().map(TestKey::jwk).collect();
    }

    /// Publish arbitrary raw JWKs, for malformed or unusable key sets.
    pub fn publish(&self, keys: Vec<serde_json::Value>) {
        self.state.write().expect("write stub state").keys = keys;
    }

    /// Make both endpoints answer 500. This is the outage test.
    pub fn set_failing(&self, failing: bool) {
        self.state.write().expect("write stub state").failing = failing;
    }

    /// Answer `/jwks.json` with exactly `body`, as `application/json`.
    ///
    /// The status stays 200. What is under test is a provider that answers
    /// successfully with something that is not a key set.
    pub fn serve_jwks_body(&self, body: impl Into<String>) {
        self.state.write().expect("write stub state").jwks_body = Some(body.into());
    }

    /// Answer `/.well-known/openid-configuration` with exactly `body`.
    ///
    /// Use this for a discovery document that is malformed in a way
    /// `serde_json::json!` can express but this stub would never build on its
    /// own. Examples: no `issuer`, no `jwks_uri`, or a `jwks_uri` that is not a
    /// URL. Use it also for the capture page a captive portal serves in place of
    /// the document.
    pub fn serve_discovery_body(&self, body: impl Into<String>) {
        self.state.write().expect("write stub state").discovery_body = Some(body.into());
    }

    /// Stop serving, so every later request is a refused connection.
    ///
    /// This is distinct from [`Self::set_failing`]. A 500 is a provider that
    /// is present and unhealthy. A refused connection is one that is gone. The
    /// client takes different paths through its error handling for the two.
    pub fn stop(&self) {
        if let Some(server) = self.server.as_ref() {
            server.abort();
        }
    }

    /// Make `/jwks.json` park for `delay` before answering. This simulates an
    /// identity provider that is slow rather than down. Discovery stays quick,
    /// so only the JWKS path pays for it.
    pub fn set_delay(&self, delay: Duration) {
        self.state.write().expect("write stub state").jwks_delay = delay;
    }

    /// How many requests `/jwks.json` served, 500s included.
    pub fn jwks_requests(&self) -> usize {
        self.state
            .read()
            .expect("read stub state")
            .jwks_requests
            .load(Ordering::Relaxed)
    }

    /// Wait until `/jwks.json` answers `count` requests, and report whether that
    /// happened within five seconds.
    ///
    /// Lets a test assert "the refresh has really reached the issuer" instead
    /// of sleeping and hoping. That is the difference between a timing test
    /// that measures what it claims and one that is flaky on a loaded CI box.
    pub async fn wait_for_jwks_requests(&self, count: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.jwks_requests() < count {
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        true
    }
}

impl Drop for StubIssuer {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

async fn discovery(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<StubState>>>,
) -> axum::response::Response {
    let state = state.read().expect("read stub state");
    // Served ahead of the outage gate. The point of those tests is the body,
    // and a 500 in front of it would hide it.
    if let Some(body) = &state.discovery_body {
        return verbatim_json(body.clone()).into_response();
    }
    if state.failing {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    // The document advertises the prefix it is served from. So a realm-served
    // document points at the realm's own key set, not the root one.
    let jwks_uri = format!("{}{}/jwks.json", state.base_url, state.prefix);
    axum::Json(serde_json::json!({
        "issuer": state.issuer,
        "jwks_uri": jwks_uri,
        "authorization_endpoint": format!("{}/authorize", state.base_url),
        // Advertised from what is actually published, so a stub serving EC
        // keys does not claim to be RS256-only. Nothing in this crate reads
        // it. A stale list here would only mislead the next test written.
        "id_token_signing_alg_values_supported": state
            .keys
            .iter()
            .filter_map(|key| key.get("alg").and_then(serde_json::Value::as_str))
            .collect::<BTreeSet<_>>(),
    }))
    .into_response()
}

async fn jwks(
    axum::extract::State(state): axum::extract::State<Arc<RwLock<StubState>>>,
) -> axum::response::Response {
    // Take everything, including the lock, then release it before stalling. A
    // parked endpoint must not also park `rotate` and `publish`, which need
    // the write lock this handler would otherwise sleep holding.
    let (keys, delay, failing, body) = {
        let state = state.read().expect("read stub state");
        // Counted on arrival, before the outage gate, so a test can see a
        // request that is in flight rather than guess at one.
        state.jwks_requests.fetch_add(1, Ordering::Relaxed);
        (
            state.keys.clone(),
            state.jwks_delay,
            state.failing,
            state.jwks_body.clone(),
        )
    };

    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }

    // Re-read after the stall only to stay honest about the ordering. The body
    // override wins over both the outage and the key set.
    if let Some(body) = body {
        return verbatim_json(body).into_response();
    }

    if failing {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    axum::Json(serde_json::json!({ "keys": keys })).into_response()
}

/// A `200` whose body is exactly `body`, typed as JSON.
///
/// `axum::Json` cannot express this. It re-serialises, so a malformed or
/// truncated document would leave this stub changed.
fn verbatim_json(body: String) -> axum::response::Response {
    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )
        .body(axum::body::Body::from(body))
        .expect("a response with a fixed body")
}

// ── Log capture ──────────────────────────────────────────────────────────────

/// One captured `tracing` event: its level, its message, and every field it
/// carried, rendered to text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub level: tracing::Level,
    pub message: String,
    pub fields: Vec<(String, String)>,
}

impl LogLine {
    /// The value a named field carried, if this event had one.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A `tracing` subscriber that keeps every event it is shown.
///
/// The reason this exists is not the messages. It is that a `tracing` macro
/// evaluates its arguments only when a subscriber enables that level. With no
/// subscriber installed, `debug!(path = %parts.uri.path(), "…")` never
/// evaluates `parts.uri.path()`. So no response can prove the promise a log line
/// makes: that this misconfiguration is reported, with this detail, at this
/// level. Capturing events is the only way to hold the crate to that promise. It
/// also catches what a response cannot: a field that is present but empty, or
/// the wrong level for traffic anyone can provoke. Worst of all, it catches a
/// token that reached a log line.
///
/// Only the crate's own targets are captured, so a test's assertions are not
/// decided by whatever `hyper` or `rustls` happens to log.
#[derive(Clone, Default)]
pub struct LogCapture(Arc<Mutex<Vec<LogLine>>>);

impl LogCapture {
    /// A capture, installed as the default subscriber for the current thread.
    ///
    /// The guard has to stay held for as long as events should be recorded. It
    /// is thread-local, which suits `#[tokio::test]`. That runtime is
    /// single-threaded, so the test, the router it drives, and any task that
    /// router spawns all run on the calling thread.
    pub fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let capture = Self::default();
        let guard = tracing::subscriber::set_default(capture.clone());
        (capture, guard)
    }

    /// Every event captured so far, oldest first.
    pub fn lines(&self) -> Vec<LogLine> {
        self.0.lock().expect("read the log capture").clone()
    }

    /// Events whose message contains `needle`.
    pub fn matching(&self, needle: &str) -> Vec<LogLine> {
        self.lines()
            .into_iter()
            .filter(|line| line.message.contains(needle))
            .collect()
    }

    /// The single event whose message contains `needle`, panicking if the
    /// count is anything but one. That is usually the real bug a logging test
    /// finds: a refusal logged once per retry, or not at all.
    pub fn only(&self, needle: &str) -> LogLine {
        let lines = self.matching(needle);
        assert_eq!(
            lines.len(),
            1,
            "expected exactly one event containing `{needle}`, got {}:\n{}",
            lines.len(),
            self.text()
        );
        lines.into_iter().next().expect("one matching event")
    }

    /// Everything captured, one line each, for assertion messages.
    pub fn text(&self) -> String {
        let lines = self.lines();
        if lines.is_empty() {
            return "  (nothing captured)".to_owned();
        }
        lines
            .iter()
            .map(|line| {
                let fields = line
                    .fields
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("  {:?} {} {}", line.level, line.message, fields)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `true` when no captured event mentions `needle` anywhere, message or
    /// field. This is the assertion that keeps secrets out of logs.
    pub fn excludes(&self, needle: &str) -> bool {
        !self.text().contains(needle)
    }
}

static LOG_TARGET_PREFIX: LazyLock<&'static str> = LazyLock::new(|| {
    std::any::type_name::<Authenticator>()
        .split("::")
        .next()
        .expect("a type name always has a first segment")
});

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        // Everything the crate logs, at every level, `trace!` included.
        metadata.target().starts_with(*LOG_TARGET_PREFIX)
    }

    // No `max_level_hint`. Returning `None` means "no opinion", which leaves
    // every level enabled. A `trace!` line is as much a promise as an `error!`
    // one, and the point of capturing is to see all of them.

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visit = CollectFields::default();
        event.record(&mut visit);
        self.0
            .lock()
            .expect("write the log capture")
            .push(visit.into_line(*event.metadata().level()));
    }

    // Spans are not asserted on anywhere, so `NoSubscriber` handles them.
    // An id that is never revisited, and nothing recorded.
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(0xDEAD)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Renders an event's fields to text, whichever typed `record_*` method each
/// arrived through.
#[derive(Default)]
struct CollectFields {
    message: String,
    fields: Vec<(String, String)>,
}

impl CollectFields {
    fn into_line(self, level: tracing::Level) -> LogLine {
        LogLine {
            level,
            message: self.message,
            fields: self.fields,
        }
    }
}

/// `record_debug` is the catch-all. With `tracing`'s `value` feature every typed
/// field reaches a visitor through it, `%`-formatted fields included. The typed
/// methods are implemented anyway. A field recorded by one of them would
/// otherwise vanish from the capture, and the test would assert against a field
/// list that lied.
impl tracing::field::Visit for CollectFields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // `Debug` renders a string-ish field quoted, which would make every
        // assertion in the suite compare against `\"a reason\"`. Unquoting keeps
        // `field("reason")` the value itself. So a test states the reason the
        // way it appears in the log line, not the way a `Debug` impl renders it.
        // `record_str` below already yields the bare value, and the two
        // spellings of the same field must agree.
        let rendered = format!("{value:?}");
        let text = match rendered.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            Some(inner) => inner.to_owned(),
            None => rendered,
        };

        if field.name() == "message" {
            self.message = text;
        } else {
            self.fields.push((field.name().to_owned(), text));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_debug(field, &value)
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_debug(field, &value)
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_debug(field, &value)
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_debug(field, &value)
    }
}
