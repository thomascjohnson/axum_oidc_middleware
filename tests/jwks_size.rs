//! The JWKS size cap, and whether it binds while the body is still arriving.
//!
//! [`CachePolicy::max_bytes`](axum_oidc_middleware::CachePolicy::max_bytes) exists to stop
//! a compromised issuer turning a token check into memory exhaustion. A
//! `Content-Length` header is the only thing that can warn about an oversized
//! body *before* it is read, and it is a claim the server makes voluntarily:
//! a `Transfer-Encoding: chunked` response has no length to advertise at all.
//! So the cap has to be enforced against the bytes as they stream. These tests
//! check the two halves of that claim separately. An oversized body must be
//! refused, and it must be refused *before* the whole of it is held.
//!
//! Deliberately a raw TCP responder rather than the axum stub in `common`.
//! The subject here is HTTP framing: a body that overruns the length it
//! declares, and a chunked body with no length. hyper's server computes
//! `Content-Length` from the body it is handed and refuses to be talked out of
//! it, so an axum handler cannot put either shape on the wire. Writing the
//! bytes by hand is the only way to ask the question.

mod common;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::tcp::OwnedReadHalf;
use url::Url;

use axum_oidc_middleware::{AuthConfig, AuthError, Authenticator, CachePolicy, Issuer};
use common::TestKey;

const AUDIENCE: &str = "myaudience";

/// The cap every refusal below is measured against: 1 MiB, the default.
const CAP: usize = 1 << 20;

/// One body chunk from the over-cap tests: four times `CAP`, so the very first
/// chunk of the very first response already decides the outcome. The size
/// matters twice over. It is far too big to sit unread in a socket buffer.
/// That is what makes "the client hung up before we finished sending" an
/// observable fact rather than an inference.
const HUGE_CHUNK: usize = 4 << 20;

/// How long a write is given before it counts as the client having stopped
/// reading. Generous: the refusal it is waiting against happens on the first
/// chunk, in milliseconds.
const WRITE_BUDGET: Duration = Duration::from_secs(5);

/// How long the responder waits for a request before giving up on it.
const READ_BUDGET: Duration = Duration::from_secs(5);

/// How long the responder waits for the client to end the connection.
///
/// A connection the client keeps for reuse never ends, so this budget expiring
/// is a normal outcome and not a failed measurement.
const CLOSE_BUDGET: Duration = Duration::from_secs(5);

/// How long a test waits for the responder to finish after the client call
/// returns. The refusal itself is immediate. What lags behind it is the
/// responder's blocked write noticing the socket is gone, and that has to be
/// observed rather than assumed.
///
/// A function, not a constant. `Duration: Add` is not `const`. So spelling the
/// budget as a `const` would hard-code the sum, and it would silently drift out
/// of step with `WRITE_BUDGET`. Deriving it keeps the two tied together.
fn write_settle() -> Duration {
    WRITE_BUDGET + Duration::from_secs(2)
}

/// One piece of a response body, spelled as it goes on the wire.
enum Chunk {
    /// A member of a `Transfer-Encoding: chunked` body, framed with its own
    /// length prefix. This is what a server sends when it does not know, or
    /// will not say, how big the body is.
    Chunked(Vec<u8>),
    /// Written verbatim, after a `Content-Length` that does not count it.
    Raw(Vec<u8>),
}

impl Chunk {
    /// The bytes this chunk puts on the wire, framing included.
    fn on_the_wire(&self) -> Vec<u8> {
        match self {
            Chunk::Chunked(body) => {
                let mut framed = format!("{:x}\r\n", body.len()).into_bytes();
                framed.extend_from_slice(body);
                framed.extend_from_slice(b"\r\n");
                framed
            }
            Chunk::Raw(body) => body.clone(),
        }
    }
}

/// A complete hostile response: the head, then the body one piece at a time.
struct Plan {
    /// Response header lines, terminating CRLF included, status line first.
    head: Vec<String>,
    chunks: Vec<Chunk>,
    /// End the stream without the chunk terminator, so a client that read the
    /// bytes it was given still sees the body stop short.
    truncate: bool,
}

impl Plan {
    /// Total body bytes this plan puts on the wire, framing included. This is
    /// the denominator the "how much got through" assertions are measured
    /// against.
    fn wire_len(&self) -> usize {
        self.chunks
            .iter()
            .map(|chunk| chunk.on_the_wire().len())
            .sum()
    }

    /// A chunked body with no `Content-Length` anywhere in the head.
    fn chunked(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            head: vec![
                "HTTP/1.1 200 OK\r\n".to_owned(),
                "Content-Type: application/json\r\n".to_owned(),
                "Transfer-Encoding: chunked\r\n".to_owned(),
                "\r\n".to_owned(),
            ],
            chunks: chunks.into_iter().map(Chunk::Chunked).collect(),
            truncate: false,
        }
    }

    /// Declares `declared` bytes of body and then sends more than that.
    /// `Transfer-Encoding: chunked` is present as well. A front-end that
    /// re-frames a response produces this shape. It is also the case where the
    /// declared length promises a body far smaller than the one that arrives.
    fn overrun(declared: u64, chunks: Vec<Vec<u8>>) -> Self {
        Self {
            head: vec![
                "HTTP/1.1 200 OK\r\n".to_owned(),
                "Content-Type: application/json\r\n".to_owned(),
                format!("Content-Length: {declared}\r\n"),
                "Transfer-Encoding: chunked\r\n".to_owned(),
                "\r\n".to_owned(),
            ],
            chunks: chunks.into_iter().map(Chunk::Chunked).collect(),
            truncate: false,
        }
    }

    /// Chunked members, then the connection closes without the terminator.
    ///
    /// The other plans here ask how much of a *large* body the client will
    /// take. This one asks what happens to a *short* one that never finishes.
    /// Every byte that arrives is well-formed and under the cap. The failure is
    /// that the stream ends mid-document. It is the shape of a reverse proxy
    /// killed while forwarding, or a server OOM-killed after flushing headers.
    /// It is also an idle timeout on the wrong side of a load balancer. None of
    /// those look like an outage from the head of the response, because the head
    /// says `200 OK`.
    fn cut_off(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            truncate: true,
            ..Self::chunked(chunks)
        }
    }

    /// A truthful `Content-Length`, larger than the cap, with the body to match.
    fn sized(body: Vec<u8>) -> Self {
        Self {
            head: vec![
                "HTTP/1.1 200 OK\r\n".to_owned(),
                "Content-Type: application/json\r\n".to_owned(),
                format!("Content-Length: {}\r\n", body.len()),
                "\r\n".to_owned(),
            ],
            chunks: vec![Chunk::Raw(body)],
            truncate: false,
        }
    }
}

/// What the responder managed to send. The evidence for "refused as it
/// arrived" lives here. A client that reads the whole body takes every chunk.
/// A client that hangs up mid-stream leaves the responder short by whatever it
/// never wrote.
#[derive(Default)]
struct Progress {
    /// Fetches the client made, counted once per accepted connection.
    requests: AtomicUsize,
    /// Whole chunks the kernel accepted.
    chunks: AtomicUsize,
    /// Body bytes the kernel accepted, framing included, partial writes and
    /// all. This is the quantity a stalled write stops on.
    bytes: AtomicUsize,
    /// A write failed or stalled, so the client stopped taking the body.
    abandoned: AtomicBool,
    /// The client's stack reset the connection. A peer resets when it closes
    /// with bytes still unread in its kernel, so this means the client stopped
    /// taking the body. Unlike a failed write, it does not depend on how much
    /// the peer's receive window was willing to hold.
    reset: AtomicBool,
    /// The client read what the responder sent and closed the connection
    /// cleanly. The opposite reading of `reset`, and the outcome these tests
    /// must not mistake for a hang-up.
    drained: AtomicBool,
    /// The responder finished its write loop, whether it sent the body or was
    /// refused part-way. Lets a test wait for the outcome instead of guessing
    /// at how long a blocked write needs to notice the socket closed.
    done: AtomicBool,
}

/// A JWKS endpoint serving one hand-written response, repeatedly.
struct HostileIssuer {
    jwks_url: Url,
    progress: Arc<Progress>,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl HostileIssuer {
    async fn start(plan: Plan) -> Self {
        // A `TcpSocket` rather than `TcpListener::bind`, so the send buffer can
        // be shrunk before anything is accepted: accepted streams inherit it.
        // A default buffer is megabytes. That would let the whole body of an
        // abandoned response be "written" into the kernel without a client ever
        // reading it. Then the hang-up these tests report on would not happen.
        let socket = tokio::net::TcpSocket::new_v4().expect("open an IPv4 socket");
        socket
            .set_send_buffer_size(8 * 1024)
            .expect("shrink the send buffer");
        socket
            .set_recv_buffer_size(8 * 1024)
            .expect("shrink the receive buffer");
        socket
            .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind a loopback port");
        let listener = socket.listen(16).expect("listen");
        let SocketAddr::V4(addr) = listener.local_addr().expect("read the bound address") else {
            unreachable!("bound over IPv4 loopback")
        };
        let jwks_url =
            Url::parse(&format!("http://{addr}/jwks.json")).expect("parse the stub JWKS URL");

        let plan = Arc::new(plan);
        let progress = Arc::new(Progress::default());

        let server = tokio::spawn(serve(listener, plan, progress.clone()));

        Self {
            jwks_url,
            progress,
            server: Some(server),
        }
    }

    fn jwks_url(&self) -> Url {
        self.jwks_url.clone()
    }

    fn iss(&self) -> String {
        format!("http://{}", self.jwks_url.authority())
    }

    /// JWKS fetches the client made, as accepted connections.
    ///
    /// The responder counts on accept, before it writes a byte of the answer.
    /// So a count read after the client has its verdict is settled, rather than
    /// racing with the write loop.
    fn requests(&self) -> usize {
        self.progress.requests.load(Ordering::SeqCst)
    }

    /// Body bytes the responder handed to the kernel, framing included.
    fn sent(&self) -> usize {
        self.progress.bytes.load(Ordering::SeqCst)
    }

    /// Whole chunks the responder handed to the kernel.
    fn chunks_sent(&self) -> usize {
        self.progress.chunks.load(Ordering::SeqCst)
    }

    /// Whether the client stopped taking the body before it was finished.
    ///
    /// Two independent observations. A write that failed or stalled is the
    /// direct one. A reset from the peer holds on every operating system. A
    /// peer that closes with unread bytes in its kernel always resets, whatever
    /// its buffers accepted first.
    fn left_body_unread(&self) -> bool {
        self.progress.abandoned.load(Ordering::SeqCst) || self.progress.reset.load(Ordering::SeqCst)
    }

    /// Whether the client read the body and closed the connection cleanly.
    /// Only meaningful after [`HostileIssuer::settle_close`].
    fn peer_drained(&self) -> bool {
        self.progress.drained.load(Ordering::SeqCst)
    }

    /// Wait for the client to end the connection, so the two signals above are
    /// read settled rather than mid-close.
    ///
    /// No assertion here. A client that accepted the document keeps the
    /// connection for reuse, and that connection never ends within the budget.
    /// Such a run reports neither signal, and a test that expects a hang-up
    /// fails on its own verdict instead.
    async fn settle_close(&self) {
        let deadline = Instant::now() + CLOSE_BUDGET;
        while !(self.progress.reset.load(Ordering::SeqCst)
            || self.progress.drained.load(Ordering::SeqCst))
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Wait for the responder to finish writing — body delivered or client
    /// refused — so the counts above are read settled rather than mid-write.
    /// A client that hangs up mid-body leaves a blocked write to time out, so
    /// this is genuinely asynchronous and sleeping on it would be guessing.
    async fn settle(&self) {
        let deadline = Instant::now() + write_settle();
        while !self.progress.done.load(Ordering::SeqCst) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            self.progress.done.load(Ordering::SeqCst),
            "the responder never finished writing, so its counts say nothing"
        );
    }
}

impl Drop for HostileIssuer {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

async fn serve(listener: TcpListener, plan: Arc<Plan>, progress: Arc<Progress>) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        let plan = plan.clone();
        let progress = progress.clone();
        tokio::spawn(async move {
            answer(socket, &plan, progress.clone()).await;
            progress.done.store(true, Ordering::SeqCst);
        });
    }
}

async fn answer(socket: TcpStream, plan: &Plan, progress: Arc<Progress>) {
    progress.requests.fetch_add(1, Ordering::SeqCst);

    let _ = socket.set_nodelay(true);

    // Split so the close can be watched while the body is still being written.
    let (mut reader, mut writer) = socket.into_split();

    // Drain the request, or at least the part that arrived. Nothing reads the
    // answer's side of the conversation. But leaving the request unread would
    // make the client's own write fail, instead of the one being measured.
    let mut request = Vec::new();
    let mut scratch = [0u8; 4096];
    let _ = tokio::time::timeout(READ_BUDGET, async {
        while !request.ends_with(b"\r\n\r\n") {
            let read = reader.read(&mut scratch).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&scratch[..read]);
        }
        Ok::<(), io::Error>(())
    })
    .await;

    // Watch the read direction for how this connection ends. Writes cannot
    // show it: a peer whose receive window is wide takes a whole body on its
    // application's behalf, and every write to it then succeeds.
    watch_close(reader, progress.clone());

    for line in &plan.head {
        if send(&mut writer, line.as_bytes()).await.is_err() {
            progress.abandoned.store(true, Ordering::SeqCst);
            return;
        }
    }

    // One chunk at a time, flushed, each on its own write. A peer that has
    // hung up shows up as a failure on the write after the one it stopped at.
    for (index, chunk) in plan.chunks.iter().enumerate() {
        let wire = chunk.on_the_wire();
        match send(&mut writer, &wire).await {
            Ok(written) => {
                progress.bytes.fetch_add(written, Ordering::SeqCst);
                progress.chunks.fetch_add(1, Ordering::SeqCst);
            }
            // A peer that hung up shows up as a failure part-way through a
            // chunk. What it did take is still counted. That is the amount of
            // body the client agreed to hold before it refused.
            Err((written, _)) => {
                progress.bytes.fetch_add(written, Ordering::SeqCst);
                if index + 1 < plan.chunks.len() {
                    progress.abandoned.store(true, Ordering::SeqCst);
                }
                return;
            }
        }
    }

    // The terminator is what distinguishes "body complete" from "connection
    // went away" for a chunked transfer. So skipping it and closing is the
    // whole of `cut_off`. The client has valid framing up to the last byte it
    // was given, and then an early EOF instead of a zero-length chunk.
    if !plan.truncate {
        for chunk in &plan.chunks {
            if matches!(chunk, Chunk::Chunked(_)) {
                let _ = writer.write_all(b"0\r\n\r\n").await;
                break;
            }
        }
    }
    let _ = writer.shutdown().await;
}

/// Record how the client ends the connection, on the half the client never
/// writes to.
///
/// A peer that closes with bytes still unread in its kernel sends a reset, and
/// a peer that read everything sends a clean finish. That is what `drained` and
/// `reset` distinguish, and it holds on every operating system. The write
/// direction cannot carry this claim, because a wide receive window absorbs a
/// whole body for an application that never reads it.
///
/// The read is never expected to return data: the client sends its request and
/// then only reads. Any byte that does arrive is discarded and ignored.
fn watch_close(mut reader: OwnedReadHalf, progress: Arc<Progress>) {
    tokio::spawn(async move {
        let mut seen = [0u8; 512];
        let closed_cleanly = tokio::time::timeout(CLOSE_BUDGET, async {
            loop {
                match reader.read(&mut seen).await {
                    Ok(0) => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        })
        .await;
        match closed_cleanly {
            // The stream ended and the peer closed it. It read what the
            // responder sent.
            Ok(true) => progress.drained.store(true, Ordering::SeqCst),
            // The read failed, which is a reset: the peer closed with bytes it
            // never read. This is the hang-up signal that does not depend on
            // how wide the peer's receive window was.
            Ok(false) => progress.reset.store(true, Ordering::SeqCst),
            // The budget ran out. The client kept this connection for reuse, so
            // there is no verdict to record.
            Err(_) => {}
        }
    });
}

/// One write, bounded. The `Ok` is how many bytes the kernel took. An error
/// carries how far it got first, because that partial progress *is* the
/// measurement. It says how much of the body the client let through before
/// refusing. A blocked write is an error too: a client that will not drain is
/// the same event as one that closed.
async fn send<W>(socket: &mut W, bytes: &[u8]) -> Result<usize, (usize, io::Error)>
where
    W: AsyncWrite + Unpin,
{
    let attempt = tokio::time::timeout(WRITE_BUDGET, async {
        let mut written = 0;
        let result: io::Result<()> = async {
            while written < bytes.len() {
                let taken = socket.write(&bytes[written..]).await?;
                if taken == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "the peer took nothing",
                    ));
                }
                written += taken;
            }
            socket.flush().await
        }
        .await;
        (written, result)
    })
    .await;

    match attempt {
        Ok((written, Ok(()))) => Ok(written),
        Ok((written, Err(err))) => Err((written, err)),
        Err(_) => Err((0, io::Error::new(io::ErrorKind::TimedOut, "stalled"))),
    }
}

/// A policy whose cap is `max_bytes`, otherwise the defaults the crate ships.
fn policy(max_bytes: usize) -> CachePolicy {
    CachePolicy {
        max_bytes,
        ..CachePolicy::default()
    }
}

/// The refusal's message. Every caller has already asserted the variant with
/// `matches!`. This reads the wording, and reaching the panic would mean the
/// body was refused for some reason unrelated to its size.
fn refusal(outcome: Result<(), AuthError>) -> String {
    match outcome {
        Err(AuthError::ProviderUnavailable(note)) => note,
        other => panic!("expected a provider refusal, got {other:?}"),
    }
}

/// Warm an authenticator against `issuer`. The warm-up fetch *is* the fetch
/// under test, so it reports both success and failure to the caller instead of
/// unwrapping. Which one happened is the assertion.
async fn start(issuer: &HostileIssuer, key: &TestKey, max_bytes: usize) -> Result<(), AuthError> {
    let config = AuthConfig::empty()
        .with_issuer(Issuer::with_jwks_url(issuer.iss(), issuer.jwks_url()).expect("valid issuer"))
        .with_policy(policy(max_bytes))
        .with_insecure_http(true)
        .with_audience(AUDIENCE);

    // `algorithms` defaults to RS256, which is what `TestKey::generate` is.
    let _ = key;
    Authenticator::start(config).await.map(|_| ())
}

/// A filler JWK `pad_to` bytes of junk long. `kty: oct` is refused by
/// `convert_key`, so it inflates the document without inflating the trust
/// bundle. That is what lets a test set a body's size exactly.
fn padding(pad_to: usize) -> serde_json::Value {
    serde_json::json!({
        "kty": "oct",
        "kid": "padding",
        "k": "A".repeat(pad_to),
    })
}

/// A JWKS holding `key` plus filler, whose serialised length is reported so the
/// caller can set its cap against the exact byte count.
fn document(key: &TestKey, pad_to: usize) -> (Vec<u8>, usize) {
    let body = serde_json::to_vec(&serde_json::json!({
        "keys": [key.jwk(), padding(pad_to)],
    }))
    .expect("serialise a JWKS");
    let len = body.len();
    (body, len)
}

/// Three 4 MiB chunked members, no `Content-Length`, against a 1 MiB cap.
#[tokio::test]
async fn a_chunked_body_over_the_cap_is_refused_as_it_arrives() {
    let key = TestKey::generate("k1");
    let chunks: Vec<Vec<u8>> = (0..3).map(|_| vec![b'x'; HUGE_CHUNK]).collect();
    let sent = Plan::chunked(chunks);
    let body_bytes = sent.wire_len();
    let issuer = HostileIssuer::start(sent).await;

    let outcome = start(&issuer, &key, CAP).await;

    assert!(
        matches!(outcome, Err(AuthError::ProviderUnavailable(_))),
        "12 MiB of chunked JWKS under a 1 MiB cap must be refused, got {outcome:?}"
    );

    // The bound under test is on *streaming*, not on final length. A client
    // that read the body and then checked it would leave the responder having
    // handed over all 12 MiB. Refusing on the first chunk leaves the responder
    // stuck part-way through that chunk. 4 MiB cannot hide behind a small send
    // buffer once the peer stops reading. So the measure is how much of the
    // body the responder managed to write at all.
    issuer.settle().await;
    issuer.settle_close().await;
    assert!(
        issuer.left_body_unread(),
        "the client took the whole {body_bytes} byte body instead of hanging up, \
         so the cap bounded a check rather than the download. The responder wrote \
         {} bytes, and the peer closed clean: {}",
        issuer.sent(),
        issuer.peer_drained()
    );
    // No verdict on `sent()` here. It counts what the peer's kernel accepted,
    // and a wide receive window accepts a whole body for an application that
    // never reads it. The memory claim is asserted below in the client's own
    // words. It names the byte count the client stopped at, over the cap and
    // short of the body.

    // One fetch, not one fetch per refused chunk: the cap ends the download, it
    // does not restart it. A client that retried after refusing an oversized
    // body would take the body a second time, which is the exposure this file
    // exists to bound.
    assert_eq!(
        issuer.requests(),
        1,
        "an over-cap chunked body must cost exactly one fetch, got {}",
        issuer.requests()
    );

    // Named in the refusal: the running total the client stopped at. It is
    // over the cap and far short of the body, which is the peak-memory claim
    // in the client's own words.
    //
    // Deliberately NOT `HUGE_CHUNK`: the client's chunk boundaries are the
    // transport's, not the responder's writes. hyper fills its read buffer as
    // the socket delivers, so a 4 MiB server-side write surfaces as many
    // ~110 KB `chunk()` yields. Demanding the refusal name a 4 MiB chunk asserts
    // that the two boundaries coincide. They do not. What actually arrived
    // (cap + ~60 KB) is the stronger result. It shows the download died within
    // one transport read of the cap, rather than after 12 MiB.
    let note = refusal(outcome);
    // Asserted before it is read. The byte count is what the rest of the test
    // reasons about. So "there was none" belongs in the failure message, not in
    // a closure this path never enters.
    let stopped_at = note
        .split_whitespace()
        .find_map(|token| token.parse::<usize>().ok());
    assert!(
        stopped_at.is_some(),
        "refusal did not state a byte count: `{note}`"
    );
    let stopped_at = stopped_at.expect("asserted above");
    assert!(
        note.contains("body was"),
        "the refusal should be the streaming one, got `{note}`"
    );
    assert!(
        stopped_at > CAP && stopped_at < body_bytes,
        "the client stopped at {stopped_at} bytes: it must be over the {CAP} byte \
         cap and short of the {body_bytes} byte body, since a refusal at the far \
         end would mean the whole body was buffered first. got `{note}`"
    );
}

/// A `Content-Length` that promises 12 bytes and a body that sends 12 MiB.
#[tokio::test]
async fn a_body_that_overruns_its_declared_length_is_refused() {
    let key = TestKey::generate("k1");
    let chunks: Vec<Vec<u8>> = (0..3).map(|_| vec![b'x'; HUGE_CHUNK]).collect();
    let sent = Plan::overrun(12, chunks);
    let body_bytes = sent.wire_len();
    let issuer = HostileIssuer::start(sent).await;

    let outcome = start(&issuer, &key, CAP).await;

    // A declared length of 12 is a wave-through by construction. It is under any
    // cap anyone would configure, and it is the only number the fast path could
    // consult. Whether the response is safe therefore rests entirely on the body
    // being measured as it arrives.
    assert!(
        matches!(outcome, Err(AuthError::ProviderUnavailable(_))),
        "a body that overruns a 12-byte `Content-Length` must be refused, got {outcome:?}"
    );
    issuer.settle().await;
    issuer.settle_close().await;
    assert!(
        issuer.left_body_unread(),
        "a client that obeyed the 12-byte lie and read on would have taken all \
         {body_bytes} bytes; the responder wrote {} and the peer closed clean: {}",
        issuer.sent(),
        issuer.peer_drained()
    );

    // Refused *because of size*, not incidentally. A truncated or malformed
    // body would fail JSON parsing and prove nothing about the cap, so the
    // message has to be the cap's own.
    let note = refusal(outcome);
    assert!(
        note.contains("over the") && note.contains(&format!("{CAP} byte limit")),
        "the refusal must be the size cap's, not a JSON error arriving by luck, \
         got `{note}`"
    );
}

/// A valid JWKS that fits exactly, sent as two chunked members.
#[tokio::test]
async fn a_jwks_exactly_at_the_cap_is_accepted() {
    let key = TestKey::generate("k1");
    let (body, size) = document(&key, 2048);

    // Split in the middle, so accepting this depends on the accumulated
    // length of both halves rather than on a single chunk happening to fit.
    let middle = body.len() / 2;
    let chunks = vec![body[..middle].to_vec(), body[middle..].to_vec()];
    let issuer = HostileIssuer::start(Plan::chunked(chunks)).await;

    let outcome = start(&issuer, &key, size).await;

    assert!(
        outcome.is_ok(),
        "a JWKS of exactly {size} bytes against a {size} byte cap must be \
         accepted: the cap is inclusive, and refusing at equality would be a \
         blanket break, got {outcome:?}"
    );
    assert_eq!(
        // `chunks_sent`, not `sent`: `sent` counts framed wire bytes, which
        // exceed the body by the hex length prefixes and CRLFs chunked
        // transfer adds. Both framed writes landing is what "the client read
        // it all" means on this side of the socket.
        issuer.chunks_sent(),
        2,
        "an accepted body must have had both chunks delivered"
    );

    // Accepted *and* usable: the bytes survived reassembly across chunks.
    let auth = Authenticator::start(
        AuthConfig::empty()
            .with_issuer(Issuer::with_jwks_url(issuer.iss(), issuer.jwks_url()).expect("issuer"))
            .with_policy(policy(size))
            .with_insecure_http(true)
            .with_audience(AUDIENCE),
    )
    .await
    .expect("a second fetch of the same document");
    let claims = auth
        .authenticate(&key.sign(&key.claims(&issuer.iss(), AUDIENCE)))
        .await
        .expect("a token against a key that fit under the cap");
    assert_eq!(
        claims.sub, "user-123",
        "the key that arrived in two chunks must still verify"
    );

    // Two fetches for two authenticators, and no hidden extra attempt. Each
    // `Authenticator::start` warms its own bundle exactly once. So a count above
    // two would mean the client accepted a body and then retried it.
    issuer.settle().await;
    assert_eq!(
        issuer.requests(),
        2,
        "two authenticators against one issuer mean two fetches, got {}",
        issuer.requests()
    );
}

/// The same document, one byte too many for the cap.
#[tokio::test]
async fn a_jwks_one_byte_over_the_cap_is_refused() {
    let key = TestKey::generate("k1");
    let (body, size) = document(&key, 2048);

    let middle = body.len() / 2;
    let chunks = vec![body[..middle].to_vec(), body[middle..].to_vec()];
    let issuer = HostileIssuer::start(Plan::chunked(chunks)).await;

    // One byte under the body's exact size. That is the boundary the cap is
    // defined on, with no slack for an off-by-one in either direction to hide
    // in.
    let outcome = start(&issuer, &key, size - 1).await;

    assert!(
        matches!(outcome, Err(AuthError::ProviderUnavailable(_))),
        "a {size} byte JWKS against a {} byte cap must be refused, got {outcome:?}",
        size - 1
    );
}

/// An honest `Content-Length` over the cap, refused without the body arriving.
#[tokio::test]
async fn an_oversized_content_length_is_refused_before_the_body_is_read() {
    let key = TestKey::generate("k1");
    let mut body = Vec::with_capacity(HUGE_CHUNK);
    while body.len() < HUGE_CHUNK {
        body.extend_from_slice(b"{\"keys\":[]}");
    }
    let issuer = HostileIssuer::start(Plan::sized(body.clone())).await;

    let outcome = start(&issuer, &key, CAP).await;

    assert!(
        matches!(outcome, Err(AuthError::ProviderUnavailable(_))),
        "a 4 MiB `Content-Length` against a 1 MiB cap must be refused, got {outcome:?}"
    );

    // The distinguishing claim: this refusal is the fast path's, taken on the
    // header alone. Nothing of the body needed to be read to decide it, so the
    // message names the declared size rather than a running total.
    let note = refusal(outcome);
    assert!(
        note.contains(&format!("{} bytes", body.len())),
        "the refusal should name the advertised {HUGE_CHUNK} byte length rather \
         than a count taken while streaming, got `{note}`"
    );
    assert!(
        !note.contains("body was"),
        "`body was` is the streaming refusal's wording; seeing it here means the \
         body was read before it was refused, got `{note}`"
    );

    // And refused on a single attempt. The header fast path answers, rather than
    // falling through to a second fetch that would read the body it just
    // declined to look at.
    assert_eq!(
        issuer.requests(),
        1,
        "an advertised length over the cap must be refused without retrying, got {} \
         fetches",
        issuer.requests()
    );
}

/// A body that stops mid-document is an outage. It has to be reported as one.
///
/// Every other plan in this file sends a body that is too *big*. This one sends
/// a body that is too short. It has valid chunk framing up to the last byte
/// delivered, then the connection closes without the terminator. Nothing in the
/// response head says the provider is in trouble. It says `200 OK` with a good
/// `Content-Type`. That is what a proxy killed mid-forward looks like from here,
/// or an idle timeout on the wrong side of a load balancer.
///
/// The complaint the operator receives is the whole test. Reading to EOF and
/// parsing afterwards would report broken JSON. An operator chasing
/// `invalid value: string at line 1 column 40` then audits the realm's JWKS
/// document, when the fault is in the path to it. Refusing at the stream makes
/// the message say the connection ended. That happens on the read that came up
/// short, before the crate parses any of it.
#[tokio::test]
async fn a_jwks_whose_stream_ends_mid_document_is_reported_as_an_outage() {
    let key = TestKey::generate("k1");
    let (body, size) = document(&key, 2048);

    // A third of the document: correctly framed, far under any cap, and not a
    // parseable JWKS. Which of those two things the refusal blames is the point.
    let cut = body.len() / 3;
    let issuer = HostileIssuer::start(Plan::cut_off(vec![body[..cut].to_vec()])).await;

    let outcome = Authenticator::start(
        AuthConfig::empty()
            .with_issuer(
                Issuer::with_jwks_url(issuer.iss(), issuer.jwks_url()).expect("valid issuer"),
            )
            .with_insecure_http(true)
            .with_audience(AUDIENCE),
    )
    .await;

    let Err(err) = outcome else {
        panic!(
            "a JWKS that arrived {cut} of {size} bytes cannot be a trust bundle: \
             starting anyway means verifying tokens against keys that never got \
             here"
        );
    };

    assert!(
        matches!(err, AuthError::ProviderUnavailable(_)),
        "the provider ended the stream early, which is neither a misconfiguration \
         nor a verdict on a token: {err:?}"
    );

    let note = err.to_string();
    assert!(
        !note.contains("invalid value") && !note.contains("expected"),
        "the refusal should name the broken stream, not the JSON that never \
         finished arriving — otherwise the operator is sent to audit an identity \
         provider that is not the thing that failed: `{note}`"
    );

    // That the responder stopped short, rather than the client refusing early: it
    // delivered what it had and then closed. Without this, the test would pass on
    // a plan that never sent anything at all.
    issuer.settle().await;
    assert_eq!(
        issuer.chunks_sent(),
        1,
        "the chunk should have gone out in full, with only the terminator missing"
    );
}
