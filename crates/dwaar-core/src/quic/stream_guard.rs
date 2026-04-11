// Copyright (C) 2026 Permanu
// SPDX-License-Identifier: BSL-1.1
//
// This file is part of Dwaar — https://dwaar.dev
// Licensed under the Business Source License 1.1

//! Streaming-bridge guards: per-chunk timeouts, wall-clock body deadlines,
//! and H2 send-stream capacity gating.
//!
//! The HTTP/3 → upstream bridge streams DATA frames chunk-by-chunk in both
//! directions. Without guards, three failure modes can stall or OOM the
//! process:
//!
//! 1. **Slow-loris peers** — a client or upstream that trickles bytes below
//!    the timeout threshold of the outer round-trip wrapper keeps a stream
//!    open indefinitely. Solved by per-chunk read timeouts (Guardrail #29)
//!    *and* a wall-clock body deadline that bounds the aggregate transfer
//!    time regardless of chunk arrival rate.
//! 2. **H2 internal queueing** — `h2::SendStream::send_data` buffers
//!    unboundedly when the peer's flow-control window is closed (the
//!    `h2` crate documents this: "sending large amounts of data without
//!    reserving capacity before hand could result in large amounts of
//!    data being buffered in memory"). Solved by reserving capacity for
//!    each chunk and awaiting `poll_capacity` before calling `send_data`,
//!    so back-pressure propagates upstream to the H3 client.
//! 3. **Unbounded request body** — the classic Guardrail #28 case,
//!    enforced by `MAX_REQUEST_BODY`.
//!
//! The constants live here so both the HTTP/1.1 and HTTP/2 upstream paths
//! use identical limits. Changing them in one place changes both bridges.

use std::future::poll_fn;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use tokio::time::error::Elapsed;

/// Hard wall-clock cap on a single body transfer (request or response).
///
/// Even if every individual chunk arrives before [`CHUNK_READ_TIMEOUT`],
/// a peer pacing 1 byte/chunk can still keep a stream alive forever.
/// This deadline bounds the *aggregate* transfer time — five minutes is
/// generous for legitimate large uploads on slow links while still
/// rejecting pathological slow-loris streams.
pub const BODY_WALL_CLOCK: Duration = Duration::from_secs(5 * 60);

/// Maximum time we'll wait for a single H3 DATA chunk to arrive from
/// the client, or a single upstream buffer fill to land on our socket.
///
/// 30 seconds matches [`super::bridge::UPSTREAM_TIMEOUT_SECS`] — the
/// idea is that *the slowest legitimate client chunk* should not take
/// longer than the outer round-trip limit. If a chunk stalls past this,
/// the peer is effectively dead.
pub const CHUNK_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time we'll wait for H2 flow-control capacity to become
/// available for a single upstream send. A slow or stalled upstream
/// reader translates into a closed H2 window; if the window stays
/// closed this long we bail rather than pile chunks into h2's internal
/// queue.
pub const H2_CAPACITY_WAIT: Duration = Duration::from_secs(30);

/// Tracks how much time is left on a body transfer's wall-clock budget.
///
/// Every per-chunk `recv_data()` and `read_into_buf()` call should be
/// wrapped with [`BodyDeadline::remaining`] so the effective timeout
/// is `min(CHUNK_READ_TIMEOUT, time remaining on BODY_WALL_CLOCK)`.
/// Once the wall-clock runs out, `remaining` returns `Duration::ZERO`
/// and the next timeout wrapper fires immediately with [`Elapsed`].
#[derive(Debug, Clone, Copy)]
pub struct BodyDeadline {
    expires_at: Instant,
}

impl BodyDeadline {
    /// Start a new deadline of [`BODY_WALL_CLOCK`] from `now`.
    pub fn new() -> Self {
        Self {
            expires_at: Instant::now() + BODY_WALL_CLOCK,
        }
    }

    /// Effective timeout for the next I/O operation: the smaller of
    /// [`CHUNK_READ_TIMEOUT`] and the remaining wall-clock.
    #[inline]
    pub fn next_chunk_timeout(&self) -> Duration {
        self.expires_at
            .saturating_duration_since(Instant::now())
            .min(CHUNK_READ_TIMEOUT)
    }

    /// True once the wall-clock budget is fully consumed.
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

impl Default for BodyDeadline {
    fn default() -> Self {
        Self::new()
    }
}

/// Wait for the H2 `SendStream` to have at least `need` bytes of
/// flow-control capacity, bounded by [`H2_CAPACITY_WAIT`].
///
/// The caller must have already called
/// `send_stream.reserve_capacity(need)` — this function only awaits
/// the asynchronous grant. When the future resolves, subsequent
/// `send_data` calls up to `need` bytes are guaranteed not to enqueue
/// unbounded data in h2's internal buffer.
///
/// # Why a helper?
///
/// `h2::SendStream::poll_capacity` returns `Poll<Option<Result<usize,
/// h2::Error>>>` — a four-level nested outcome that's painful to
/// read inline. Wrapping it once here keeps the bridge readable.
pub async fn await_h2_capacity(
    send_stream: &mut h2::SendStream<Bytes>,
    need: usize,
) -> Result<(), H2CapacityError> {
    if need == 0 {
        return Ok(());
    }
    if send_stream.capacity() >= need {
        return Ok(());
    }

    let waited = tokio::time::timeout(H2_CAPACITY_WAIT, async {
        loop {
            if send_stream.capacity() >= need {
                return Ok::<(), h2::Error>(());
            }
            match poll_fn(|cx| send_stream.poll_capacity(cx)).await {
                // `poll_capacity` yields the new total capacity. Loop
                // back and check whether it's enough for `need`.
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                // `None` means the stream has been reset — treat as
                // a normal h2 error so the caller can evict the
                // connection from the pool.
                None => {
                    return Err(h2::Error::from(h2::Reason::STREAM_CLOSED));
                }
            }
        }
    })
    .await;

    match waited {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(H2CapacityError::H2(e)),
        Err(_elapsed) => Err(H2CapacityError::Timeout),
    }
}

/// Errors from [`await_h2_capacity`].
#[derive(Debug, thiserror::Error)]
pub enum H2CapacityError {
    #[error("h2 flow-control error while waiting for capacity: {0}")]
    H2(h2::Error),

    #[error("upstream H2 window did not open within {H2_CAPACITY_WAIT:?}")]
    Timeout,
}

/// `SendRequest` is carried through the bridge for fast-path retries —
/// expose the type alias here so both bridges import it from one place.
pub type H2Sender = SendRequest<Bytes>;

/// Convenience: run `fut` with the effective deadline from `deadline`.
///
/// Returns the inner error if the future fails, or `Err(Elapsed)` when
/// the wall-clock / per-chunk budget fires. The caller is responsible
/// for mapping `Elapsed` into its own error type.
#[inline]
pub async fn with_chunk_deadline<F, T>(deadline: BodyDeadline, fut: F) -> Result<T, Elapsed>
where
    F: std::future::Future<Output = T>,
{
    // `tokio::time::timeout` with a zero or near-zero duration still
    // polls `fut` once before declaring elapsed, which matches what
    // we want: an already-ready future returns its value even if the
    // wall-clock has just expired.
    let budget = deadline.next_chunk_timeout();
    tokio::time::timeout(budget, fut).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: construct a deadline that expires at a caller-supplied
    /// `Instant`. Only used by tests — production code always goes
    /// through `BodyDeadline::new()`.
    fn deadline_expiring_at(expires_at: Instant) -> BodyDeadline {
        BodyDeadline { expires_at }
    }

    #[test]
    fn body_deadline_caps_chunk_timeout_when_wall_clock_is_far_away() {
        // Deadline with 10 minutes of wall-clock — well above CHUNK_READ_TIMEOUT.
        let d = deadline_expiring_at(Instant::now() + Duration::from_secs(600));
        // Effective per-chunk budget should be clamped to CHUNK_READ_TIMEOUT.
        assert_eq!(d.next_chunk_timeout(), CHUNK_READ_TIMEOUT);
        assert!(!d.is_exhausted());
    }

    #[test]
    fn body_deadline_shrinks_chunk_timeout_as_wall_clock_nears() {
        // Deadline with 5s of wall-clock remaining — less than the
        // per-chunk cap, so the wall-clock should win.
        let d = deadline_expiring_at(Instant::now() + Duration::from_secs(5));
        let budget = d.next_chunk_timeout();
        assert!(budget <= Duration::from_secs(5));
        assert!(budget > Duration::ZERO);
    }

    #[test]
    fn body_deadline_exhausted_reports_zero_budget() {
        // Deadline 10ms in the past — already exhausted.
        let past = Instant::now()
            .checked_sub(Duration::from_millis(10))
            .expect("subtract 10ms from monotonic clock");
        let d = deadline_expiring_at(past);
        assert_eq!(d.next_chunk_timeout(), Duration::ZERO);
        assert!(d.is_exhausted());
    }

    #[tokio::test]
    async fn with_chunk_deadline_fires_on_slow_future() {
        // Short-fuse deadline (100ms) and an indefinitely-pending future.
        let d = deadline_expiring_at(Instant::now() + Duration::from_millis(100));
        let pending = std::future::pending::<()>();
        let outcome = with_chunk_deadline(d, pending).await;
        assert!(outcome.is_err(), "pending future should have timed out");
    }

    #[tokio::test]
    async fn await_h2_capacity_with_live_stream() {
        // Stand up a minimal H2 server that accepts and responds.
        use h2::server;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut conn = server::handshake(tcp).await.expect("handshake");
            while let Some(Ok((_req, mut respond))) = conn.accept().await {
                let response = http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("build");
                let mut send = respond.send_response(response, false).expect("send resp");
                send.send_data(Bytes::from_static(b"ok"), true)
                    .expect("data");
            }
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (sender, connection) = h2::client::handshake(tcp).await.expect("client handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut sender = sender.ready().await.expect("sender ready");

        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri("http://localhost/t")
            .body(())
            .expect("request");
        let (_resp, mut send_stream) = sender.send_request(req, false).expect("send request");

        // Reserve some capacity and wait for it. Because the server is
        // willing to accept body data, this should resolve almost
        // immediately — well under H2_CAPACITY_WAIT.
        send_stream.reserve_capacity(1024);
        await_h2_capacity(&mut send_stream, 1024)
            .await
            .expect("capacity should be granted");
        assert!(send_stream.capacity() >= 1024);
    }
}
