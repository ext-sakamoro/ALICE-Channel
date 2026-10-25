//! The one place the crate reads a clock.
//!
//! The datagram mode labels an initiation message with the system clock (TAI64N) so a responder can refuse an
//! older one, and the stream handshake bounds its reads with a deadline on the monotonic clock. Neither value is
//! part of a key, a transcript or any output two peers must agree on bit for bit; reading the clocks here keeps
//! the clippy `disallowed-methods` ban (clippy.toml) free of any other exception.

/// The current monotonic time
#[inline]
#[expect(
    clippy::disallowed_methods,
    reason = "the read deadline of the stream handshake; see the module comment"
)]
pub fn now() -> std::time::Instant {
    std::time::Instant::now()
}

/// The current system time
#[inline]
#[expect(
    clippy::disallowed_methods,
    reason = "the TAI64N label of a datagram initiation; see the module comment"
)]
pub fn system_now() -> std::time::SystemTime {
    std::time::SystemTime::now()
}
