//! The clocks the crate reads, given by the caller.
//!
//! The datagram mode labels an initiation message with the wall clock (TAI64N) so a responder can refuse an
//! older one, and the stream handshake bounds its reads with deadlines on a monotonic clock. Neither value is
//! part of a key, a transcript or any output two peers must agree on bit for bit.
//!
//! Every reading goes through a [`Clock`]. Off WebAssembly with no OS (`wasm32-unknown-unknown`) the
//! constructors without a clock argument use `SystemClock` (the standard library's clocks). On that target
//! the standard library has no clock (reading one panics), so there is no `SystemClock` and no constructor
//! without a clock: the host supplies one (in a JavaScript host, from `performance.now()` and `Date.now()`),
//! and code that does not is a compile error rather than a panic. Reading the standard clocks only here keeps
//! the clippy `disallowed-methods` ban (clippy.toml) free of any other exception.

use std::time::{Duration, SystemTime};

/// A source of time for a channel
pub trait Clock {
    /// Monotonic time since an origin of the clock's choosing (only differences are used); it must not go
    /// backwards
    fn now(&self) -> Duration;

    /// The wall clock
    fn system_now(&self) -> SystemTime;
}

impl<C: Clock + ?Sized> Clock for &C {
    fn now(&self) -> Duration {
        (**self).now()
    }

    fn system_now(&self) -> SystemTime {
        (**self).system_now()
    }
}

/// The standard library's clocks
///
/// [`std::time::Instant`] (as the time since the first reading in the process) and
/// [`std::time::SystemTime`]. Not on `wasm32-unknown-unknown`, where the standard library has no clock
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Clock for SystemClock {
    #[expect(
        clippy::disallowed_methods,
        reason = "the read deadlines of the stream handshake; see the module comment"
    )]
    fn now(&self) -> Duration {
        static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        let origin = *ORIGIN.get_or_init(std::time::Instant::now);
        std::time::Instant::now().saturating_duration_since(origin)
    }

    #[expect(
        clippy::disallowed_methods,
        reason = "the TAI64N label of a datagram initiation; see the module comment"
    )]
    fn system_now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// The clock type of a channel made without a clock argument: [`SystemClock`]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub type DefaultClock = SystemClock;

/// The clock type of a channel made without a clock argument: none on `wasm32-unknown-unknown`
///
/// This type has no value and is not a [`Clock`]: a channel there is made with `connect_with_clock` /
/// `accept_with_clock`
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub type DefaultClock = NoDefaultClock;

/// No clock: the standard library has none on `wasm32-unknown-unknown`, so the host must supply one
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoDefaultClock {}
