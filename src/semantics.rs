//! Content hash of what this crate puts on the wire for fixed keys: [`CHANNEL_SEMANTICS_ID`] (ALICE-Law G6)
//!
//! The recorded-bit tests in `tests/semantics_golden.rs` pin the bytes a handshake of fixed static and
//! ephemeral keys produces, with the transport messages after it, and the datagrams sealed after the same
//! handshake. [`CHANNEL_SEMANTICS_ID`] folds those digests with the identifier of the one Law-bearing crate
//! the channel is built on, alice-crypto's `CRYPTO_SEMANTICS_ID` (X25519, SHA-256 / HMAC / HKDF and
//! ChaCha20-Poly1305 come from it). Two builds with the same identifier put the same bytes on the wire for every
//! pinned scenario.
//!
//! # Hex form
//!
//! ```text
//! 7808060196ea5d8dd4dce277cc23da4cba5c80725a081a40c688599a76916d92
//! ```
//!
//! # Fold
//!
//! The procedure of the `SEMANTICS_ID` fold of `alice-det-math`: sort the entries by name (ascending byte
//! order), then SHA-256 over, for each entry in that order, the name length as 4 bytes big-endian (`u32`), the
//! name bytes and the 32 digest bytes.
//!
//! # Independent of cargo features
//!
//! The table and the identifier are constants that no `cfg` gates, so a build with any feature set reports the
//! same identifier. The upstream entry is recorded as hex; `tests/channel_semantics_id.rs` compares it with
//! alice-crypto's constant at the revision Cargo.toml pins.
//!
//! # Staleness
//!
//! [`CHANNEL_SEMANTICS_CHECKED_AT`] names the crate version and toolchain the pins were last checked on; a
//! different version or toolchain fails `tests/channel_semantics_id.rs` until they are checked again.

/// Decodes 64 hex digits into 32 bytes at compile time; anything else is a compile error.
const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lower-case hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "a digest is 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) * 16 + nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// The entries [`CHANNEL_SEMANTICS_ID`] folds: one per recorded-bit scenario of `tests/semantics_golden.rs`,
/// named as that file names it, and alice-crypto's identifier
pub const CHANNEL_SEMANTICS_PINS: &[(&str, [u8; 32])] = &[
    (
        "handshake and transport",
        hex32("79a6d33e6779591e9e232e40be4686eae8401aeee27a2a654a77e28d9b4f7e77"),
    ),
    (
        "datagram transport",
        hex32("d6945135bfbe87700b6d99f8da9006398dfa28cd3635c248ad99bf815040f9ff"),
    ),
    (
        "alice-crypto",
        hex32("65285bfd28e836408ac51c4989a6430b2508f25cf51e4ca30db9f3d36e26acef"),
    ),
];

/// The crate version and toolchain the pins were last checked against
pub const CHANNEL_SEMANTICS_CHECKED_AT: (&str, &str) = ("0.1.0", "1.98.1");

/// Content hash of what this crate puts on the wire for fixed keys: the fold of [`CHANNEL_SEMANTICS_PINS`]
/// described in the [module documentation](self)
pub const CHANNEL_SEMANTICS_ID: [u8; 32] =
    hex32("7808060196ea5d8dd4dce277cc23da4cba5c80725a081a40c688599a76916d92");
