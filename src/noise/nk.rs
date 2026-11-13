//! `Noise_NK_25519_ChaChaPoly_SHA256`: the handshake in which only the responder has a static key
//!
//! ```text
//! NK:
//!   <- s
//!   ...
//!   -> e, es
//!   <- e, ee
//! ```
//!
//! The initiator holds the responder's static key before it writes and never sends a static key of its own,
//! so the responder learns nothing that names the initiator: two handshakes from the same initiator share no
//! bytes. This is a second pattern over the same symmetric state, cipher state and primitives as
//! [`super::HandshakeState`] (section 5 of the framework), not another implementation of them. The public test
//! vector of this protocol pins every message and the handshake hash (`tests/noise_nk_vectors.rs`).
//!
//! Not implemented yet: every method fails fast.

use super::{Keypair, NoiseError, Transport, DH_LEN};

/// The protocol name; it is exactly 32 bytes, so it is the initial handshake hash as it stands
pub const PROTOCOL_NAME: &[u8; 32] = b"Noise_NK_25519_ChaChaPoly_SHA256";

/// The NK handshake of one side (section 5.3, pattern NK of section 7.4)
pub struct NkHandshakeState {
    _not_implemented: (),
}

impl NkHandshakeState {
    /// The initiator's handshake: `rs` is the responder's static key it already holds; it has no static key
    /// of its own, and the ephemeral key comes fresh from the operating system
    #[must_use]
    pub fn initiator(prologue: &[u8], rs: [u8; DH_LEN]) -> Self {
        let _ = (prologue, rs);
        todo!("NK initiator")
    }

    /// The responder's handshake, with `s` as this side's static key
    #[must_use]
    pub fn responder(prologue: &[u8], s: Keypair) -> Self {
        let _ = (prologue, s);
        todo!("NK responder")
    }

    /// As [`Self::initiator`] with a fixed ephemeral key, for the published test vectors only
    #[must_use]
    pub fn initiator_with_ephemeral(prologue: &[u8], rs: [u8; DH_LEN], e: Keypair) -> Self {
        let _ = (prologue, rs, e);
        todo!("NK initiator with a fixed ephemeral key")
    }

    /// As [`Self::responder`] with a fixed ephemeral key, for the published test vectors only
    #[must_use]
    pub fn responder_with_ephemeral(prologue: &[u8], s: Keypair, e: Keypair) -> Self {
        let _ = (prologue, s, e);
        todo!("NK responder with a fixed ephemeral key")
    }

    /// Write the next handshake message carrying `payload`
    ///
    /// # Errors
    /// [`NoiseError::OutOfTurn`], [`NoiseError::WeakKey`], [`NoiseError::TooLong`],
    /// [`NoiseError::Randomness`]
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let _ = payload;
        todo!("NK write_message")
    }

    /// Read the next handshake message and return its payload; a message that fails leaves the handshake as
    /// it was before
    ///
    /// # Errors
    /// [`NoiseError::OutOfTurn`], [`NoiseError::Truncated`], [`NoiseError::Decrypt`],
    /// [`NoiseError::WeakKey`], [`NoiseError::TooLong`]
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let _ = message;
        todo!("NK read_message")
    }

    /// Whether both messages have been written or read
    #[must_use]
    pub fn is_finished(&self) -> bool {
        todo!("NK is_finished")
    }

    /// The handshake hash: the transcript so far
    #[must_use]
    pub fn handshake_hash(&self) -> [u8; 32] {
        todo!("NK handshake_hash")
    }

    /// The transport keys after the second message
    ///
    /// # Errors
    /// [`NoiseError::NotFinished`] before then
    pub fn into_transport(self) -> Result<Transport, NoiseError> {
        todo!("NK into_transport")
    }
}
