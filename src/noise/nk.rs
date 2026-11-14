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

use zeroize::Zeroize;

use super::{
    Keypair, NoiseError, Role, SymmetricState, Transport, TransportReceiver, TransportSender,
    DH_LEN, MAX_MESSAGE,
};

/// The protocol name; it is exactly 32 bytes, so it is the initial handshake hash as it stands
pub const PROTOCOL_NAME: &[u8; 32] = b"Noise_NK_25519_ChaChaPoly_SHA256";

/// The NK handshake of one side (section 5.3, pattern NK of section 7.4)
pub struct NkHandshakeState {
    role: Role,
    symmetric: SymmetricState,
    /// the responder's static key (the responder's own; for the initiator, only its public half is held)
    s: Option<Keypair>,
    rs: [u8; DH_LEN],
    e: Option<Keypair>,
    re: Option<[u8; DH_LEN]>,
    /// the next message of the pattern, 0 or 1 (2 = finished)
    step: u8,
    fixed_e: Option<Keypair>,
}

impl NkHandshakeState {
    /// The initiator's handshake: `rs` is the responder's static key it already holds; it has no static key
    /// of its own, and the ephemeral key comes fresh from the operating system
    #[must_use]
    pub fn initiator(prologue: &[u8], rs: [u8; DH_LEN]) -> Self {
        Self::build(Role::Initiator, prologue, None, rs, None)
    }

    /// The responder's handshake, with `s` as this side's static key
    #[must_use]
    pub fn responder(prologue: &[u8], s: Keypair) -> Self {
        let rs = s.public();
        Self::build(Role::Responder, prologue, Some(s), rs, None)
    }

    /// As [`Self::initiator`] with a fixed ephemeral key, for the published test vectors only (a reused
    /// ephemeral key voids the protocol's guarantees)
    #[must_use]
    pub fn initiator_with_ephemeral(prologue: &[u8], rs: [u8; DH_LEN], e: Keypair) -> Self {
        Self::build(Role::Initiator, prologue, None, rs, Some(e))
    }

    /// As [`Self::responder`] with a fixed ephemeral key, for the published test vectors only
    #[must_use]
    pub fn responder_with_ephemeral(prologue: &[u8], s: Keypair, e: Keypair) -> Self {
        let rs = s.public();
        Self::build(Role::Responder, prologue, Some(s), rs, Some(e))
    }

    fn build(
        role: Role,
        prologue: &[u8],
        s: Option<Keypair>,
        rs: [u8; DH_LEN],
        fixed_e: Option<Keypair>,
    ) -> Self {
        let mut symmetric = SymmetricState::for_protocol(PROTOCOL_NAME);
        symmetric.mix_hash(prologue);
        // the pre-message `<- s`: both sides hash the responder's static key
        symmetric.mix_hash(&rs);
        Self {
            role,
            symmetric,
            s,
            rs,
            e: None,
            re: None,
            step: 0,
            fixed_e,
        }
    }

    const fn my_turn(&self) -> bool {
        match self.role {
            Role::Initiator => self.step == 0,
            Role::Responder => self.step == 1,
        }
    }

    /// Write the next handshake message carrying `payload`
    ///
    /// # Errors
    /// [`NoiseError::OutOfTurn`], [`NoiseError::WeakKey`], [`NoiseError::TooLong`],
    /// [`NoiseError::Randomness`]
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.my_turn() {
            return Err(NoiseError::OutOfTurn);
        }
        let fixed = self.fixed_e.take();
        #[cfg(test)]
        let fixed = fixed.or_else(test_ephemeral::take);
        let e = fixed.map_or_else(Keypair::generate, Ok)?;
        let mut out = e.public().to_vec();
        // work on a copy, kept only when the whole message is written
        let mut sym = self.symmetric.clone_state();
        sym.mix_hash(&e.public());
        if self.step == 0 {
            // -> e, es
            let es = e.dh(&self.rs)?;
            sym.mix_key(es.as_ref());
        } else {
            // <- e, ee
            let re = self.re.ok_or(NoiseError::OutOfTurn)?;
            let ee = e.dh(&re)?;
            sym.mix_key(ee.as_ref());
        }
        let mut p = payload.to_vec();
        let sealed = sym.encrypt_and_hash(&p);
        p.zeroize();
        out.extend_from_slice(&sealed?);
        if out.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        self.symmetric = sym;
        self.e = Some(e);
        self.step += 1;
        Ok(out)
    }

    /// Read the next handshake message and return its payload; a message that fails leaves the handshake as
    /// it was before
    ///
    /// # Errors
    /// [`NoiseError::OutOfTurn`], [`NoiseError::Truncated`], [`NoiseError::Decrypt`],
    /// [`NoiseError::WeakKey`], [`NoiseError::TooLong`]
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.my_turn() || self.step > 1 {
            return Err(NoiseError::OutOfTurn);
        }
        if message.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        if message.len() < DH_LEN {
            return Err(NoiseError::Truncated);
        }
        let (re_bytes, rest) = message.split_at(DH_LEN);
        let mut re = [0u8; DH_LEN];
        re.copy_from_slice(re_bytes);
        let mut sym = self.symmetric.clone_state();
        sym.mix_hash(&re);
        if self.step == 0 {
            // -> e, es (read by the responder)
            let s = self.s.as_ref().ok_or(NoiseError::OutOfTurn)?;
            let es = s.dh(&re)?;
            sym.mix_key(es.as_ref());
        } else {
            // <- e, ee (read by the initiator)
            let e = self.e.as_ref().ok_or(NoiseError::OutOfTurn)?;
            let ee = e.dh(&re)?;
            sym.mix_key(ee.as_ref());
        }
        if rest.len() < sym.cipher.tag_len() {
            return Err(NoiseError::Truncated);
        }
        let payload = sym.decrypt_and_hash(rest)?;
        self.symmetric = sym;
        self.re = Some(re);
        self.step += 1;
        Ok(payload)
    }

    /// Whether both messages have been written or read
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.step == 2
    }

    /// The handshake hash: the transcript so far
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.symmetric.h
    }

    /// The transport keys after the second message
    ///
    /// # Errors
    /// [`NoiseError::NotFinished`] before then
    pub fn into_transport(self) -> Result<Transport, NoiseError> {
        if !self.is_finished() {
            return Err(NoiseError::NotFinished);
        }
        let (c1, c2) = self.symmetric.split();
        let (send, recv) = match self.role {
            Role::Initiator => (c1, c2),
            Role::Responder => (c2, c1),
        };
        let handshake_hash = self.symmetric.h;
        Ok(Transport {
            sender: TransportSender {
                cipher: send,
                handshake_hash,
            },
            receiver: TransportReceiver {
                cipher: recv,
                handshake_hash,
            },
            epoch: 0,
        })
    }
}

/// A test-only source of the next ephemeral key, so the stream channel built on this handshake can be run with
/// fixed keys and its bytes recorded (per thread: each side of a test runs on its own thread)
#[cfg(test)]
pub(crate) mod test_ephemeral {
    use super::Keypair;
    use std::cell::RefCell;

    thread_local! {
        static NEXT: RefCell<Option<Keypair>> = const { RefCell::new(None) };
    }

    /// Use `e` as the next ephemeral key this thread's NK handshake writes
    pub fn set(e: Keypair) {
        NEXT.with(|n| *n.borrow_mut() = Some(e));
    }

    pub(super) fn take() -> Option<Keypair> {
        NEXT.with(|n| n.borrow_mut().take())
    }
}
