//! The Noise protocol framework (revision 34), for the one protocol this crate speaks:
//! `Noise_IK_25519_ChaChaPoly_SHA256`.
//!
//! ```text
//! IK:
//!   <- s
//!   ...
//!   -> e, es, s, ss
//!   <- e, ee, se
//! ```
//!
//! The initiator holds the responder's static key before it writes; the responder's static key never
//! travels, and a first message made for another static key does not open.
//!
//! This layer does no I/O and knows nothing about identities: it turns payloads into handshake and transport
//! messages and back. The primitives are ALICE-Crypto's X25519 (a Diffie-Hellman result of all zero, from a
//! small-order key, is refused), SHA-256 with HMAC, and ChaCha20-Poly1305 as RFC 8439 defines it (the nonce is
//! 4 zero bytes followed by the 64-bit counter, little-endian). The public test vector of this protocol pins
//! every message and the handshake hash (`tests/noise_vectors.rs`).

use alice_crypto::chacha20poly1305_ietf as aead;
use alice_crypto::{random, sha256, x25519};
use zeroize::{Zeroize, Zeroizing};

/// The protocol name; it is exactly 32 bytes, so it is the initial handshake hash as it stands
pub const PROTOCOL_NAME: &[u8; 32] = b"Noise_IK_25519_ChaChaPoly_SHA256";

/// The longest Noise message (handshake or transport), in bytes
pub const MAX_MESSAGE: usize = 65_535;

const DH_LEN: usize = 32;
const TAG_LEN: usize = aead::TAG_SIZE;

/// Why a Noise message was not written or read
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseError {
    /// A message was written or read when it was the other side's turn, or after the handshake ended
    OutOfTurn,
    /// The handshake is not over, so there are no transport keys yet
    NotFinished,
    /// The message ends before the fields the pattern expects
    Truncated,
    /// A tag does not verify: the message was changed, or the two sides do not share a transcript
    Decrypt,
    /// A Diffie-Hellman result is all zero (the peer's key has small order)
    WeakKey,
    /// The message would be longer than [`MAX_MESSAGE`]
    TooLong,
    /// The 64-bit nonce counter is spent (2^64 - 1 messages under one key)
    NonceExhausted,
    /// The operating system's random source failed while making the ephemeral key
    Randomness,
}

impl core::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::OutOfTurn => "Noise message out of turn",
            Self::NotFinished => "the Noise handshake is not finished",
            Self::Truncated => "the Noise message is truncated",
            Self::Decrypt => "a Noise message does not decrypt",
            Self::WeakKey => "a Noise Diffie-Hellman result is all zero",
            Self::TooLong => "the Noise message is too long",
            Self::NonceExhausted => "the Noise nonce counter is spent",
            Self::Randomness => "the random source failed",
        })
    }
}

impl std::error::Error for NoiseError {}

/// An X25519 key pair (the secret is zeroed on drop)
#[derive(Clone)]
pub struct Keypair {
    secret: Zeroizing<[u8; DH_LEN]>,
    public: [u8; DH_LEN],
}

impl Keypair {
    /// The key pair of a 32-byte secret (clamped by X25519 itself)
    #[must_use]
    pub fn from_secret(secret: [u8; DH_LEN]) -> Self {
        let public = x25519::public_key(&secret);
        Self {
            secret: Zeroizing::new(secret),
            public,
        }
    }

    /// A fresh key pair from the operating system's random source
    ///
    /// # Errors
    /// [`NoiseError::Randomness`] when the random source fails
    pub fn generate() -> Result<Self, NoiseError> {
        let mut secret = Zeroizing::new([0u8; DH_LEN]);
        random::fill(secret.as_mut()).map_err(|_| NoiseError::Randomness)?;
        Ok(Self::from_secret(*secret))
    }

    #[must_use]
    pub const fn public(&self) -> [u8; DH_LEN] {
        self.public
    }

    fn dh(&self, peer: &[u8; DH_LEN]) -> Result<Zeroizing<[u8; DH_LEN]>, NoiseError> {
        x25519::diffie_hellman(&self.secret, peer)
            .map(Zeroizing::new)
            .map_err(|_| NoiseError::WeakKey)
    }
}

impl core::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// HKDF as the Noise specification defines it (section 4.3), with two or three outputs
fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let temp = Zeroizing::new(sha256::hmac(ck, ikm));
    let out1 = Zeroizing::new(sha256::hmac(temp.as_ref(), &[1]));
    let mut in2 = Zeroizing::new([0u8; 33]);
    in2[..32].copy_from_slice(out1.as_ref());
    in2[32] = 2;
    let out2 = Zeroizing::new(sha256::hmac(temp.as_ref(), in2.as_ref()));
    (out1, out2)
}

/// The 96-bit nonce of a counter: 32 zero bits, then the counter little-endian (section 5.1 for
/// `ChaChaPoly`); 2^64 - 1 is reserved
fn nonce_of(counter: u64) -> Result<[u8; 12], NoiseError> {
    if counter == u64::MAX {
        return Err(NoiseError::NonceExhausted);
    }
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    Ok(n)
}

/// One direction's key and nonce counter (section 5.1)
#[derive(Clone)]
struct CipherState {
    key: Option<Zeroizing<[u8; 32]>>,
    nonce: u64,
}

impl CipherState {
    const fn empty() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    fn with_key(key: [u8; 32]) -> Self {
        Self {
            key: Some(Zeroizing::new(key)),
            nonce: 0,
        }
    }

    fn nonce_bytes(&self) -> Result<[u8; 12], NoiseError> {
        nonce_of(self.nonce)
    }

    /// Seal under the explicit `counter` as the nonce (the datagram mode), without touching the counter
    fn seal_at(&self, counter: u64, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let key = self.key.as_ref().ok_or(NoiseError::NotFinished)?;
        Ok(aead::seal(key, &nonce_of(counter)?, ad, plaintext))
    }

    /// Open under the explicit `counter` as the nonce (the datagram mode)
    fn open_at(&self, counter: u64, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let key = self.key.as_ref().ok_or(NoiseError::NotFinished)?;
        aead::open(key, &nonce_of(counter)?, ad, ciphertext).map_err(|_| NoiseError::Decrypt)
    }

    fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = &self.key else {
            return Ok(plaintext.to_vec());
        };
        let n = self.nonce_bytes()?;
        let out = aead::seal(key, &n, ad, plaintext);
        self.nonce += 1;
        Ok(out)
    }

    fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let Some(key) = &self.key else {
            return Ok(ciphertext.to_vec());
        };
        let n = self.nonce_bytes()?;
        // the counter moves on only when the message opens
        let out = aead::open(key, &n, ad, ciphertext).map_err(|_| NoiseError::Decrypt)?;
        self.nonce += 1;
        Ok(out)
    }

    const fn tag_len(&self) -> usize {
        if self.key.is_some() {
            TAG_LEN
        } else {
            0
        }
    }
}

/// The chaining key, the handshake hash and the handshake's cipher (section 5.2)
struct SymmetricState {
    ck: Zeroizing<[u8; 32]>,
    h: [u8; 32],
    cipher: CipherState,
}

impl SymmetricState {
    fn new() -> Self {
        Self {
            ck: Zeroizing::new(*PROTOCOL_NAME),
            h: *PROTOCOL_NAME,
            cipher: CipherState::empty(),
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut joined = Vec::with_capacity(32 + data.len());
        joined.extend_from_slice(&self.h);
        joined.extend_from_slice(data);
        self.h = sha256::digest(&joined);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.cipher = CipherState::with_key(*k);
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ct = self.cipher.encrypt(&self.h, plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let pt = self.cipher.decrypt(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::with_key(*k1), CipherState::with_key(*k2))
    }
}

/// Which side of the handshake this is
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends the first message; knows the responder's static key beforehand
    Initiator,
    /// Receives the first message
    Responder,
}

/// The IK handshake of one side (section 5.3, pattern IK of section 7.5)
pub struct HandshakeState {
    role: Role,
    symmetric: SymmetricState,
    s: Keypair,
    e: Option<Keypair>,
    re: Option<[u8; DH_LEN]>,
    rs: Option<[u8; DH_LEN]>,
    /// the next message of the pattern, 0 or 1 (2 = finished)
    step: u8,
    /// the ephemeral key to use, when it is fixed in advance (test vectors)
    fixed_e: Option<Keypair>,
}

impl HandshakeState {
    /// The initiator's handshake: `s` is this side's static key, `rs` the responder's static key it already
    /// holds, and the ephemeral key comes fresh from the operating system
    #[must_use]
    pub fn initiator(prologue: &[u8], s: Keypair, rs: [u8; DH_LEN]) -> Self {
        Self::build(Role::Initiator, prologue, s, Some(rs), None)
    }

    /// The responder's handshake, with `s` as this side's static key
    #[must_use]
    pub fn responder(prologue: &[u8], s: Keypair) -> Self {
        Self::build(Role::Responder, prologue, s, None, None)
    }

    /// As [`Self::initiator`] with a fixed ephemeral key, for the published test vectors only (a reused
    /// ephemeral key voids the protocol's guarantees)
    #[must_use]
    pub fn initiator_with_ephemeral(
        prologue: &[u8],
        s: Keypair,
        rs: [u8; DH_LEN],
        e: Keypair,
    ) -> Self {
        Self::build(Role::Initiator, prologue, s, Some(rs), Some(e))
    }

    /// As [`Self::responder`] with a fixed ephemeral key, for the published test vectors only
    #[must_use]
    pub fn responder_with_ephemeral(prologue: &[u8], s: Keypair, e: Keypair) -> Self {
        Self::build(Role::Responder, prologue, s, None, Some(e))
    }

    fn build(
        role: Role,
        prologue: &[u8],
        s: Keypair,
        rs: Option<[u8; DH_LEN]>,
        fixed_e: Option<Keypair>,
    ) -> Self {
        let mut symmetric = SymmetricState::new();
        symmetric.mix_hash(prologue);
        // the pre-message `<- s`: both sides hash the responder's static key
        match role {
            Role::Initiator => symmetric.mix_hash(rs.as_ref().expect("the initiator holds rs")),
            Role::Responder => symmetric.mix_hash(&s.public()),
        }
        Self {
            role,
            symmetric,
            s,
            e: None,
            re: None,
            rs,
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

    fn take_ephemeral(&mut self) -> Result<Keypair, NoiseError> {
        self.fixed_e.take().map_or_else(Keypair::generate, Ok)
    }

    const fn ephemeral(&self) -> &Keypair {
        // set before any token that uses it (each message writes `e` first)
        self.e
            .as_ref()
            .expect("ephemeral key set by the first token")
    }

    /// Write the next handshake message carrying `payload`
    ///
    /// # Errors
    /// [`NoiseError::OutOfTurn`], [`NoiseError::WeakKey`], [`NoiseError::TooLong`],
    /// [`NoiseError::Randomness`]
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.write_message_with(|_| payload.to_vec())
    }

    /// Write the next handshake message, with the payload made by `payload` from the handshake hash at the
    /// point the payload is encrypted (after the message's keys and Diffie-Hellman results are mixed in)
    ///
    /// # Errors
    /// As [`Self::write_message`]
    pub fn write_message_with(
        &mut self,
        payload: impl FnOnce(&[u8; 32]) -> Vec<u8>,
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.my_turn() {
            return Err(NoiseError::OutOfTurn);
        }
        let mut out = Vec::new();
        let e = self.take_ephemeral()?;
        out.extend_from_slice(&e.public());
        self.symmetric.mix_hash(&e.public());
        self.e = Some(e);
        if self.step == 0 {
            // -> e, es, s, ss
            let rs = self.rs.ok_or(NoiseError::OutOfTurn)?;
            let es = self.ephemeral().dh(&rs)?;
            self.symmetric.mix_key(es.as_ref());
            let s_pub = self.s.public();
            out.extend_from_slice(&self.symmetric.encrypt_and_hash(&s_pub)?);
            let ss = self.s.dh(&rs)?;
            self.symmetric.mix_key(ss.as_ref());
        } else {
            // <- e, ee, se
            let re = self.re.ok_or(NoiseError::OutOfTurn)?;
            let ee = self.ephemeral().dh(&re)?;
            self.symmetric.mix_key(ee.as_ref());
            let rs = self.rs.ok_or(NoiseError::OutOfTurn)?;
            let se = self.ephemeral().dh(&rs)?;
            self.symmetric.mix_key(se.as_ref());
        }
        let mut p = payload(&self.symmetric.h);
        let sealed = self.symmetric.encrypt_and_hash(&p);
        p.zeroize();
        out.extend_from_slice(&sealed?);
        if out.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        self.step += 1;
        Ok(out)
    }

    /// Read the next handshake message and return its payload
    ///
    /// # Errors
    /// [`NoiseError::OutOfTurn`], [`NoiseError::Truncated`], [`NoiseError::Decrypt`],
    /// [`NoiseError::WeakKey`], [`NoiseError::TooLong`]
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.read_message_with_hash(message).map(|(p, _)| p)
    }

    /// Read the next handshake message and return its payload with the handshake hash at the point the
    /// payload was encrypted (the value [`Self::write_message_with`] handed the sender)
    ///
    /// A message that fails leaves the handshake as it was before (a responder that could not open the
    /// first message holds no remote static key)
    ///
    /// # Errors
    /// As [`Self::read_message`]
    pub fn read_message_with_hash(
        &mut self,
        message: &[u8],
    ) -> Result<(Vec<u8>, [u8; 32]), NoiseError> {
        if self.my_turn() || self.step > 1 {
            return Err(NoiseError::OutOfTurn);
        }
        if message.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        let take = |rest: &mut &[u8], n: usize| -> Result<Vec<u8>, NoiseError> {
            if rest.len() < n {
                return Err(NoiseError::Truncated);
            }
            let (head, tail) = rest.split_at(n);
            *rest = tail;
            Ok(head.to_vec())
        };
        // work on a copy of the transcript, kept only when the whole message opens
        let mut sym = SymmetricState {
            ck: self.symmetric.ck.clone(),
            h: self.symmetric.h,
            cipher: self.symmetric.cipher.clone(),
        };
        let mut rest = message;
        let re: [u8; DH_LEN] = take(&mut rest, DH_LEN)?
            .try_into()
            .map_err(|_| NoiseError::Truncated)?;
        sym.mix_hash(&re);
        let rs = if self.step == 0 {
            // -> e, es, s, ss (read by the responder)
            let es = self.s.dh(&re)?;
            sym.mix_key(es.as_ref());
            let enc_s = take(&mut rest, DH_LEN + sym.cipher.tag_len())?;
            let got: [u8; DH_LEN] = sym
                .decrypt_and_hash(&enc_s)?
                .try_into()
                .map_err(|_| NoiseError::Decrypt)?;
            let ss = self.s.dh(&got)?;
            sym.mix_key(ss.as_ref());
            Some(got)
        } else {
            // <- e, ee, se (read by the initiator)
            let ee = self.ephemeral().dh(&re)?;
            sym.mix_key(ee.as_ref());
            let se = self.s.dh(&re)?;
            sym.mix_key(se.as_ref());
            self.rs
        };
        if rest.len() < sym.cipher.tag_len() {
            return Err(NoiseError::Truncated);
        }
        let h = sym.h;
        let payload = sym.decrypt_and_hash(rest)?;
        self.symmetric = sym;
        self.re = Some(re);
        self.rs = rs;
        self.step += 1;
        Ok((payload, h))
    }

    /// Whether both messages have been written or read
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.step == 2
    }

    /// The handshake hash: the transcript so far (after the last message, the value both sides share)
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.symmetric.h
    }

    /// The peer's static public key: the initiator holds it from the start, the responder once it has read
    /// the first message
    #[must_use]
    pub const fn remote_static(&self) -> Option<[u8; DH_LEN]> {
        self.rs
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
        })
    }
}

/// The two transport ciphers after the handshake (section 5.2, `Split`)
pub struct Transport {
    sender: TransportSender,
    receiver: TransportReceiver,
}

impl Transport {
    /// Encrypt the next outgoing message
    ///
    /// # Errors
    /// [`NoiseError::TooLong`] when the message would exceed [`MAX_MESSAGE`],
    /// [`NoiseError::NonceExhausted`]
    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.sender.send(payload)
    }

    /// Decrypt the next incoming message (messages must arrive in order; a replayed or reordered one fails)
    ///
    /// # Errors
    /// [`NoiseError::Decrypt`], [`NoiseError::TooLong`], [`NoiseError::NonceExhausted`]
    pub fn recv(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.receiver.recv(message)
    }

    /// The handshake hash both sides share (a channel binding value)
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.sender.handshake_hash
    }

    /// Separate the two directions, so that sending and receiving can proceed independently
    #[must_use]
    pub fn split(self) -> (TransportSender, TransportReceiver) {
        (self.sender, self.receiver)
    }

    /// Use the transport keys for datagrams: each message is sealed under an explicit counter instead of
    /// the next implicit one, so messages can be opened out of order (the caller keeps the replay window).
    /// The transport is consumed, so the same keys are never used in both modes
    #[must_use]
    pub fn into_datagram(self) -> DatagramTransport {
        DatagramTransport {
            next: self.sender.cipher.nonce,
            send: self.sender.cipher,
            recv: self.receiver.cipher,
            handshake_hash: self.sender.handshake_hash,
        }
    }
}

/// The two transport ciphers for datagrams: an explicit counter per message as its nonce
pub struct DatagramTransport {
    send: CipherState,
    recv: CipherState,
    next: u64,
    handshake_hash: [u8; 32],
}

impl DatagramTransport {
    /// Seal `payload` under the next counter; returns that counter and the ciphertext
    ///
    /// # Errors
    /// [`NoiseError::TooLong`] when the ciphertext would exceed [`MAX_MESSAGE`],
    /// [`NoiseError::NonceExhausted`] once the counters are spent
    pub fn seal(&mut self, ad: &[u8], payload: &[u8]) -> Result<(u64, Vec<u8>), NoiseError> {
        if payload.len() + TAG_LEN > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        let counter = self.next;
        let out = self.send.seal_at(counter, ad, payload)?;
        self.next = counter + 1;
        Ok((counter, out))
    }

    /// Open a ciphertext sealed under `counter` (any order; the caller refuses a counter it has opened)
    ///
    /// # Errors
    /// [`NoiseError::Decrypt`], [`NoiseError::TooLong`], [`NoiseError::NonceExhausted`] for the
    /// reserved counter
    pub fn open(&self, counter: u64, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if ciphertext.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        self.recv.open_at(counter, ad, ciphertext)
    }

    /// The handshake hash both sides share
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }
}

/// The outgoing cipher of a split [`Transport`]
pub struct TransportSender {
    cipher: CipherState,
    handshake_hash: [u8; 32],
}

impl TransportSender {
    /// Encrypt the next outgoing message
    ///
    /// # Errors
    /// [`NoiseError::TooLong`] when the message would exceed [`MAX_MESSAGE`],
    /// [`NoiseError::NonceExhausted`]
    pub fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if payload.len() + TAG_LEN > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        self.cipher.encrypt(&[], payload)
    }

    /// The handshake hash both sides share
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }
}

/// The incoming cipher of a split [`Transport`]
pub struct TransportReceiver {
    cipher: CipherState,
    handshake_hash: [u8; 32],
}

impl TransportReceiver {
    /// Decrypt the next incoming message (messages must arrive in order; a replayed or reordered one fails)
    ///
    /// # Errors
    /// [`NoiseError::Decrypt`], [`NoiseError::TooLong`], [`NoiseError::NonceExhausted`]
    pub fn recv(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if message.len() > MAX_MESSAGE {
            return Err(NoiseError::TooLong);
        }
        self.cipher.decrypt(&[], message)
    }

    /// The handshake hash both sides share
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.handshake_hash
    }
}
