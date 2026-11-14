//! Suspending a [`Transport`] to bytes and resuming it, for a host that handles each message in a separate
//! callback and may be evicted and restarted between callbacks
//!
//! [`Transport::suspend`] seals the two transport keys, the two nonce counters, the handshake hash and the
//! channel's epoch under a key the host supplies ([`SuspendKey`]); [`Transport::resume`] opens them again.
//! The sealed form is ChaCha20-Poly1305 (RFC 8439) under `HMAC-SHA256(host key, SUSPEND_KEY_LABEL)`, with a
//! fresh random nonce per suspension and the header as associated data, so a copy that was edited, forged
//! without the host key, or sealed under another host key is refused, and the keys cannot be read from
//! where the host keeps the copy.
//!
//! # Layout (version 2, [`SUSPENDED_LEN`] = 166 bytes)
//!
//! ```text
//! header (38 bytes, the associated data):
//!   version u8 (= 2) | phase u8 (0 = transport, 1 = awaiting the key confirmation)
//!   | channel id [u8; 16] (the first 16 bytes of the handshake hash, [`ChannelId`])
//!   | epoch u64 LE | nonce [u8; 12]
//! sealed (112 + 16 bytes):
//!   send key [u8; 32] | send nonce u64 LE | receive key [u8; 32] | receive nonce u64 LE | handshake hash [u8; 32]
//!   | tag [u8; 16]
//! ```
//!
//! Version 1 (150 bytes, no channel id) is refused with [`ResumeError::Version`]: the version byte is read
//! before the length, so an older copy is named as such.
//!
//! # Nonces: the host's rule
//!
//! A transport nonce must never be used twice under one key. Resuming the same copy twice would do exactly
//! that: both resumed transports would seal their next message under the same nonce. So every copy carries
//! its channel's epoch, and the host keeps one number per channel beside it, the floor (0 for a channel
//! fresh from its handshake). [`Transport::resume`] refuses a copy whose epoch is below the floor
//! ([`ResumeError::Stale`]) and hands back a [`Resumed`] whose [`Resumed::next_floor`] is one above the
//! copy's epoch. **The host must persist that floor before any ciphertext leaves and before any received
//! message is acted on**; only then may it call [`Resumed::floor_persisted`] and use the transport. The next
//! suspension carries the new epoch, so it is accepted at the new floor, and every older copy is refused.
//! A host evicted after a message left but before it stored the next copy finds only an older copy below
//! its floor: the channel is lost (a new handshake is needed), but no nonce is reused.
//!
//! **Persisting the floor first is the only protection.** A copy used anyway, in breach of the rule, seals
//! under a (key, nonce) pair that has already been used: anyone who saw both ciphertexts has the XOR of the
//! two plaintexts, and Poly1305 forgeries under that key become possible. The peer refuses the second message
//! (its nonce is behind the peer's counter), but that only detects the breach after the fact; it does not undo
//! the leak.
//!
//! # Channels
//!
//! The floor belongs to one channel, and a new handshake starts again at 0, so a floor alone cannot tell an
//! earlier channel's copy (left in a storage slot the host reuses) from a fresh one. Every copy therefore
//! names its channel in the authenticated header ([`ChannelId`], from [`Transport::channel_id`] or
//! [`crate::AwaitConfirmation::channel_id`]); the host stores the id when the handshake completes and passes
//! it to `resume`, which refuses a copy of another channel ([`ResumeError::OtherChannel`]). An edited id
//! breaks the tag ([`ResumeError::Authentication`]).

use alice_crypto::chacha20poly1305_ietf as aead;
use alice_crypto::{random, sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{CipherState, NoiseError, Transport, TransportReceiver, TransportSender};

/// The version byte of the layout this crate writes and reads
pub const SUSPENDED_VERSION: u8 = 2;

/// The length of a suspended transport, in bytes
pub const SUSPENDED_LEN: usize = HEADER_LEN + PLAIN_LEN + aead::TAG_SIZE;

/// The label of the key derivation: the sealing key is `HMAC-SHA256(host key, SUSPEND_KEY_LABEL)`
pub const SUSPEND_KEY_LABEL: &[u8] = b"alice-channel suspended transport v1";

const HEADER_LEN: usize = 1 + 1 + CHANNEL_ID_LEN + 8 + aead::NONCE_SIZE;
const ID_AT: core::ops::Range<usize> = 2..2 + CHANNEL_ID_LEN;
const EPOCH_AT: core::ops::Range<usize> = ID_AT.end..ID_AT.end + 8;
const NONCE_AT: core::ops::Range<usize> = EPOCH_AT.end..HEADER_LEN;
const PLAIN_LEN: usize = 32 + 8 + 32 + 8 + 32;

/// What a suspended copy holds: an open transport, or a responder's transport still waiting for the
/// initiator's key confirmation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Transport = 0,
    AwaitingConfirmation = 1,
}

/// Why a suspended transport was refused
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeError {
    /// The bytes are not [`SUSPENDED_LEN`] long (cut short, or with bytes after the end)
    Length {
        /// [`SUSPENDED_LEN`]
        expected: usize,
        /// the length given
        got: usize,
    },
    /// The version byte is not [`SUSPENDED_VERSION`]
    Version(u8),
    /// The tag does not verify under this host key: the copy was changed, forged, or sealed under another key
    Authentication,
    /// The copy holds another phase than the one being resumed (a transport waiting for its key
    /// confirmation is resumed as such, not as an open transport, and the other way round)
    Phase(u8),
    /// The copy's epoch is below the host's floor: an older copy of a channel that has moved on
    Stale {
        /// the copy's epoch
        epoch: u64,
        /// the floor the host gave
        floor: u64,
    },
    /// The copy's epoch is the last one: it cannot be resumed again
    EpochExhausted,
    /// The copy belongs to another channel than the one the host expected (a copy left from an earlier
    /// handshake in the same storage slot)
    OtherChannel {
        /// the channel the host expected
        expected: ChannelId,
        /// the channel the copy names
        got: ChannelId,
    },
}

impl core::fmt::Display for ResumeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Length { expected, got } => {
                write!(f, "a suspended transport is {expected} bytes, got {got}")
            }
            Self::Version(v) => write!(f, "unknown suspended transport version {v}"),
            Self::Authentication => f.write_str("the suspended transport does not authenticate"),
            Self::Phase(p) => write!(f, "the suspended transport holds phase {p}"),
            Self::Stale { epoch, floor } => write!(
                f,
                "the suspended transport is older (epoch {epoch}) than the floor {floor}"
            ),
            Self::EpochExhausted => f.write_str("the suspended transport's epoch is spent"),
            Self::OtherChannel { expected, got } => write!(
                f,
                "the suspended transport belongs to channel {got}, not {expected}"
            ),
        }
    }
}

impl std::error::Error for ResumeError {}

/// The identity of one channel: the first [`CHANNEL_ID_LEN`] bytes of its handshake hash
///
/// The handshake hash is a SHA-256 transcript that includes both sides' fresh ephemeral keys, so no one can
/// choose it. 16 bytes (128 bits) make two channels of one host share an id only after about 2^64 channels
/// (the birthday bound), and forcing a match with a given id costs 2^128 handshakes, the strength of the
/// AEAD's own 128-bit tag. It is not secret: a host may store it beside the copy, in clear
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId([u8; CHANNEL_ID_LEN]);

/// The length of a [`ChannelId`], in bytes
pub const CHANNEL_ID_LEN: usize = 16;

impl ChannelId {
    /// The id of the channel whose handshake hash is `handshake_hash`
    #[must_use]
    pub fn of_handshake_hash(handshake_hash: &[u8; 32]) -> Self {
        let mut id = [0u8; CHANNEL_ID_LEN];
        id.copy_from_slice(&handshake_hash[..CHANNEL_ID_LEN]);
        Self(id)
    }

    /// An id the host stored ([`Self::as_bytes`])
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHANNEL_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The bytes to store
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHANNEL_ID_LEN] {
        &self.0
    }
}

impl From<[u8; CHANNEL_ID_LEN]> for ChannelId {
    fn from(bytes: [u8; CHANNEL_ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for ChannelId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Display for ChannelId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// The host's key for sealing suspended transports (zeroed on drop; no equality and no display, so it is
/// neither compared in variable time nor printed)
pub struct SuspendKey(Zeroizing<[u8; 32]>);

impl SuspendKey {
    /// A host key of 32 bytes (from the host's own secret storage)
    #[must_use]
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    fn sealing_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(sha256::hmac(self.0.as_ref(), SUSPEND_KEY_LABEL))
    }
}

impl core::fmt::Debug for SuspendKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SuspendKey(..)")
    }
}

/// A fixed-size buffer zeroed on drop
struct Scrub<const N: usize>([u8; N]);

impl<const N: usize> Drop for Scrub<N> {
    fn drop(&mut self) {
        self.0.zeroize();
        probe::record(&self.0);
    }
}

/// A sealed transport: [`SUSPENDED_LEN`] bytes, zeroed on drop
pub struct SuspendedTransport {
    bytes: Scrub<SUSPENDED_LEN>,
}

impl SuspendedTransport {
    /// Read a suspended transport the host kept; only its length and version are checked here (the rest
    /// when it is resumed)
    ///
    /// # Errors
    /// [`ResumeError::Length`], [`ResumeError::Version`]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ResumeError> {
        let mut copy = Scrub([0u8; SUSPENDED_LEN]);
        // the version first: a copy of another layout is named as such, whatever its length
        if let Some(&v) = bytes.first() {
            if v != SUSPENDED_VERSION {
                return Err(ResumeError::Version(v));
            }
        }
        if bytes.len() != SUSPENDED_LEN {
            return Err(ResumeError::Length {
                expected: SUSPENDED_LEN,
                got: bytes.len(),
            });
        }
        copy.0.copy_from_slice(bytes);
        Ok(Self { bytes: copy })
    }

    /// The bytes to keep
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.bytes.0
    }

    /// The channel the header names (not authenticated until the copy is resumed): for a host that finds
    /// its stored id by the copy, the id still has to match what it expects
    #[must_use]
    pub fn channel_id(&self) -> ChannelId {
        let mut id = [0u8; CHANNEL_ID_LEN];
        id.copy_from_slice(&self.bytes.0[ID_AT]);
        ChannelId(id)
    }

    /// The epoch the header names (not authenticated until the copy is resumed)
    #[must_use]
    pub fn epoch(&self) -> u64 {
        let mut e = [0u8; 8];
        e.copy_from_slice(&self.bytes.0[EPOCH_AT]);
        u64::from_le_bytes(e)
    }
}

impl core::fmt::Debug for SuspendedTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SuspendedTransport")
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

/// A resumed value that may not be used until the host has persisted [`Self::next_floor`]
#[must_use = "persist next_floor, then call floor_persisted"]
pub struct Resumed<T> {
    value: T,
    next_floor: u64,
}

impl<T> Resumed<T> {
    /// The floor the host must persist for this channel before using the value: one above the epoch of the
    /// copy just resumed
    #[must_use]
    pub const fn next_floor(&self) -> u64 {
        self.next_floor
    }

    /// The value, once the host has persisted [`Self::next_floor`]
    #[must_use]
    pub fn floor_persisted(self) -> T {
        self.value
    }

    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Resumed<U> {
        Resumed {
            value: f(self.value),
            next_floor: self.next_floor,
        }
    }
}

impl Transport {
    /// The id of this channel, for the host to store beside its suspended copies and pass to
    /// [`Self::resume`]
    #[must_use]
    pub fn channel_id(&self) -> ChannelId {
        ChannelId::of_handshake_hash(&self.sender.handshake_hash)
    }

    /// Seal this transport under the host key, for a host that is about to be evicted
    ///
    /// # Errors
    /// [`NoiseError::Randomness`] when the random source fails
    pub fn suspend(self, key: &SuspendKey) -> Result<SuspendedTransport, NoiseError> {
        seal(self, Phase::Transport, key)
    }

    /// Open a suspended transport of the channel `channel`, refusing a copy below the host's `floor` for it
    /// (see the module documentation for the rule the host follows)
    ///
    /// # Errors
    /// [`ResumeError::Authentication`], [`ResumeError::Phase`], [`ResumeError::OtherChannel`],
    /// [`ResumeError::Stale`], [`ResumeError::EpochExhausted`]
    pub fn resume(
        suspended: &SuspendedTransport,
        key: &SuspendKey,
        floor: u64,
        channel: ChannelId,
    ) -> Result<Resumed<Self>, ResumeError> {
        open(suspended, Phase::Transport, key, floor, channel)
    }
}

/// Seal `transport` (consumed: its keys are zeroed as it drops) with its phase and epoch
pub(crate) fn seal(
    transport: Transport,
    phase: Phase,
    key: &SuspendKey,
) -> Result<SuspendedTransport, NoiseError> {
    let send = &transport.sender.cipher;
    let recv = &transport.receiver.cipher;
    let (Some(send_key), Some(recv_key)) = (send.key.as_ref(), recv.key.as_ref()) else {
        return Err(NoiseError::NotFinished);
    };
    let mut plain = Scrub([0u8; PLAIN_LEN]);
    plain.0[0..32].copy_from_slice(send_key.as_ref());
    plain.0[32..40].copy_from_slice(&send.nonce.to_le_bytes());
    plain.0[40..72].copy_from_slice(recv_key.as_ref());
    plain.0[72..80].copy_from_slice(&recv.nonce.to_le_bytes());
    plain.0[80..112].copy_from_slice(&transport.sender.handshake_hash);

    let mut out = Scrub([0u8; SUSPENDED_LEN]);
    out.0[0] = SUSPENDED_VERSION;
    out.0[1] = phase as u8;
    out.0[ID_AT].copy_from_slice(transport.channel_id().as_bytes());
    out.0[EPOCH_AT].copy_from_slice(&transport.epoch.to_le_bytes());
    random::fill(&mut out.0[NONCE_AT]).map_err(|_| NoiseError::Randomness)?;
    let mut nonce = [0u8; aead::NONCE_SIZE];
    nonce.copy_from_slice(&out.0[NONCE_AT]);
    let sealed = aead::seal(&key.sealing_key(), &nonce, &out.0[..HEADER_LEN], &plain.0);
    out.0[HEADER_LEN..].copy_from_slice(&sealed);
    // the transport's keys are zeroed as it drops
    drop(transport);
    Ok(SuspendedTransport { bytes: out })
}

/// Open `suspended` as `phase`, refusing it below `floor`; the transport comes back one epoch later
pub(crate) fn open(
    suspended: &SuspendedTransport,
    phase: Phase,
    key: &SuspendKey,
    floor: u64,
    channel: ChannelId,
) -> Result<Resumed<Transport>, ResumeError> {
    let bytes = &suspended.bytes.0;
    let (header, sealed) = bytes.split_at(HEADER_LEN);
    let mut nonce = [0u8; aead::NONCE_SIZE];
    nonce.copy_from_slice(&header[NONCE_AT]);
    let mut opened = aead::open(&key.sealing_key(), &nonce, header, sealed)
        .map_err(|_| ResumeError::Authentication)?;
    let mut plain = Scrub([0u8; PLAIN_LEN]);
    let fits = opened.len() == PLAIN_LEN;
    if fits {
        plain.0.copy_from_slice(&opened);
    }
    // the library's buffer held the keys too: zero it before it is released
    opened.as_mut_slice().zeroize();
    probe::record(&opened);
    drop(opened);
    if !fits {
        // unreachable for a copy of SUSPENDED_LEN bytes; refused rather than read
        return Err(ResumeError::Authentication);
    }
    if header[1] != phase as u8 {
        return Err(ResumeError::Phase(header[1]));
    }
    // the header is authenticated by now: its channel id is the one the copy was sealed with
    let got = suspended.channel_id();
    if got != channel {
        return Err(ResumeError::OtherChannel {
            expected: channel,
            got,
        });
    }
    let epoch = suspended.epoch();
    if epoch < floor {
        return Err(ResumeError::Stale { epoch, floor });
    }
    let next_floor = epoch.checked_add(1).ok_or(ResumeError::EpochExhausted)?;
    let p = &plain.0;
    let word = |at: usize| {
        let mut w = [0u8; 8];
        w.copy_from_slice(&p[at..at + 8]);
        u64::from_le_bytes(w)
    };
    let mut k = [0u8; 32];
    let cipher = |k: &mut [u8; 32], at: usize, nonce: u64| {
        k.copy_from_slice(&p[at..at + 32]);
        let mut c = CipherState::with_key(*k);
        k.zeroize();
        c.nonce = nonce;
        c
    };
    let send = cipher(&mut k, 0, word(32));
    let recv = cipher(&mut k, 40, word(72));
    let mut handshake_hash = [0u8; 32];
    handshake_hash.copy_from_slice(&p[80..112]);
    Ok(Resumed {
        value: Transport {
            sender: TransportSender {
                cipher: send,
                handshake_hash,
            },
            receiver: TransportReceiver {
                cipher: recv,
                handshake_hash,
            },
            epoch: next_floor,
        },
        next_floor,
    })
}

/// A test-only record of every scrubbed buffer as it is just before it is released
#[cfg(test)]
pub(crate) mod probe {
    use std::cell::RefCell;

    thread_local! {
        static SEEN: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(bytes: &[u8]) {
        SEEN.with(|s| s.borrow_mut().push(bytes.to_vec()));
    }

    /// The buffers recorded on this thread since the last call
    pub fn take() -> Vec<Vec<u8>> {
        SEEN.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }
}

#[cfg(not(test))]
mod probe {
    #[inline]
    pub(super) const fn record(_: &[u8]) {}
}

#[cfg(test)]
mod tests {
    use super::{probe, SuspendKey, SuspendedTransport, Transport};
    use crate::noise::nk::NkHandshakeState;
    use crate::noise::Keypair;

    fn pair() -> (Transport, Transport) {
        let s = Keypair::from_secret([0x71; 32]);
        let mut i = NkHandshakeState::initiator(b"t", s.public());
        let mut r = NkHandshakeState::responder(b"t", s);
        r.read_message(&i.write_message(&[]).unwrap()).unwrap();
        i.read_message(&r.write_message(&[]).unwrap()).unwrap();
        (i.into_transport().unwrap(), r.into_transport().unwrap())
    }

    fn keys(t: &Transport) -> [[u8; 32]; 2] {
        [
            **t.sender.cipher.key.as_ref().unwrap(),
            **t.receiver.cipher.key.as_ref().unwrap(),
        ]
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn the_nonces_and_epoch_come_back_as_they_were() {
        let (mut a, mut b) = pair();
        for _ in 0..4 {
            b.recv(&a.send(b"x").unwrap()).unwrap();
        }
        a.recv(&b.send(b"y").unwrap()).unwrap();
        let before = keys(&a);
        let key = SuspendKey::from_bytes([9; 32]);
        let id = a.channel_id();
        let s = a.suspend(&key).unwrap();
        let r = Transport::resume(&s, &key, 0, id).unwrap();
        let a = r.floor_persisted();
        assert_eq!(a.sender.cipher.nonce, 4);
        assert_eq!(a.receiver.cipher.nonce, 1);
        assert_eq!(a.epoch, 1);
        assert_eq!(keys(&a), before);
        let s = a.suspend(&key).unwrap();
        assert_eq!(s.epoch(), 1);
    }

    #[test]
    fn every_buffer_that_held_the_keys_is_zeroed_before_it_is_released() {
        let (a, _) = pair();
        let [send, recv] = keys(&a);
        let key = SuspendKey::from_bytes([9; 32]);
        let id = a.channel_id();
        let _ = probe::take();
        let kept = a.suspend(&key).unwrap().as_bytes().to_vec();
        let s = SuspendedTransport::from_bytes(&kept).unwrap();
        let resumed = Transport::resume(&s, &key, 0, id)
            .unwrap()
            .floor_persisted();
        drop(s);
        drop(resumed);
        let seen = probe::take();
        // the plaintext built by suspend, the copy sealed and dropped by suspend's caller, the plaintext opened
        // by resume and the copy read back: at least four buffers, every one all zero when released
        assert!(seen.len() >= 4, "{} buffers recorded", seen.len());
        for (i, buf) in seen.iter().enumerate() {
            assert!(buf.iter().all(|&b| b == 0), "buffer {i} not zeroed");
            assert!(!contains(buf, &send) && !contains(buf, &recv));
        }
        assert!(seen.iter().any(|b| b.len() == super::PLAIN_LEN));
        assert!(seen.iter().any(|b| b.len() == super::SUSPENDED_LEN));
    }
}
