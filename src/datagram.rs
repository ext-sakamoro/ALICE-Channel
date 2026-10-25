//! The datagram mode: the same handshake and identity binding as [`SecureChannel`](crate::SecureChannel),
//! carried in datagrams that may be lost, reordered or duplicated
//!
//! Nothing here does I/O. The caller sends the packets these types return and feeds back the packets it
//! receives, so the same code serves a UDP socket, a relay, or a test that drops and reorders packets.
//!
//! Every packet starts with its kind ([`KIND_INIT`], [`KIND_RESPONSE`], [`KIND_DATA`]):
//!
//! ```text
//! init      [1][the initiator's Noise message]
//! response  [2][the responder's Noise message]
//! data      [3][counter: u64 little-endian][ciphertext]
//! ```
//!
//! The handshake is the stream channel's Noise IK with the same signed payloads, so the same certificates
//! and policy decide who gets a channel. The initiator's encrypted payload also carries a timestamp
//! ([`InitTimestamp`], TAI64N): a [`Responder`] answers an init only when its timestamp is later than the
//! last one it accepted from the same static key, so an old init replayed later starts nothing.
//!
//! Two consequences follow from keeping only the last timestamp, in memory:
//!
//! - after the responder restarts it holds no timestamps, so the first replay of an old init is answered
//!   once; that handshake cannot be confirmed (the replayer holds no static key) and an open channel is
//!   not affected
//! - an initiator whose clock steps back is refused ([`ChannelError::StaleInit`]) until its clock passes
//!   the last time the responder accepted from it; the caller should report that refusal rather than
//!   retry silently
//!
//! Packets may be lost, so the initiator repeats its init packet ([`Initiator::first`]) until it has the
//! response, and the responder answers a repeated init with the
//! response it already wrote ([`Pending::is_first`], [`Pending::response`]) rather than starting a second
//! handshake. The responder's channel is returned by the first data packet that opens under the new keys
//! ([`Pending::confirm`]): the initiator's empty key confirmation, or, when that was lost, any later data
//! packet. If the responder keeps repeating its response, the initiator answers with a fresh confirmation
//! ([`DatagramChannel::answer_repeated_response`]).
//!
//! Each data packet is sealed on its own: its counter is the nonce and is carried in the clear. The
//! receiver keeps a window of the last [`REPLAY_WINDOW`] counters below the highest it has opened and
//! opens each counter at most once, in any order: a counter it has opened is [`DatagramError::Replayed`],
//! one below the window is [`DatagramError::TooOld`]. A counter is recorded only after its packet opened,
//! so a changed or forged packet moves nothing.

use std::collections::BTreeMap;

use alice_identity::device_cert::DeviceCert;

use crate::noise::{DatagramTransport, HandshakeState, Keypair, NoiseError};
use crate::{
    dial_key, expect_subject, sign_handshake, verify_peer, write_signed, ChannelError, Credential,
    PeerPolicy, PROLOGUE,
};

/// The kind of an initiator's handshake packet
pub const KIND_INIT: u8 = 1;
/// The kind of a responder's handshake packet
pub const KIND_RESPONSE: u8 = 2;
/// The kind of a data packet
pub const KIND_DATA: u8 = 3;

/// How many counters below the highest opened one are still accepted (once each)
pub const REPLAY_WINDOW: u64 = 1024;

/// The associated data of every data packet's seal (keeps the datagram ciphertexts apart from any other
/// use of the keys)
pub const DATAGRAM_AD: &[u8] = b"alice-channel/datagram/v1";

/// The bytes before the ciphertext of a data packet: the kind and the counter
pub const DATA_HEADER_LEN: usize = 1 + 8;

/// The largest payload of one data packet, in bytes (a UDP payload of 65,507 bytes at most)
pub const MAX_DATAGRAM_PAYLOAD: usize = 65_507 - DATA_HEADER_LEN - TAG_LEN;

const TAG_LEN: usize = alice_crypto::chacha20poly1305_ietf::TAG_SIZE;
const WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// The time an init was made, as TAI64N: 8 bytes big-endian of 2^62 + the seconds since 1970, then 4 bytes
/// big-endian of the nanoseconds, so a later time is greater byte by byte
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InitTimestamp(pub [u8; 12]);

impl InitTimestamp {
    /// The bytes it takes at the head of the initiator's payload
    pub const LEN: usize = 12;

    /// The label of `secs` seconds and `nanos` nanoseconds after 1970 (nanoseconds above 999,999,999 are
    /// taken as 999,999,999)
    #[must_use]
    pub fn from_unix(secs: u64, nanos: u32) -> Self {
        let mut b = [0u8; 12];
        b[..8].copy_from_slice(&((1u64 << 62) + secs).to_be_bytes());
        b[8..].copy_from_slice(&nanos.min(999_999_999).to_be_bytes());
        Self(b)
    }

    /// The label of the system clock now (before 1970 counts as 1970)
    #[must_use]
    pub fn now() -> Self {
        let d = crate::clock::system_now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self::from_unix(d.as_secs(), d.subsec_nanos())
    }
}

/// Why a data packet was not sealed or opened
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramError {
    /// Not a data packet of this layout (another kind, or shorter than a header and a tag)
    Malformed,
    /// A packet with this counter has already opened
    Replayed,
    /// The counter is below the replay window
    TooOld,
    /// The packet does not open under the keys (changed, forged, or sealed under other keys)
    Decrypt,
    /// The payload is longer than [`MAX_DATAGRAM_PAYLOAD`]
    TooLong,
    /// An empty payload is not sent (an empty data packet is the key confirmation)
    Empty,
    /// The counters of this channel are spent
    CounterExhausted,
}

impl core::fmt::Display for DatagramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a data packet",
            Self::Replayed => "a data packet with this counter has already opened",
            Self::TooOld => "the data packet's counter is below the replay window",
            Self::Decrypt => "the data packet does not open",
            Self::TooLong => "the datagram payload is too long",
            Self::Empty => "an empty payload is not sent",
            Self::CounterExhausted => "the datagram counters are spent",
        })
    }
}

impl std::error::Error for DatagramError {}

/// The counters already opened: the next counter above all of them, and a bit per counter of the
/// [`REPLAY_WINDOW`] below it
struct ReplayWindow {
    next: u64,
    bits: [u64; WORDS],
}

impl ReplayWindow {
    const fn new() -> Self {
        Self {
            next: 0,
            bits: [0; WORDS],
        }
    }

    const fn slot(counter: u64) -> (usize, u64) {
        let i = counter % REPLAY_WINDOW;
        ((i / 64) as usize, 1 << (i % 64))
    }

    /// Whether `counter` may still open
    const fn check(&self, counter: u64) -> Result<(), DatagramError> {
        if counter >= self.next {
            return Ok(());
        }
        if self.next - counter > REPLAY_WINDOW {
            return Err(DatagramError::TooOld);
        }
        let (w, b) = Self::slot(counter);
        if self.bits[w] & b == 0 {
            Ok(())
        } else {
            Err(DatagramError::Replayed)
        }
    }

    /// Record `counter` as opened (only after [`Self::check`] passed and the packet opened)
    fn mark(&mut self, counter: u64) {
        if counter >= self.next {
            let advance = counter - self.next + 1;
            if advance >= REPLAY_WINDOW {
                self.bits = [0; WORDS];
            } else {
                // the slots the window moves over held counters that have now left it
                for c in self.next..=counter {
                    let (w, b) = Self::slot(c);
                    self.bits[w] &= !b;
                }
            }
            self.next = counter + 1;
        }
        let (w, b) = Self::slot(counter);
        self.bits[w] |= b;
    }
}

/// The initiator of a datagram handshake, until the response comes
pub struct Initiator {
    hs: HandshakeState,
    first: Vec<u8>,
    dialled: DeviceCert,
}

impl Initiator {
    /// Start a handshake with the device `peer` certifies; returns the init packet to send (repeat it
    /// with [`Self::first`] until the response comes)
    ///
    /// # Errors
    /// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] when `peer` is refused,
    /// [`ChannelError::Credential`], [`ChannelError::Noise`]
    pub fn start(
        cred: &Credential,
        policy: &impl PeerPolicy,
        peer: &DeviceCert,
    ) -> Result<(Self, Vec<u8>), ChannelError> {
        Self::start_at(cred, policy, peer, InitTimestamp::now())
    }

    /// As [`Self::start`], with the init's timestamp given (it must be later than any earlier init of
    /// this static key to the same responder)
    ///
    /// # Errors
    /// As [`Self::start`]
    pub fn start_at(
        cred: &Credential,
        policy: &impl PeerPolicy,
        peer: &DeviceCert,
        at: InitTimestamp,
    ) -> Result<(Self, Vec<u8>), ChannelError> {
        let rs = dial_key(peer, policy)?;
        let hs = HandshakeState::initiator(PROLOGUE, cred.noise_static.clone(), rs);
        Self::begin(hs, cred, peer, at)
    }

    /// As [`Self::start_at`] with a fixed ephemeral key, for test vectors only (a reused ephemeral key
    /// voids the protocol's guarantees)
    ///
    /// # Errors
    /// As [`Self::start`]
    pub fn start_with_ephemeral(
        cred: &Credential,
        policy: &impl PeerPolicy,
        peer: &DeviceCert,
        at: InitTimestamp,
        ephemeral: Keypair,
    ) -> Result<(Self, Vec<u8>), ChannelError> {
        let rs = dial_key(peer, policy)?;
        let hs = HandshakeState::initiator_with_ephemeral(
            PROLOGUE,
            cred.noise_static.clone(),
            rs,
            ephemeral,
        );
        Self::begin(hs, cred, peer, at)
    }

    fn begin(
        mut hs: HandshakeState,
        cred: &Credential,
        peer: &DeviceCert,
        at: InitTimestamp,
    ) -> Result<(Self, Vec<u8>), ChannelError> {
        let mut failed = None;
        let msg = hs.write_message_with(|h| {
            let mut payload = at.0.to_vec();
            match sign_handshake(cred, h) {
                Ok(sig) => payload.extend_from_slice(&sig.to_bytes()),
                Err(e) => failed = Some(e),
            }
            payload
        })?;
        if let Some(e) = failed {
            return Err(e);
        }
        let mut first = vec![KIND_INIT];
        first.extend_from_slice(&msg);
        Ok((
            Self {
                hs,
                first: first.clone(),
                dialled: peer.clone(),
            },
            first,
        ))
    }

    /// The init packet, to send again while no response has come
    #[must_use]
    pub fn first(&self) -> &[u8] {
        &self.first
    }

    /// Finish on the responder's packet: returns the channel and the key confirmation to send
    ///
    /// # Errors
    /// [`ChannelError::Noise`] when `packet` is not a response that opens for this handshake,
    /// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] / [`ChannelError::StaticKeyMismatch`]
    /// when the responder's proof is refused, [`ChannelError::UnexpectedPeer`]
    pub fn finish(
        mut self,
        packet: &[u8],
        policy: &impl PeerPolicy,
    ) -> Result<(DatagramChannel, Vec<u8>), ChannelError> {
        let body = packet
            .strip_prefix(&[KIND_RESPONSE])
            .ok_or(ChannelError::Noise(NoiseError::Truncated))?;
        let (payload, h) = self.hs.read_message_with_hash(body)?;
        let got = verify_peer(&payload, &h, self.hs.remote_static(), policy)?;
        let peer = expect_subject(got, &self.dialled)?;
        let transport = self.hs.into_transport()?.into_datagram();
        let mut channel = DatagramChannel {
            transport,
            window: ReplayWindow::new(),
            peer,
            response: Some(packet.to_vec()),
        };
        let confirmation = channel.seal_raw(&[])?;
        Ok((channel, confirmation))
    }
}

/// The responder's side of datagram handshakes: it remembers the latest init timestamp it accepted from
/// each initiator's static key
#[derive(Debug, Default)]
pub struct Responder {
    last: BTreeMap<[u8; 32], InitTimestamp>,
}

impl Responder {
    /// A responder that has accepted no init yet
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer an init packet: nothing is returned (so nothing is sent) unless it opens for this side's
    /// static key, the initiator verifies under the policy, and its timestamp is later than the last one
    /// accepted from that static key. A repeat of an init already answered is refused as stale: check
    /// [`Pending::is_first`] first and send [`Pending::response`] again
    ///
    /// # Errors
    /// [`ChannelError::Noise`] when the packet does not open (another static key, a changed packet),
    /// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] / [`ChannelError::StaticKeyMismatch`]
    /// when the initiator is refused, [`ChannelError::StaleInit`], [`ChannelError::Credential`]
    pub fn respond(
        &mut self,
        cred: &Credential,
        policy: &impl PeerPolicy,
        packet: &[u8],
    ) -> Result<Pending, ChannelError> {
        let hs = HandshakeState::responder(PROLOGUE, cred.noise_static.clone());
        self.answer(hs, cred, policy, packet)
    }

    /// As [`Self::respond`] with a fixed ephemeral key, for test vectors only
    ///
    /// # Errors
    /// As [`Self::respond`]
    pub fn respond_with_ephemeral(
        &mut self,
        cred: &Credential,
        policy: &impl PeerPolicy,
        packet: &[u8],
        ephemeral: Keypair,
    ) -> Result<Pending, ChannelError> {
        let hs = HandshakeState::responder_with_ephemeral(
            PROLOGUE,
            cred.noise_static.clone(),
            ephemeral,
        );
        self.answer(hs, cred, policy, packet)
    }

    fn answer(
        &mut self,
        mut hs: HandshakeState,
        cred: &Credential,
        policy: &impl PeerPolicy,
        packet: &[u8],
    ) -> Result<Pending, ChannelError> {
        let body = packet
            .strip_prefix(&[KIND_INIT])
            .ok_or(ChannelError::Noise(NoiseError::Truncated))?;
        let (payload, h) = hs.read_message_with_hash(body)?;
        if payload.len() < InitTimestamp::LEN {
            return Err(ChannelError::Noise(NoiseError::Truncated));
        }
        let (stamp, signed) = payload.split_at(InitTimestamp::LEN);
        let mut at = [0u8; InitTimestamp::LEN];
        at.copy_from_slice(stamp);
        let at = InitTimestamp(at);
        let peer = verify_peer(signed, &h, hs.remote_static(), policy)?;
        let rs = hs
            .remote_static()
            .ok_or(ChannelError::Noise(NoiseError::OutOfTurn))?;
        if self.last.get(&rs).is_some_and(|last| at <= *last) {
            return Err(ChannelError::StaleInit);
        }
        let mut response = vec![KIND_RESPONSE];
        response.extend_from_slice(&write_signed(&mut hs, cred)?);
        self.last.insert(rs, at);
        Ok(Pending {
            first: packet.to_vec(),
            response,
            transport: hs.into_transport()?.into_datagram(),
            peer,
        })
    }
}

/// A responder that has answered and waits for the first data packet under the new keys
pub struct Pending {
    first: Vec<u8>,
    response: Vec<u8>,
    transport: DatagramTransport,
    peer: DeviceCert,
}

impl Pending {
    /// The response packet: send it again when the init packet comes again, or on a timer
    #[must_use]
    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// Whether `packet` is the init packet this side answered (a repeat, to answer with
    /// [`Self::response`] and not with a new handshake)
    #[must_use]
    pub fn is_first(&self, packet: &[u8]) -> bool {
        packet == self.first.as_slice()
    }

    /// The certificate of the initiator, as verified (not yet confirmed)
    #[must_use]
    pub const fn peer_cert(&self) -> &DeviceCert {
        &self.peer
    }

    /// Take a data packet: when it opens under the new keys the handshake is confirmed, and the channel
    /// is returned with the packet's payload (`None` for the empty key confirmation). A packet that does
    /// not open ([`DatagramError::Malformed`], [`DatagramError::Decrypt`]) leaves this side waiting
    #[must_use]
    pub fn confirm(self, packet: &[u8]) -> Confirmed {
        let mut channel = DatagramChannel {
            transport: self.transport,
            window: ReplayWindow::new(),
            peer: self.peer,
            response: None,
        };
        match channel.open(packet) {
            Ok(payload) => Confirmed::Open(channel, payload),
            Err(e) => Confirmed::Waiting(
                Self {
                    first: self.first,
                    response: self.response,
                    transport: channel.transport,
                    peer: channel.peer,
                },
                e,
            ),
        }
    }
}

/// What [`Pending::confirm`] made of a packet
pub enum Confirmed {
    /// The packet opened: the channel, and the packet's payload (`None` for the key confirmation)
    Open(DatagramChannel, Option<Vec<u8>>),
    /// The packet did not open: the responder still waits
    Waiting(Pending, DatagramError),
}

impl Confirmed {
    /// The channel and payload, or why the packet did not open (dropping the waiting responder)
    ///
    /// # Errors
    /// The packet's [`DatagramError`]
    pub fn channel(self) -> Result<(DatagramChannel, Option<Vec<u8>>), DatagramError> {
        match self {
            Self::Open(c, p) => Ok((c, p)),
            Self::Waiting(_, e) => Err(e),
        }
    }
}

/// An established datagram channel: seal and open data packets in any order
pub struct DatagramChannel {
    transport: DatagramTransport,
    window: ReplayWindow,
    peer: DeviceCert,
    /// the response the initiator finished on (none on the responder's side)
    response: Option<Vec<u8>>,
}

impl DatagramChannel {
    /// Seal `payload` into the next data packet
    ///
    /// # Errors
    /// [`DatagramError::Empty`], [`DatagramError::TooLong`], [`DatagramError::CounterExhausted`]
    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, DatagramError> {
        if payload.is_empty() {
            return Err(DatagramError::Empty);
        }
        if payload.len() > MAX_DATAGRAM_PAYLOAD {
            return Err(DatagramError::TooLong);
        }
        self.seal_raw(payload).map_err(|e| match e {
            ChannelError::Noise(NoiseError::TooLong) => DatagramError::TooLong,
            _ => DatagramError::CounterExhausted,
        })
    }

    fn seal_raw(&mut self, payload: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let (counter, ct) = self.transport.seal(DATAGRAM_AD, payload)?;
        let mut packet = Vec::with_capacity(DATA_HEADER_LEN + ct.len());
        packet.push(KIND_DATA);
        packet.extend_from_slice(&counter.to_le_bytes());
        packet.extend_from_slice(&ct);
        Ok(packet)
    }

    /// Open a data packet: its payload, or `None` for an empty one (a key confirmation)
    ///
    /// # Errors
    /// [`DatagramError::Malformed`], [`DatagramError::Replayed`], [`DatagramError::TooOld`],
    /// [`DatagramError::Decrypt`]
    pub fn open(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, DatagramError> {
        if packet.len() < DATA_HEADER_LEN + TAG_LEN || packet[0] != KIND_DATA {
            return Err(DatagramError::Malformed);
        }
        let mut c = [0u8; 8];
        c.copy_from_slice(&packet[1..DATA_HEADER_LEN]);
        let counter = u64::from_le_bytes(c);
        self.window.check(counter)?;
        let payload = self
            .transport
            .open(counter, DATAGRAM_AD, &packet[DATA_HEADER_LEN..])
            .map_err(|_| DatagramError::Decrypt)?;
        self.window.mark(counter);
        Ok(if payload.is_empty() {
            None
        } else {
            Some(payload)
        })
    }

    /// On the initiator's side, answer the response packet it finished on, when it comes again (the
    /// responder has not seen a confirmation), with a fresh one; `None` for any other packet
    ///
    /// # Errors
    /// [`DatagramError::CounterExhausted`]
    pub fn answer_repeated_response(
        &mut self,
        packet: &[u8],
    ) -> Option<Result<Vec<u8>, DatagramError>> {
        if self.response.as_deref() != Some(packet) {
            return None;
        }
        Some(
            self.seal_raw(&[])
                .map_err(|_| DatagramError::CounterExhausted),
        )
    }

    /// The peer's device certificate, as verified in the handshake
    #[must_use]
    pub const fn peer_cert(&self) -> &DeviceCert {
        &self.peer
    }

    /// The handshake hash both sides share
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.transport.handshake_hash()
    }
}
