//! Mutually authenticated, encrypted channels between certified devices
//!
//! Two devices run the Noise handshake `Noise_IK_25519_ChaChaPoly_SHA256` ([`noise`]). Each device's
//! certificate (`alice-identity`, layout version 2) names its Noise static key under the master key's
//! signature. The initiator dials a peer whose certificate it already holds: it checks that certificate
//! against its [`PeerPolicy`] and takes the responder's static key from it, so the responder's static key
//! never travels. Each side's handshake payload is an artifact signature by its certified device key, for
//! the context [`HANDSHAKE_CONTEXT`], over
//!
//! ```text
//! SHA-256(handshake hash at the point the payload is encrypted || the sender's Noise static public key)
//! ```
//!
//! and the certificate in it must name that static key.
//!
//! The responder answers only an initiator it accepts. A first message made for another static key does not
//! open, and one from a device the policy refuses is dropped; in both cases nothing is written back, so a
//! peer without the responder's static key and an accepted certificate learns nothing from it. The receiver
//! resolves the certificate's subject to its master key through the [`PeerPolicy`], checks the certificate
//! (issuer, validity at the policy's time, revocation), that it names the static key the handshake used, and
//! the signature over its own transcript: a device without a known master, a revoked or expired certificate,
//! or a signature from another session or for another static key never gets a channel. The responder writes
//! its message only after verifying the initiator, so `connect` returning means the responder accepted this
//! side. The handshake ends with a key confirmation: the initiator sends one empty message on the new keys,
//! and the responder's `accept` returns only once it has opened it within its deadline
//! ([`ChannelError::Timeout`] otherwise), so a replayed first message never yields a channel. After the
//! handshake, every message is encrypted and authenticated in order. An operation that did not finish (an
//! I/O error, or for the async channel of the `async` feature a dropped future) leaves the channel
//! [`ChannelError::Poisoned`]: it is never used out of step with its peer.
//!
//! On the wire every Noise message is one frame: a big-endian `u16` length, then that many bytes.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]

pub mod datagram;
pub mod noise;

#[cfg(feature = "async")]
mod async_channel;
#[cfg(feature = "async")]
pub use async_channel::{AsyncRecvHalf, AsyncSecureChannel, AsyncSendHalf};

use std::io::{Read, Write};
use std::time::{Duration, Instant};

use alice_identity::artifact::{
    sha256_payload, sign_artifact, verify_artifact, ArtifactError, ArtifactSignature,
    PayloadDigest, Revocation,
};
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey};

use noise::{HandshakeState, Keypair, NoiseError, Transport};

/// The context of the handshake's artifact signatures
pub const HANDSHAKE_CONTEXT: &[u8] = b"alice-channel/handshake/v1";

/// The Noise prologue: both sides mix it in first, so a handshake of another protocol does not complete
pub const PROLOGUE: &[u8] = b"alice-channel v3";

/// The largest frame on the wire, in bytes (the Noise message limit)
pub const MAX_FRAME: usize = noise::MAX_MESSAGE;

/// The largest payload of one [`SecureChannel::send`], in bytes
pub const MAX_PAYLOAD: usize = MAX_FRAME - 16;

/// How long a handshake waits for the other side's next message unless told otherwise: `connect` for the
/// responder's message, `accept` for the initiator's first message and then for its key confirmation
pub const DEFAULT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(10);

/// Why a channel was not opened, or a message not sent or received
#[derive(Debug)]
pub enum ChannelError {
    /// The stream failed
    Io(std::io::ErrorKind),
    /// The peer closed the stream at a frame boundary
    Closed,
    /// A Noise message was refused (changed, out of order, or from another transcript)
    Noise(NoiseError),
    /// The peer's certificate names a subject whose master key the policy does not know
    UnknownPeer,
    /// The peer's certificate or handshake signature was refused
    Rejected(ArtifactError),
    /// This side's own credential cannot sign (the device key is not the certificate's, or the certificate
    /// does not fit an artifact signature)
    Credential(ArtifactError),
    /// The payload is longer than [`MAX_PAYLOAD`]
    TooLong,
    /// The other side's handshake message or key confirmation did not come within the deadline
    Timeout,
    /// A certificate names another Noise static key than the one the handshake used (or, for this side's
    /// own credential, than its Noise static key)
    StaticKeyMismatch,
    /// The responder proved another subject than the certificate the initiator dialled
    UnexpectedPeer,
    /// An earlier operation on this channel did not finish; the channel is not used again
    Poisoned,
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(k) => write!(f, "channel stream: {k}"),
            Self::Closed => f.write_str("the peer closed the channel"),
            Self::Noise(e) => write!(f, "{e}"),
            Self::UnknownPeer => f.write_str("the peer's master key is unknown"),
            Self::Rejected(e) => write!(f, "the peer was refused: {e}"),
            Self::Credential(e) => write!(f, "this side's credential cannot sign: {e}"),
            Self::TooLong => f.write_str("the channel payload is too long"),
            Self::Timeout => f.write_str("the peer did not continue the handshake in time"),
            Self::StaticKeyMismatch => {
                f.write_str("the certificate names another Noise static key")
            }
            Self::UnexpectedPeer => f.write_str("the responder is not the device that was dialled"),
            Self::Poisoned => f.write_str("an earlier operation on the channel did not finish"),
        }
    }
}

impl std::error::Error for ChannelError {}

impl From<NoiseError> for ChannelError {
    fn from(e: NoiseError) -> Self {
        Self::Noise(e)
    }
}

/// What the receiver of a handshake trusts: the master key of each subject, the revocation lists, the time
pub trait PeerPolicy {
    /// The master key of `subject`, or `None` when the subject is not one this side accepts
    fn master_of(&self, subject: &Did) -> Option<PublicKey>;
    /// The revocation lists to check the peer's certificate against
    fn revocation(&self) -> Revocation<'_>;
    /// The time at which the peer's certificate must be valid (seconds, as the certificate counts them)
    fn now(&self) -> u64;
}

/// One device's identity on a channel: its certified signing key and its Noise static key
pub struct Credential {
    device: KeyPair,
    cert: DeviceCert,
    noise_static: Keypair,
}

impl Credential {
    /// A credential from the device key, the certificate that names it, and the Noise static key
    ///
    /// # Errors
    /// [`ChannelError::Credential`] when `device` is not the key `cert` names, or the certificate does not
    /// fit an artifact signature; [`ChannelError::StaticKeyMismatch`] when `cert` names another Noise static
    /// key than `noise_static`
    pub fn new(
        device: KeyPair,
        cert: DeviceCert,
        noise_static: Keypair,
    ) -> Result<Self, ChannelError> {
        // a trial signature checks the key and the certificate once, so the handshake cannot fail on them
        sign_artifact(
            &device,
            &cert,
            HANDSHAKE_CONTEXT,
            &PayloadDigest::sha256([0; 32]),
        )
        .map_err(ChannelError::Credential)?;
        if *cert.noise_static() != noise_static.public() {
            return Err(ChannelError::StaticKeyMismatch);
        }
        Ok(Self {
            device,
            cert,
            noise_static,
        })
    }

    #[must_use]
    pub const fn cert(&self) -> &DeviceCert {
        &self.cert
    }

    #[must_use]
    pub const fn noise_static(&self) -> &Keypair {
        &self.noise_static
    }

    #[must_use]
    pub const fn noise_static_public(&self) -> [u8; 32] {
        self.noise_static.public()
    }
}

fn handshake_digest(h: &[u8; 32], static_pub: &[u8; 32]) -> PayloadDigest {
    let mut joined = [0u8; 64];
    joined[..32].copy_from_slice(h);
    joined[32..].copy_from_slice(static_pub);
    sha256_payload(&joined)
}

/// The handshake signature of `cred` for the transcript hash `h`: an artifact signature for
/// [`HANDSHAKE_CONTEXT`] over SHA-256(`h` || the credential's Noise static public key)
///
/// # Errors
/// [`ChannelError::Credential`] (not reachable for a credential made by [`Credential::new`])
pub fn sign_handshake(cred: &Credential, h: &[u8; 32]) -> Result<ArtifactSignature, ChannelError> {
    sign_artifact(
        &cred.device,
        &cred.cert,
        HANDSHAKE_CONTEXT,
        &handshake_digest(h, &cred.noise_static.public()),
    )
    .map_err(ChannelError::Credential)
}

/// Check `cert` against the policy as it stands: the subject's master key is known, the certificate verifies
/// under it at [`PeerPolicy::now`], and no revocation list the policy holds revokes it
///
/// # Errors
/// [`ChannelError::UnknownPeer`], [`ChannelError::Rejected`]
pub fn check_cert(cert: &DeviceCert, policy: &impl PeerPolicy) -> Result<(), ChannelError> {
    let master = policy
        .master_of(cert.subject())
        .ok_or(ChannelError::UnknownPeer)?;
    cert.verify(&master, policy.now())
        .map_err(|e| ChannelError::Rejected(ArtifactError::Cert(e)))?;
    if let Revocation::Checked(list) = policy.revocation() {
        if list.revokes(cert) {
            return Err(ChannelError::Rejected(ArtifactError::Revoked));
        }
    }
    Ok(())
}

/// Check the peer's handshake payload against the transcript hash `h` and its Noise static key `rs`
fn verify_peer(
    payload: &[u8],
    h: &[u8; 32],
    rs: Option<[u8; 32]>,
    policy: &impl PeerPolicy,
) -> Result<DeviceCert, ChannelError> {
    let sig = ArtifactSignature::from_bytes(payload).map_err(ChannelError::Rejected)?;
    let master = policy
        .master_of(sig.cert().subject())
        .ok_or(ChannelError::UnknownPeer)?;
    // the pattern carries or presupposes the static key before the payload, so it is known here
    let rs = rs.ok_or(ChannelError::Noise(NoiseError::OutOfTurn))?;
    verify_artifact(
        &sig,
        &master,
        HANDSHAKE_CONTEXT,
        &handshake_digest(h, &rs),
        policy.now(),
        policy.revocation(),
    )
    .map_err(ChannelError::Rejected)?;
    if *sig.cert().noise_static() != rs {
        return Err(ChannelError::StaticKeyMismatch);
    }
    Ok(sig.cert().clone())
}

/// Before dialling: the certificate the initiator dials must pass the policy, and its static key is the
/// responder key of the handshake
fn dial_key(peer: &DeviceCert, policy: &impl PeerPolicy) -> Result<[u8; 32], ChannelError> {
    check_cert(peer, policy)?;
    Ok(*peer.noise_static())
}

/// The responder must prove the subject the initiator dialled
fn expect_subject(got: DeviceCert, dialled: &DeviceCert) -> Result<DeviceCert, ChannelError> {
    if got.subject() == dialled.subject() {
        Ok(got)
    } else {
        Err(ChannelError::UnexpectedPeer)
    }
}

fn io(e: &std::io::Error) -> ChannelError {
    ChannelError::Io(e.kind())
}

fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<(), ChannelError> {
    let len = u16::try_from(bytes.len()).map_err(|_| ChannelError::TooLong)?;
    stream.write_all(&len.to_be_bytes()).map_err(|e| io(&e))?;
    stream.write_all(bytes).map_err(|e| io(&e))?;
    stream.flush().map_err(|e| io(&e))
}

fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, ChannelError> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ChannelError::Closed)
        }
        Err(e) => return Err(io(&e)),
    }
    let mut bytes = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut bytes).map_err(|e| io(&e))?;
    Ok(bytes)
}

/// Write the next handshake message with this side's handshake signature as its payload
fn write_signed(hs: &mut HandshakeState, cred: &Credential) -> Result<Vec<u8>, ChannelError> {
    let mut failed = None;
    let msg = hs.write_message_with(|h| match sign_handshake(cred, h) {
        Ok(sig) => sig.to_bytes(),
        Err(e) => {
            failed = Some(e);
            Vec::new()
        }
    })?;
    failed.map_or(Ok(msg), Err)
}

/// Open the initiator's key confirmation: one empty message on the new keys
fn open_confirmation(transport: &mut Transport, frame: &[u8]) -> Result<(), ChannelError> {
    if transport.recv(frame)?.is_empty() {
        Ok(())
    } else {
        Err(ChannelError::Noise(NoiseError::Decrypt))
    }
}

/// A blocking stream whose reads can be given a deadline (for the key confirmation)
pub trait ReadTimeout {
    /// The current read timeout
    ///
    /// # Errors
    /// The stream's own
    fn read_timeout(&self) -> std::io::Result<Option<Duration>>;
    /// Set the read timeout
    ///
    /// # Errors
    /// The stream's own
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl ReadTimeout for std::net::TcpStream {
    fn read_timeout(&self) -> std::io::Result<Option<Duration>> {
        Self::read_timeout(self)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }
}

#[cfg(unix)]
impl ReadTimeout for std::os::unix::net::UnixStream {
    fn read_timeout(&self) -> std::io::Result<Option<Duration>> {
        Self::read_timeout(self)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }
}

/// The length of the confirmation frame: an empty message is only its tag
pub(crate) const CONFIRMATION_LEN: usize = alice_crypto::chacha20poly1305_ietf::TAG_SIZE;

/// Fill `buf` from `stream` before `end`, setting the time that is left before each read (a read timeout
/// alone would restart with every byte a slow peer sends)
fn read_before<S: Read + ReadTimeout>(
    stream: &mut S,
    buf: &mut [u8],
    end: Instant,
) -> Result<(), ChannelError> {
    let mut filled = 0;
    while filled < buf.len() {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ChannelError::Timeout);
        }
        stream.set_read_timeout(Some(left)).map_err(|e| io(&e))?;
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err(ChannelError::Closed),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ChannelError::Timeout)
            }
            Err(e) => return Err(io(&e)),
        }
    }
    Ok(())
}

/// Read one frame within `deadline` in total; when `len` is given, a frame of another length is refused before
/// its body is read. The stream's own read timeout is restored afterwards
fn read_frame_before<S: Read + ReadTimeout>(
    stream: &mut S,
    deadline: Duration,
    len: Option<usize>,
) -> Result<Vec<u8>, ChannelError> {
    let before = stream.read_timeout().map_err(|e| io(&e))?;
    let end = Instant::now() + deadline;
    let read = (|| {
        let mut head = [0u8; 2];
        read_before(stream, &mut head, end)?;
        let n = usize::from(u16::from_be_bytes(head));
        if len.is_some_and(|want| want != n) {
            return Err(ChannelError::Noise(NoiseError::Decrypt));
        }
        let mut body = vec![0u8; n];
        read_before(stream, &mut body, end)?;
        Ok(body)
    })();
    stream.set_read_timeout(before).map_err(|e| io(&e))?;
    read
}

/// An open channel: the peer's certificate and the transport keys over `S`
pub struct SecureChannel<S> {
    stream: S,
    transport: Transport,
    peer: DeviceCert,
    poisoned: bool,
}

impl<S: Read + Write + ReadTimeout> SecureChannel<S> {
    /// Open a channel to the device `peer` certifies, as the side that connected, waiting
    /// [`DEFAULT_CONFIRM_TIMEOUT`] for the responder's message
    ///
    /// # Errors
    /// As [`Self::connect_with_timeout`]
    pub fn connect(
        stream: S,
        cred: &Credential,
        policy: &impl PeerPolicy,
        peer: &DeviceCert,
    ) -> Result<Self, ChannelError> {
        Self::connect_with_timeout(stream, cred, policy, peer, DEFAULT_CONFIRM_TIMEOUT)
    }

    /// Open a channel to the device `peer` certifies, as the side that connected. `peer` is checked against
    /// the policy before anything is written, and its Noise static key is the responder key of the handshake.
    /// The channel is returned once the responder's message, which it writes only after verifying this side,
    /// has come within `timeout` and verifies as the subject of `peer`; this side's key confirmation is sent
    /// before returning
    ///
    /// # Errors
    /// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] when `peer` or the responder's proof is
    /// refused, [`ChannelError::StaticKeyMismatch`], [`ChannelError::UnexpectedPeer`],
    /// [`ChannelError::Closed`] or [`ChannelError::Io`] when the responder refused this side or went away,
    /// [`ChannelError::Timeout`] when its message did not come, [`ChannelError::Noise`]
    pub fn connect_with_timeout(
        mut stream: S,
        cred: &Credential,
        policy: &impl PeerPolicy,
        peer: &DeviceCert,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        let rs = dial_key(peer, policy)?;
        let mut hs = HandshakeState::initiator(PROLOGUE, cred.noise_static.clone(), rs);
        write_frame(&mut stream, &write_signed(&mut hs, cred)?)?;
        let frame = read_frame_before(&mut stream, timeout, None)?;
        let (payload, h) = hs.read_message_with_hash(&frame)?;
        let got = verify_peer(&payload, &h, hs.remote_static(), policy)?;
        let peer = expect_subject(got, peer)?;
        let mut transport = hs.into_transport()?;
        // key confirmation: the responder's accept returns only after this
        write_frame(&mut stream, &transport.send(&[])?)?;
        Ok(Self {
            stream,
            transport,
            peer,
            poisoned: false,
        })
    }

    /// Open a channel as the side that accepted the connection, waiting [`DEFAULT_CONFIRM_TIMEOUT`] for the
    /// initiator's first message and then for its key confirmation
    ///
    /// # Errors
    /// As [`Self::accept_with_timeout`]
    pub fn accept(
        stream: S,
        cred: &Credential,
        policy: &impl PeerPolicy,
    ) -> Result<Self, ChannelError> {
        Self::accept_with_timeout(stream, cred, policy, DEFAULT_CONFIRM_TIMEOUT)
    }

    /// Open a channel as the side that accepted the connection. Nothing is written unless the first message
    /// opens for this side's static key and the initiator verifies under the policy. The first message must
    /// come within `timeout` (a silent connection is dropped then, with nothing written), and the channel is
    /// returned once the initiator's key confirmation has come within `timeout` after this side's message;
    /// each deadline holds for the whole message, however slowly its bytes come
    ///
    /// A returned channel means the peer completed the handshake. It does not mean the peer is still there:
    /// it may go away right after its confirmation, and then the first `send` or `recv` returns
    /// [`ChannelError::Closed`] or [`ChannelError::Io`].
    ///
    /// # Errors
    /// [`ChannelError::Noise`] when the first message does not open (another static key, a changed message),
    /// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] / [`ChannelError::StaticKeyMismatch`] when
    /// the initiator is refused, [`ChannelError::Timeout`] when the first message or the confirmation did not
    /// come,
    /// [`ChannelError::Closed`], [`ChannelError::Io`]
    pub fn accept_with_timeout(
        mut stream: S,
        cred: &Credential,
        policy: &impl PeerPolicy,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        let mut hs = HandshakeState::responder(PROLOGUE, cred.noise_static.clone());
        let first = read_frame_before(&mut stream, timeout, None)?;
        let (payload, h) = hs.read_message_with_hash(&first)?;
        let peer = verify_peer(&payload, &h, hs.remote_static(), policy)?;
        write_frame(&mut stream, &write_signed(&mut hs, cred)?)?;
        let mut transport = hs.into_transport()?;
        let frame = read_frame_before(&mut stream, timeout, Some(CONFIRMATION_LEN))?;
        open_confirmation(&mut transport, &frame)?;
        Ok(Self {
            stream,
            transport,
            peer,
            poisoned: false,
        })
    }
}

impl<S: Read + Write> SecureChannel<S> {
    /// Send one message
    ///
    /// # Errors
    /// [`ChannelError::TooLong`] above [`MAX_PAYLOAD`], [`ChannelError::Io`], [`ChannelError::Noise`]
    pub fn send(&mut self, payload: &[u8]) -> Result<(), ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(ChannelError::TooLong);
        }
        // the nonce advances with the encryption: a frame not fully written leaves the peer out of step
        self.poisoned = true;
        let msg = self.transport.send(payload)?;
        write_frame(&mut self.stream, &msg)?;
        self.poisoned = false;
        Ok(())
    }

    /// Receive the next message
    ///
    /// # Errors
    /// [`ChannelError::Closed`], [`ChannelError::Io`], [`ChannelError::Noise`] (a changed, replayed or
    /// reordered message)
    pub fn recv(&mut self) -> Result<Vec<u8>, ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        self.poisoned = true;
        let frame = read_frame(&mut self.stream)?;
        let payload = self.transport.recv(&frame)?;
        self.poisoned = false;
        Ok(payload)
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
