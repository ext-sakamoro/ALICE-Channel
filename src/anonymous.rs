//! Channels whose initiator stays unnamed: only the responder is authenticated
//!
//! [`AnonymousChannel`] runs `Noise_NK_25519_ChaChaPoly_SHA256` ([`crate::noise::nk`]) under its own prologue
//! [`ANONYMOUS_PROLOGUE`], so a first message of the mutually authenticated channel ([`crate::SecureChannel`])
//! does not open here and an anonymous first message does not open there. The initiator dials a responder
//! whose certificate it already holds and checks it against its [`PeerPolicy`] before anything is written;
//! the responder's static key comes from that certificate, so only the device holding it can finish the
//! handshake. The initiator writes no static key, no certificate and no signature: its first message is an
//! ephemeral key and an empty encrypted payload, and two connections from the same device share no bytes.
//! The handshake ends with the same key confirmation as the mutual channel (one empty message from the
//! initiator on the new keys; `accept` returns only once it has opened it within its deadline), so a replayed
//! first message never yields a channel.
//!
//! The responder's side has no way to name its peer: the type carries no peer certificate. Whatever the
//! responder needs to decide about a request (a capability, a token) must travel inside the request.
//! What the responder still sees is outside this layer: the network address and the timing of the connection.
//!
//! The handshake itself is the sans-I/O state machines [`Initiate`], [`Respond`] and [`AwaitConfirmation`]: bytes
//! in, bytes out, no stream and no clock, for a host that handles each message in a separate callback (the
//! host keeps the deadlines). [`AnonymousChannel`] is built on them and writes the same bytes. A responder
//! evicted while it waits for the key confirmation can suspend its [`AwaitConfirmation`] and resume it, as a
//! [`Transport`] can ([`crate::noise::suspend`]).

use std::io::{Read, Write};
use std::time::Duration;

use alice_identity::device_cert::DeviceCert;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use crate::clock::SystemClock;
use crate::clock::{Clock, DefaultClock};
use crate::noise::nk::NkHandshakeState;
use crate::noise::suspend::{self, Phase};
use crate::noise::{
    ChannelId, Keypair, NoiseError, ResumeError, Resumed, SuspendKey, SuspendedTransport, Transport,
};
use crate::{
    dial_key, read_frame, read_frame_before, read_frame_within, write_frame, ChannelError,
    Credential, PeerPolicy, ReadTimeout, CONFIRMATION_LEN, MAX_PAYLOAD,
};

#[cfg(test)]
mod vectors;

/// The Noise prologue of an anonymous channel (different from [`crate::PROLOGUE`], so neither kind of first
/// message opens as the other)
pub const ANONYMOUS_PROLOGUE: &[u8] = b"alice-channel anonymous v1";

/// The length of the initiator's first message: its ephemeral key and the tag of the empty payload
pub const FIRST_MESSAGE_LEN: usize = 32 + CONFIRMATION_LEN;

/// The length of the responder's message: its ephemeral key and the tag of the empty payload
pub const RESPONSE_LEN: usize = 32 + CONFIRMATION_LEN;

/// The length of the initiator's key confirmation: one empty transport message, only its tag
pub const KEY_CONFIRMATION_LEN: usize = CONFIRMATION_LEN;

/// Why a step of the anonymous handshake ([`Initiate`], [`Respond`], [`AwaitConfirmation`]) refused its input
///
/// The step's state is consumed either way, so a refused handshake is never continued. Each message has
/// exactly one length, at which its payload is empty, so a payload shows as [`Self::Length`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousError {
    /// The message is not the exact length of its step ([`FIRST_MESSAGE_LEN`], [`RESPONSE_LEN`],
    /// [`KEY_CONFIRMATION_LEN`])
    Length {
        /// the length of the step's message
        expected: usize,
        /// the length given
        got: usize,
    },
    /// The message did not open (another static key, another prologue, a changed byte), or the ephemeral key
    /// could not be made
    Noise(NoiseError),
}

impl core::fmt::Display for AnonymousError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Length { expected, got } => {
                write!(
                    f,
                    "an anonymous handshake message of {got} bytes, not {expected}"
                )
            }
            Self::Noise(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AnonymousError {}

impl From<NoiseError> for AnonymousError {
    fn from(e: NoiseError) -> Self {
        Self::Noise(e)
    }
}

/// The stream channel reports a message of the wrong length as a message that does not open, as it always
/// has
impl From<AnonymousError> for ChannelError {
    fn from(e: AnonymousError) -> Self {
        match e {
            AnonymousError::Length { .. } => Self::Noise(NoiseError::Decrypt),
            AnonymousError::Noise(e) => Self::Noise(e),
        }
    }
}

/// A message of exactly `expected` bytes, or [`AnonymousError::Length`]
const fn exact(message: &[u8], expected: usize) -> Result<(), AnonymousError> {
    if message.len() == expected {
        Ok(())
    } else {
        Err(AnonymousError::Length {
            expected,
            got: message.len(),
        })
    }
}

/// The initiator's side of the anonymous handshake, without I/O and without a clock
///
/// [`Self::start`] gives the first message to send, [`Self::finish`] reads the responder's message and gives
/// the transport and the key confirmation to send. Deadlines belong to the host
pub struct Initiate {
    hs: NkHandshakeState,
}

impl Initiate {
    /// Start a handshake with the responder whose Noise static key is `responder_static`; returns the state
    /// and the first message ([`FIRST_MESSAGE_LEN`] bytes)
    ///
    /// # Errors
    /// [`AnonymousError::Noise`] when the ephemeral key cannot be made
    pub fn start(responder_static: [u8; 32]) -> Result<(Self, Vec<u8>), AnonymousError> {
        Self::begin(NkHandshakeState::initiator(
            ANONYMOUS_PROLOGUE,
            responder_static,
        ))
    }

    /// Check the responder's certificate against `policy` and start a handshake with the static key it names
    ///
    /// # Errors
    /// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] when the certificate is refused,
    /// [`ChannelError::Noise`] when the ephemeral key cannot be made
    pub fn dial(
        responder: &DeviceCert,
        policy: &impl PeerPolicy,
    ) -> Result<(Self, Vec<u8>), ChannelError> {
        let rs = dial_key(responder, policy)?;
        Ok(Self::start(rs)?)
    }

    /// As [`Self::start`] with a fixed ephemeral key, for test vectors only (feature `test-vectors`, off by default) (a reused ephemeral key voids the
    /// protocol's guarantees)
    ///
    /// # Errors
    /// As [`Self::start`]
    #[cfg(feature = "test-vectors")]
    pub fn start_with_ephemeral(
        responder_static: [u8; 32],
        ephemeral: Keypair,
    ) -> Result<(Self, Vec<u8>), AnonymousError> {
        Self::begin(NkHandshakeState::initiator_with_ephemeral(
            ANONYMOUS_PROLOGUE,
            responder_static,
            ephemeral,
        ))
    }

    fn begin(mut hs: NkHandshakeState) -> Result<(Self, Vec<u8>), AnonymousError> {
        // the first payload is empty: nothing of this side travels
        let first = hs.write_message(&[])?;
        Ok((Self { hs }, first))
    }

    /// Read the responder's message ([`RESPONSE_LEN`] bytes, an empty payload); returns the transport and
    /// the key confirmation to send ([`KEY_CONFIRMATION_LEN`] bytes)
    ///
    /// # Errors
    /// [`AnonymousError::Length`], [`AnonymousError::Noise`] (another static key answered, or a changed
    /// byte)
    pub fn finish(self, response: &[u8]) -> Result<(Transport, Vec<u8>), AnonymousError> {
        let mut hs = self.hs;
        exact(response, RESPONSE_LEN)?;
        if !hs.read_message(response)?.is_empty() {
            // unreachable at RESPONSE_LEN (the payload is the bytes after the ephemeral key and the tag)
            return Err(AnonymousError::Noise(NoiseError::Decrypt));
        }
        let mut transport = hs.into_transport()?;
        // key confirmation: the responder's handshake ends only once it opens this
        let confirmation = transport.send(&[])?;
        Ok((transport, confirmation))
    }
}

/// The responder's side of the anonymous handshake, without I/O and without a clock
///
/// [`Self::respond`] reads the first message and gives the response to send and an [`AwaitConfirmation`].
/// It holds only the responder's Noise static key: the initiator is not named
///
/// The state is consumed by each step, so a refused message ends the handshake:
///
/// ```compile_fail
/// # use alice_channel::anonymous::Respond;
/// # use alice_channel::noise::Keypair;
/// let r = Respond::new(Keypair::from_secret([7; 32]));
/// let _ = r.respond(&[0; 47]); // refused: AnonymousError::Length
/// let _ = r.respond(&[0; 48]); // the state was moved: does not compile
/// ```
pub struct Respond {
    hs: NkHandshakeState,
}

impl Respond {
    /// A responder with `static_key` as its Noise static key
    #[must_use]
    pub fn new(static_key: Keypair) -> Self {
        Self {
            hs: NkHandshakeState::responder(ANONYMOUS_PROLOGUE, static_key),
        }
    }

    /// As [`Self::new`] with a fixed ephemeral key, for test vectors only (feature `test-vectors`, off by default)
    #[cfg(feature = "test-vectors")]
    #[must_use]
    pub fn with_ephemeral(static_key: Keypair, ephemeral: Keypair) -> Self {
        Self {
            hs: NkHandshakeState::responder_with_ephemeral(
                ANONYMOUS_PROLOGUE,
                static_key,
                ephemeral,
            ),
        }
    }

    /// Read the initiator's first message ([`FIRST_MESSAGE_LEN`] bytes, an empty payload, for this static key
    /// under [`ANONYMOUS_PROLOGUE`]); returns the state that waits for the key confirmation and the response
    /// to send ([`RESPONSE_LEN`] bytes). Nothing should be sent when this fails
    ///
    /// # Errors
    /// [`AnonymousError::Length`], [`AnonymousError::Noise`]
    pub fn respond(self, first: &[u8]) -> Result<(AwaitConfirmation, Vec<u8>), AnonymousError> {
        let mut hs = self.hs;
        // the first message is always an ephemeral key and the tag of an empty payload: another length is
        // refused before any key agreement is done
        exact(first, FIRST_MESSAGE_LEN)?;
        if !hs.read_message(first)?.is_empty() {
            // unreachable at FIRST_MESSAGE_LEN
            return Err(AnonymousError::Noise(NoiseError::Decrypt));
        }
        let response = hs.write_message(&[])?;
        let transport = hs.into_transport()?;
        Ok((AwaitConfirmation { transport }, response))
    }
}

/// The responder's transport before the initiator's key confirmation has opened; a host evicted while it
/// waits can suspend it ([`Self::suspend`]) like an open transport
pub struct AwaitConfirmation {
    transport: Transport,
}

impl AwaitConfirmation {
    /// Open the key confirmation ([`KEY_CONFIRMATION_LEN`] bytes, an empty transport message); returns the
    /// transport
    ///
    /// # Errors
    /// [`AnonymousError::Length`], [`AnonymousError::Noise`]
    pub fn confirm(self, confirmation: &[u8]) -> Result<Transport, AnonymousError> {
        let mut transport = self.transport;
        exact(confirmation, KEY_CONFIRMATION_LEN)?;
        if !transport.recv(confirmation)?.is_empty() {
            // unreachable at KEY_CONFIRMATION_LEN
            return Err(AnonymousError::Noise(NoiseError::Decrypt));
        }
        Ok(transport)
    }

    /// The handshake hash both sides share
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.transport.handshake_hash()
    }

    /// The id of this channel (as [`Transport::channel_id`]), for the host to store at handshake time
    #[must_use]
    pub fn channel_id(&self) -> ChannelId {
        self.transport.channel_id()
    }

    /// Seal the waiting state under the host key (as [`Transport::suspend`], marked as waiting for the key
    /// confirmation)
    ///
    /// # Errors
    /// [`NoiseError::Randomness`]
    pub fn suspend(self, key: &SuspendKey) -> Result<SuspendedTransport, NoiseError> {
        suspend::seal(self.transport, Phase::AwaitingConfirmation, key)
    }

    /// Open a suspended waiting state (as [`Transport::resume`], with the same floor rule)
    ///
    /// # Errors
    /// As [`Transport::resume`]; [`ResumeError::Phase`] for a copy of an open transport
    pub fn resume(
        suspended: &SuspendedTransport,
        key: &SuspendKey,
        floor: u64,
        channel: ChannelId,
    ) -> Result<Resumed<Self>, ResumeError> {
        Ok(
            suspend::open(suspended, Phase::AwaitingConfirmation, key, floor, channel)?
                .map(|transport| Self { transport }),
        )
    }
}

/// A transport that carries whole messages (a WebSocket, a message queue, a datagram link with its own
/// framing): each `send` is one message and each `recv` returns one whole message
///
/// [`connect_messages`] and [`accept_messages`] run the anonymous handshake over it with the same bytes as
/// [`Initiate`] / [`Respond`]. Unlike [`AnonymousChannel`], no length prefix is added, since the transport
/// keeps message boundaries itself. Deadlines are the transport's: a `recv` that waits too long returns its
/// own error ([`ChannelError::Timeout`], for example)
pub trait MessageIo {
    /// Send `message` as one message
    ///
    /// # Errors
    /// The transport's own
    fn send(&mut self, message: &[u8]) -> Result<(), ChannelError>;
    /// Receive the next whole message; `max` is the longest message the caller accepts, so a transport may
    /// refuse a longer one before reading it (a longer one returned is refused by the caller)
    ///
    /// # Errors
    /// The transport's own
    fn recv(&mut self, max: usize) -> Result<Vec<u8>, ChannelError>;
}

/// Run the initiator's side of the anonymous handshake over a message transport
///
/// Check `responder` against `policy` and send the first message ([`FIRST_MESSAGE_LEN`] bytes), receive the response (exactly
/// [`RESPONSE_LEN`] bytes), send the key confirmation ([`KEY_CONFIRMATION_LEN`] bytes) and return the
/// transport keys
///
/// The bytes sent are those of [`Initiate::dial`] and [`Initiate::finish`]. Nothing is sent when `responder`
/// is refused
///
/// # Errors
/// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] when `responder` is refused (nothing is
/// sent), [`ChannelError::Noise`] when the response is not [`RESPONSE_LEN`] long or does not open (another
/// static key answered, a changed byte), the transport's own errors
pub fn connect_messages(
    io: &mut impl MessageIo,
    responder: &DeviceCert,
    policy: &impl PeerPolicy,
) -> Result<Transport, ChannelError> {
    let (init, first) = Initiate::dial(responder, policy)?;
    io.send(&first)?;
    // `finish` refuses any length but RESPONSE_LEN before any key agreement (one check, not a copy here)
    let response = io.recv(RESPONSE_LEN)?;
    let (transport, confirmation) = init.finish(&response)?;
    // key confirmation: the responder's handshake ends only once it opens this
    io.send(&confirmation)?;
    Ok(transport)
}

/// Run the responder's side of the anonymous handshake over a message transport
///
/// With the Noise static key `static_key`: receive the first message (exactly [`FIRST_MESSAGE_LEN`] bytes), send the response
/// ([`RESPONSE_LEN`] bytes), receive the key confirmation (exactly [`KEY_CONFIRMATION_LEN`] bytes) and return
/// the transport keys
///
/// The bytes are those of [`Respond::respond`] and [`AwaitConfirmation::confirm`]. Nothing is sent when the
/// first message is refused
///
/// # Errors
/// [`ChannelError::Noise`] when a message is not its step's length or does not open, the transport's own
/// errors
pub fn accept_messages(
    io: &mut impl MessageIo,
    static_key: &Keypair,
) -> Result<Transport, ChannelError> {
    let respond = Respond::new(static_key.clone());
    let first = io.recv(FIRST_MESSAGE_LEN)?;
    let (pending, response) = respond.respond(&first)?;
    io.send(&response)?;
    let confirmation = io.recv(KEY_CONFIRMATION_LEN)?;
    Ok(pending.confirm(&confirmation)?)
}

/// An open channel whose initiator is not named
///
/// It holds the transport keys over `S`, on the initiator's side the responder's certificate it dialled, and
/// the clock `C` its deadlines read (as for [`crate::SecureChannel`])
pub struct AnonymousChannel<S, C = DefaultClock> {
    stream: S,
    transport: Transport,
    responder: Option<DeviceCert>,
    poisoned: bool,
    clock: C,
}

impl<S: Read + Write + ReadTimeout, C: Clock> AnonymousChannel<S, C> {
    /// Receive the next message, waiting at most `deadline` for the whole of it
    ///
    /// # Errors
    /// [`ChannelError::Timeout`] when the message has not all come by then: the channel stays usable when
    /// no byte of it had come, and is poisoned otherwise; as [`Self::recv`] for the rest
    pub fn recv_before(&mut self, deadline: Duration) -> Result<Vec<u8>, ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        let frame = read_frame_within(&mut self.stream, &self.clock, deadline).map_err(
            |(e, started)| {
                self.poisoned = started;
                e
            },
        )?;
        self.poisoned = true;
        let payload = self.transport.recv(&frame)?;
        self.poisoned = false;
        Ok(payload)
    }

    /// Open an anonymous channel to the device `responder` certifies, reading time from `clock`. `responder` is checked against the
    /// policy before anything is written; the channel is returned once the responder's message has come
    /// within `timeout` and opened, and this side's key confirmation is sent before returning
    ///
    /// # Errors
    /// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] when `responder` is refused (nothing is
    /// written), [`ChannelError::Noise`] when the responder's message does not open (another static key),
    /// [`ChannelError::Timeout`], [`ChannelError::Closed`], [`ChannelError::Io`]
    pub fn connect_with_clock(
        mut stream: S,
        policy: &impl PeerPolicy,
        responder: &DeviceCert,
        timeout: Duration,
        clock: C,
    ) -> Result<Self, ChannelError> {
        let (init, first) = Initiate::dial(responder, policy)?;
        write_frame(&mut stream, &first)?;
        let frame = read_frame_before(&mut stream, &clock, timeout, None)?;
        let (transport, confirmation) = init.finish(&frame)?;
        // key confirmation: the responder's accept returns only after this
        write_frame(&mut stream, &confirmation)?;
        Ok(Self {
            stream,
            transport,
            responder: Some(responder.clone()),
            poisoned: false,
            clock,
        })
    }

    /// Accept an anonymous channel, reading time from `clock`. Nothing is written unless the first message opens for this side's static
    /// key under [`ANONYMOUS_PROLOGUE`] with an empty payload; the channel is returned once the initiator's
    /// key confirmation has come within `timeout`
    ///
    /// # Errors
    /// [`ChannelError::Noise`] when the first message does not open (another static key, another prologue,
    /// a non-empty payload) or its frame is not [`FIRST_MESSAGE_LEN`] long, [`ChannelError::Timeout`],
    /// [`ChannelError::Closed`], [`ChannelError::Io`]
    pub fn accept_with_clock(
        mut stream: S,
        cred: &Credential,
        timeout: Duration,
        clock: C,
    ) -> Result<Self, ChannelError> {
        let respond = Respond::new(cred.noise_static().clone());
        // a frame of another length than the first message is refused from its header, before any body is
        // read or any key agreement is done
        let first = read_frame_before(&mut stream, &clock, timeout, Some(FIRST_MESSAGE_LEN))?;
        let (pending, response) = respond.respond(&first)?;
        write_frame(&mut stream, &response)?;
        let frame = read_frame_before(&mut stream, &clock, timeout, Some(KEY_CONFIRMATION_LEN))?;
        let transport = pending.confirm(&frame)?;
        Ok(Self {
            stream,
            transport,
            responder: None,
            poisoned: false,
            clock,
        })
    }
}

/// The constructors without a clock argument: they use [`SystemClock`], so they do not exist on
/// `wasm32-unknown-unknown`
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl<S: Read + Write + ReadTimeout> AnonymousChannel<S, SystemClock> {
    /// Open an anonymous channel to the device `responder` certifies, waiting
    /// [`crate::DEFAULT_CONFIRM_TIMEOUT`] for its message
    ///
    /// # Errors
    /// As [`Self::connect_with_clock`] with [`SystemClock`]
    pub fn connect(
        stream: S,
        policy: &impl PeerPolicy,
        responder: &DeviceCert,
    ) -> Result<Self, ChannelError> {
        Self::connect_with_timeout(stream, policy, responder, crate::DEFAULT_CONFIRM_TIMEOUT)
    }

    /// As [`Self::connect_with_clock`] with [`SystemClock`]
    ///
    /// # Errors
    /// As [`Self::connect_with_clock`]
    pub fn connect_with_timeout(
        stream: S,
        policy: &impl PeerPolicy,
        responder: &DeviceCert,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        Self::connect_with_clock(stream, policy, responder, timeout, SystemClock)
    }

    /// Accept an anonymous channel as the device `cred` names, waiting [`crate::DEFAULT_CONFIRM_TIMEOUT`]
    ///
    /// # Errors
    /// As [`Self::accept_with_clock`] with [`SystemClock`]
    pub fn accept(stream: S, cred: &Credential) -> Result<Self, ChannelError> {
        Self::accept_with_timeout(stream, cred, crate::DEFAULT_CONFIRM_TIMEOUT)
    }

    /// As [`Self::accept_with_clock`] with [`SystemClock`]
    ///
    /// # Errors
    /// As [`Self::accept_with_clock`]
    pub fn accept_with_timeout(
        stream: S,
        cred: &Credential,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        Self::accept_with_clock(stream, cred, timeout, SystemClock)
    }
}

impl<S: Read + Write, C> AnonymousChannel<S, C> {
    /// Send one message
    ///
    /// # Errors
    /// [`ChannelError::TooLong`] above [`crate::MAX_PAYLOAD`], [`ChannelError::Io`], [`ChannelError::Noise`]
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
    /// [`ChannelError::Closed`], [`ChannelError::Io`], [`ChannelError::Noise`]
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

    /// On the initiator's side, the certificate of the responder it dialled; `None` on the responder's side
    #[must_use]
    pub const fn responder_cert(&self) -> Option<&DeviceCert> {
        self.responder.as_ref()
    }

    /// The handshake hash both sides share
    #[must_use]
    pub const fn handshake_hash(&self) -> [u8; 32] {
        self.transport.handshake_hash()
    }
}
