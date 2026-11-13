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

use std::io::{Read, Write};
use std::time::Duration;

use alice_identity::device_cert::DeviceCert;

use crate::noise::nk::NkHandshakeState;
use crate::noise::{NoiseError, Transport};
use crate::{
    dial_key, open_confirmation, read_frame, read_frame_before, read_frame_within, write_frame,
    ChannelError, Credential, PeerPolicy, ReadTimeout, CONFIRMATION_LEN, MAX_PAYLOAD,
};

/// The Noise prologue of an anonymous channel (different from [`crate::PROLOGUE`], so neither kind of first
/// message opens as the other)
pub const ANONYMOUS_PROLOGUE: &[u8] = b"alice-channel anonymous v1";

/// The length of the initiator's first message: its ephemeral key and the tag of the empty payload
pub const FIRST_MESSAGE_LEN: usize = 32 + CONFIRMATION_LEN;

/// An open channel whose initiator is not named: the transport keys over `S`, and on the initiator's side the
/// responder's certificate it dialled
pub struct AnonymousChannel<S> {
    stream: S,
    transport: Transport,
    responder: Option<DeviceCert>,
    poisoned: bool,
}

impl<S: Read + Write + ReadTimeout> AnonymousChannel<S> {
    /// Receive the next message, waiting at most `deadline` for the whole of it
    ///
    /// # Errors
    /// [`ChannelError::Timeout`] when the message has not all come by then: the channel stays usable when
    /// no byte of it had come, and is poisoned otherwise; as [`Self::recv`] for the rest
    pub fn recv_before(&mut self, deadline: Duration) -> Result<Vec<u8>, ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        let frame = read_frame_within(&mut self.stream, deadline).map_err(|(e, started)| {
            self.poisoned = started;
            e
        })?;
        self.poisoned = true;
        let payload = self.transport.recv(&frame)?;
        self.poisoned = false;
        Ok(payload)
    }

    /// Open an anonymous channel to the device `responder` certifies, waiting
    /// [`crate::DEFAULT_CONFIRM_TIMEOUT`] for its message
    ///
    /// # Errors
    /// As [`Self::connect_with_timeout`]
    pub fn connect(
        stream: S,
        policy: &impl PeerPolicy,
        responder: &DeviceCert,
    ) -> Result<Self, ChannelError> {
        Self::connect_with_timeout(stream, policy, responder, crate::DEFAULT_CONFIRM_TIMEOUT)
    }

    /// Open an anonymous channel to the device `responder` certifies. `responder` is checked against the
    /// policy before anything is written; the channel is returned once the responder's message has come
    /// within `timeout` and opened, and this side's key confirmation is sent before returning
    ///
    /// # Errors
    /// [`ChannelError::UnknownPeer`] / [`ChannelError::Rejected`] when `responder` is refused (nothing is
    /// written), [`ChannelError::Noise`] when the responder's message does not open (another static key),
    /// [`ChannelError::Timeout`], [`ChannelError::Closed`], [`ChannelError::Io`]
    pub fn connect_with_timeout(
        mut stream: S,
        policy: &impl PeerPolicy,
        responder: &DeviceCert,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        let rs = dial_key(responder, policy)?;
        let mut hs = NkHandshakeState::initiator(ANONYMOUS_PROLOGUE, rs);
        // the first payload is empty: nothing of this side travels
        write_frame(&mut stream, &hs.write_message(&[])?)?;
        let frame = read_frame_before(&mut stream, timeout, None)?;
        if !hs.read_message(&frame)?.is_empty() {
            return Err(ChannelError::Noise(NoiseError::Decrypt));
        }
        let mut transport = hs.into_transport()?;
        // key confirmation: the responder's accept returns only after this
        write_frame(&mut stream, &transport.send(&[])?)?;
        Ok(Self {
            stream,
            transport,
            responder: Some(responder.clone()),
            poisoned: false,
        })
    }

    /// Accept an anonymous channel as the device `cred` names, waiting [`crate::DEFAULT_CONFIRM_TIMEOUT`]
    ///
    /// # Errors
    /// As [`Self::accept_with_timeout`]
    pub fn accept(stream: S, cred: &Credential) -> Result<Self, ChannelError> {
        Self::accept_with_timeout(stream, cred, crate::DEFAULT_CONFIRM_TIMEOUT)
    }

    /// Accept an anonymous channel. Nothing is written unless the first message opens for this side's static
    /// key under [`ANONYMOUS_PROLOGUE`] with an empty payload; the channel is returned once the initiator's
    /// key confirmation has come within `timeout`
    ///
    /// # Errors
    /// [`ChannelError::Noise`] when the first message does not open (another static key, another prologue,
    /// a non-empty payload) or its frame is not [`FIRST_MESSAGE_LEN`] long, [`ChannelError::Timeout`],
    /// [`ChannelError::Closed`], [`ChannelError::Io`]
    pub fn accept_with_timeout(
        mut stream: S,
        cred: &Credential,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        let mut hs = NkHandshakeState::responder(ANONYMOUS_PROLOGUE, cred.noise_static().clone());
        // the first message is always an ephemeral key and the tag of an empty payload: a frame of another
        // length is refused from its header, before any body is read or any key agreement is done
        let first = read_frame_before(&mut stream, timeout, Some(FIRST_MESSAGE_LEN))?;
        if !hs.read_message(&first)?.is_empty() {
            return Err(ChannelError::Noise(NoiseError::Decrypt));
        }
        write_frame(&mut stream, &hs.write_message(&[])?)?;
        let mut transport = hs.into_transport()?;
        let frame = read_frame_before(&mut stream, timeout, Some(CONFIRMATION_LEN))?;
        open_confirmation(&mut transport, &frame)?;
        Ok(Self {
            stream,
            transport,
            responder: None,
            poisoned: false,
        })
    }
}

impl<S: Read + Write> AnonymousChannel<S> {
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
