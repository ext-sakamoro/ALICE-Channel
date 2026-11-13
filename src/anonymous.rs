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
//! Not implemented yet: every method fails fast.

use std::io::{Read, Write};
use std::time::Duration;

use alice_identity::device_cert::DeviceCert;

use crate::{ChannelError, Credential, PeerPolicy, ReadTimeout};

/// The Noise prologue of an anonymous channel (different from [`crate::PROLOGUE`], so neither kind of first
/// message opens as the other)
pub const ANONYMOUS_PROLOGUE: &[u8] = b"alice-channel anonymous v1";

/// An open channel whose initiator is not named: the transport keys over `S`, and on the initiator's side the
/// responder's certificate it dialled
pub struct AnonymousChannel<S> {
    _stream: S,
}

impl<S: Read + Write + ReadTimeout> AnonymousChannel<S> {
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
        stream: S,
        policy: &impl PeerPolicy,
        responder: &DeviceCert,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        let _ = (stream, policy, responder, timeout);
        todo!("anonymous connect")
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
    /// a non-empty payload), [`ChannelError::Timeout`], [`ChannelError::Closed`], [`ChannelError::Io`]
    pub fn accept_with_timeout(
        stream: S,
        cred: &Credential,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        let _ = (stream, cred, timeout);
        todo!("anonymous accept")
    }

    /// Send one message
    ///
    /// # Errors
    /// [`ChannelError::TooLong`] above [`crate::MAX_PAYLOAD`], [`ChannelError::Io`], [`ChannelError::Noise`]
    pub fn send(&mut self, payload: &[u8]) -> Result<(), ChannelError> {
        let _ = payload;
        todo!("anonymous send")
    }

    /// Receive the next message
    ///
    /// # Errors
    /// [`ChannelError::Closed`], [`ChannelError::Io`], [`ChannelError::Noise`]
    pub fn recv(&mut self) -> Result<Vec<u8>, ChannelError> {
        todo!("anonymous recv")
    }

    /// On the initiator's side, the certificate of the responder it dialled; `None` on the responder's side
    #[must_use]
    pub fn responder_cert(&self) -> Option<&DeviceCert> {
        todo!("anonymous responder_cert")
    }

    /// The handshake hash both sides share
    #[must_use]
    pub fn handshake_hash(&self) -> [u8; 32] {
        todo!("anonymous handshake_hash")
    }
}
