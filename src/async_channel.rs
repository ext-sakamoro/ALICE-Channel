//! The channel over tokio streams (feature `async`): the same handshake, identity binding and key
//! confirmation as [`crate::SecureChannel`], built on the same sans-IO Noise layer and checks.
//!
//! Every future here is safe to drop. A dropped `connect` or `accept` yields no channel (the stream goes
//! with it, so the peer's handshake fails). A dropped `send` or `recv` may have written or read part of a
//! frame, or advanced a nonce; the channel is then [`ChannelError::Poisoned`] and refuses every further
//! operation instead of continuing out of step with its peer.
//!
//! [`AsyncSecureChannel::into_split`] separates the channel into a sending and a receiving half, each with
//! its own stream half and nonce, so that both directions can run on separate tasks. Each half is poisoned
//! on its own: a dropped send leaves the receiving half usable, and the other way round.

use std::time::Duration;

use alice_identity::device_cert::DeviceCert;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use crate::noise::{HandshakeState, Transport, TransportReceiver, TransportSender};
use crate::{
    dial_key, expect_subject, open_confirmation, verify_peer, write_signed, ChannelError,
    Credential, PeerPolicy, CONFIRMATION_LEN, DEFAULT_CONFIRM_TIMEOUT, MAX_PAYLOAD, PROLOGUE,
};

fn io(e: &std::io::Error) -> ChannelError {
    ChannelError::Io(e.kind())
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<(), ChannelError> {
    let len = u16::try_from(bytes.len()).map_err(|_| ChannelError::TooLong)?;
    // one buffer, one write: a frame is either handed to the stream whole or the operation did not finish
    let mut frame = Vec::with_capacity(2 + bytes.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(bytes);
    stream.write_all(&frame).await.map_err(|e| io(&e))?;
    stream.flush().await.map_err(|e| io(&e))
}

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, ChannelError> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ChannelError::Closed)
        }
        Err(e) => return Err(io(&e)),
    }
    let mut bytes = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut bytes).await.map_err(|e| io(&e))?;
    Ok(bytes)
}

/// Read the confirmation frame: a frame of another length than an empty message is refused before its body
async fn read_confirmation<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, ChannelError> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ChannelError::Closed)
        }
        Err(e) => return Err(io(&e)),
    }
    if usize::from(u16::from_be_bytes(len)) != CONFIRMATION_LEN {
        return Err(ChannelError::Noise(crate::noise::NoiseError::Decrypt));
    }
    let mut body = vec![0u8; CONFIRMATION_LEN];
    stream.read_exact(&mut body).await.map_err(|e| io(&e))?;
    Ok(body)
}

/// An open channel over a tokio stream
pub struct AsyncSecureChannel<S> {
    stream: S,
    transport: Transport,
    peer: DeviceCert,
    poisoned: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncSecureChannel<S> {
    /// Open a channel to the device `peer` certifies, as the side that connected, waiting
    /// [`DEFAULT_CONFIRM_TIMEOUT`] for the responder's message
    ///
    /// # Errors
    /// As [`Self::connect_with_timeout`]
    pub async fn connect(
        stream: S,
        cred: &Credential,
        policy: &(impl PeerPolicy + Sync),
        peer: &DeviceCert,
    ) -> Result<Self, ChannelError> {
        Self::connect_with_timeout(stream, cred, policy, peer, DEFAULT_CONFIRM_TIMEOUT).await
    }

    /// Open a channel to the device `peer` certifies, as the side that connected; see
    /// [`crate::SecureChannel::connect_with_timeout`]
    ///
    /// # Errors
    /// As [`crate::SecureChannel::connect_with_timeout`]
    pub async fn connect_with_timeout(
        mut stream: S,
        cred: &Credential,
        policy: &(impl PeerPolicy + Sync),
        peer: &DeviceCert,
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        let rs = dial_key(peer, policy)?;
        let mut hs = HandshakeState::initiator(PROLOGUE, cred.noise_static().clone(), rs);
        write_frame(&mut stream, &write_signed(&mut hs, cred)?).await?;
        let frame = tokio::time::timeout(timeout, read_frame(&mut stream))
            .await
            .map_err(|_| ChannelError::Timeout)??;
        let (payload, h) = hs.read_message_with_hash(&frame)?;
        let got = verify_peer(&payload, &h, hs.remote_static(), policy)?;
        let peer = expect_subject(got, peer)?;
        let mut transport = hs.into_transport()?;
        write_frame(&mut stream, &transport.send(&[])?).await?;
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
    pub async fn accept(
        stream: S,
        cred: &Credential,
        policy: &(impl PeerPolicy + Sync),
    ) -> Result<Self, ChannelError> {
        Self::accept_with_timeout(stream, cred, policy, DEFAULT_CONFIRM_TIMEOUT).await
    }

    /// Open a channel as the side that accepted the connection; see
    /// [`crate::SecureChannel::accept_with_timeout`]
    ///
    /// # Errors
    /// As [`crate::SecureChannel::accept_with_timeout`]
    pub async fn accept_with_timeout(
        mut stream: S,
        cred: &Credential,
        policy: &(impl PeerPolicy + Sync),
        timeout: Duration,
    ) -> Result<Self, ChannelError> {
        let mut hs = HandshakeState::responder(PROLOGUE, cred.noise_static().clone());
        let first = tokio::time::timeout(timeout, read_frame(&mut stream))
            .await
            .map_err(|_| ChannelError::Timeout)??;
        let (payload, h) = hs.read_message_with_hash(&first)?;
        let peer = verify_peer(&payload, &h, hs.remote_static(), policy)?;
        write_frame(&mut stream, &write_signed(&mut hs, cred)?).await?;
        let mut transport = hs.into_transport()?;
        let frame = tokio::time::timeout(timeout, read_confirmation(&mut stream))
            .await
            .map_err(|_| ChannelError::Timeout)??;
        open_confirmation(&mut transport, &frame)?;
        Ok(Self {
            stream,
            transport,
            peer,
            poisoned: false,
        })
    }

    /// Send one message
    ///
    /// # Errors
    /// [`ChannelError::Poisoned`] after an operation that did not finish, [`ChannelError::TooLong`] above
    /// [`MAX_PAYLOAD`], [`ChannelError::Io`], [`ChannelError::Noise`]
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(ChannelError::TooLong);
        }
        // set before the first await: a future dropped from here on leaves the channel poisoned
        self.poisoned = true;
        let msg = self.transport.send(payload)?;
        write_frame(&mut self.stream, &msg).await?;
        self.poisoned = false;
        Ok(())
    }

    /// Receive the next message
    ///
    /// # Errors
    /// [`ChannelError::Poisoned`], [`ChannelError::Closed`], [`ChannelError::Io`], [`ChannelError::Noise`]
    pub async fn recv(&mut self) -> Result<Vec<u8>, ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        self.poisoned = true;
        let frame = read_frame(&mut self.stream).await?;
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

    /// Separate the channel into a sending and a receiving half
    ///
    /// # Errors
    /// [`ChannelError::Poisoned`] when an earlier operation did not finish: neither direction can be trusted
    /// to be in step then
    pub fn into_split(self) -> Result<(AsyncSendHalf<S>, AsyncRecvHalf<S>), ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        let (read, write) = tokio::io::split(self.stream);
        let (sender, receiver) = self.transport.split();
        Ok((
            AsyncSendHalf {
                stream: write,
                transport: sender,
                peer: self.peer.clone(),
                poisoned: false,
            },
            AsyncRecvHalf {
                stream: read,
                transport: receiver,
                peer: self.peer,
                poisoned: false,
            },
        ))
    }
}

/// The sending half of a split [`AsyncSecureChannel`]
pub struct AsyncSendHalf<S> {
    stream: WriteHalf<S>,
    transport: TransportSender,
    peer: DeviceCert,
    poisoned: bool,
}

impl<S: AsyncWrite> AsyncSendHalf<S> {
    /// Send one message
    ///
    /// # Errors
    /// As [`AsyncSecureChannel::send`]; [`ChannelError::Poisoned`] only after a send on this half that did
    /// not finish
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(ChannelError::TooLong);
        }
        self.poisoned = true;
        let msg = self.transport.send(payload)?;
        write_frame(&mut self.stream, &msg).await?;
        self.poisoned = false;
        Ok(())
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

/// The receiving half of a split [`AsyncSecureChannel`]
pub struct AsyncRecvHalf<S> {
    stream: ReadHalf<S>,
    transport: TransportReceiver,
    peer: DeviceCert,
    poisoned: bool,
}

impl<S: AsyncRead> AsyncRecvHalf<S> {
    /// Receive the next message
    ///
    /// # Errors
    /// As [`AsyncSecureChannel::recv`]; [`ChannelError::Poisoned`] only after a receive on this half that
    /// did not finish
    pub async fn recv(&mut self) -> Result<Vec<u8>, ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        self.poisoned = true;
        let frame = read_frame(&mut self.stream).await?;
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
