//! Oracle for the async channel (feature `async`): the same handshake and identity binding as the
//! blocking channel, over tokio streams, and safe to cancel. Dropping a future at an await point leaves no
//! half-open channel: a dropped handshake yields no channel, and the peer either fails its handshake or (when
//! the dropped side had already sent its last message) finds the peer gone on first use; a dropped send
//! or receive leaves the channel unusable (`ChannelError::Poisoned`) instead of out of step with its peer.
#![cfg(feature = "async")]

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use alice_channel::noise::Keypair;
use alice_channel::{AsyncSecureChannel, ChannelError, Credential, PeerPolicy};
use alice_identity::artifact::Revocation;
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey};
use tokio::io::{duplex, AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::Notify;
use tokio::time::timeout;

const NOW: u64 = 1_800_000_100;

struct Device {
    master: KeyPair,
    cred: Credential,
    did: Did,
}

fn device(seed: u8, name: &str) -> Device {
    let master = KeyPair::from_seed([seed; 32]);
    let key = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let did = Did::parse(&format!("did:alice:{name}")).unwrap();
    let cert = DeviceCert::issue(
        &master,
        &did,
        key.public().0,
        1_800_000_000,
        1_800_086_400,
        [seed; 16],
    )
    .unwrap();
    let cred = Credential::new(
        key,
        cert,
        Keypair::from_secret([seed.wrapping_add(200); 32]),
    )
    .unwrap();
    Device { master, cred, did }
}

struct Policy(HashMap<String, PublicKey>);

impl PeerPolicy for Policy {
    fn master_of(&self, subject: &Did) -> Option<PublicKey> {
        self.0.get(&subject.to_string()).copied()
    }
    fn revocation(&self) -> Revocation<'_> {
        Revocation::NoListAvailable
    }
    fn now(&self) -> u64 {
        NOW
    }
}

fn knowing(ds: &[&Device]) -> Policy {
    Policy(
        ds.iter()
            .map(|d| (d.did.to_string(), d.master.public()))
            .collect(),
    )
}

async fn open(
    cap: usize,
) -> (
    AsyncSecureChannel<DuplexStream>,
    AsyncSecureChannel<DuplexStream>,
) {
    let a = device(1, "alice");
    let b = device(2, "bob");
    let (sa, sb) = duplex(cap);
    let pb = knowing(&[&a]);
    let pa = knowing(&[&b]);
    let server = tokio::spawn(async move { AsyncSecureChannel::accept(sb, &b.cred, &pb).await });
    let client = AsyncSecureChannel::connect(sa, &a.cred, &pa).await.unwrap();
    (client, server.await.unwrap().unwrap())
}

#[tokio::test]
async fn two_devices_connect_and_exchange_messages() {
    let (mut a, mut b) = open(64 * 1024).await;
    a.send(b"ping").await.unwrap();
    assert_eq!(b.recv().await.unwrap(), b"ping");
    b.send(b"pong").await.unwrap();
    assert_eq!(a.recv().await.unwrap(), b"pong");
    assert_eq!(a.peer_cert().subject().to_string(), "did:alice:bob");
    assert_eq!(b.peer_cert().subject().to_string(), "did:alice:alice");
    assert_eq!(a.handshake_hash(), b.handshake_hash());
}

#[tokio::test]
async fn an_unknown_device_is_refused_in_the_handshake() {
    let a = device(1, "alice");
    let b = device(2, "bob");
    let (sa, sb) = duplex(64 * 1024);
    let nobody = knowing(&[]);
    let pa = knowing(&[&b]);
    let server =
        tokio::spawn(async move { AsyncSecureChannel::accept(sb, &b.cred, &nobody).await });
    let client = AsyncSecureChannel::connect(sa, &a.cred, &pa).await;
    assert!(matches!(
        server.await.unwrap(),
        Err(ChannelError::UnknownPeer)
    ));
    // key confirmation: connect does not return a channel the responder refused
    assert!(
        matches!(client, Err(ChannelError::Closed | ChannelError::Io(_))),
        "{:?}",
        client.err()
    );
}

#[tokio::test]
async fn a_send_dropped_mid_frame_poisons_the_channel() {
    // a 64-byte pipe: a 20 000-byte frame cannot be written while the peer does not read
    let (mut a, mut b) = open(64).await;
    assert!(
        timeout(Duration::from_millis(50), a.send(&vec![7u8; 20_000]))
            .await
            .is_err()
    );
    assert!(matches!(
        timeout(Duration::from_secs(1), a.send(b"x")).await,
        Ok(Err(ChannelError::Poisoned))
    ));
    assert!(matches!(
        timeout(Duration::from_secs(1), a.recv()).await,
        Ok(Err(ChannelError::Poisoned))
    ));
    // the peer sees a broken frame, not a message: it gets the half frame, then nothing more
    drop(a);
    assert!(b.recv().await.is_err());
}

#[tokio::test]
async fn a_receive_dropped_mid_frame_poisons_the_channel() {
    let (mut a, mut b) = open(64).await;
    // the peer's send stalls after the pipe is full, so only part of the frame is ever readable
    assert!(
        timeout(Duration::from_millis(50), b.send(&vec![9u8; 20_000]))
            .await
            .is_err()
    );
    assert!(timeout(Duration::from_millis(50), a.recv()).await.is_err());
    assert!(matches!(
        timeout(Duration::from_secs(1), a.recv()).await,
        Ok(Err(ChannelError::Poisoned))
    ));
    assert!(matches!(
        timeout(Duration::from_secs(1), a.send(b"x")).await,
        Ok(Err(ChannelError::Poisoned))
    ));
}

#[tokio::test]
async fn a_completed_send_and_receive_leave_the_channel_usable() {
    // the poison is only for an operation that did not finish
    let (mut a, mut b) = open(64 * 1024).await;
    for i in 0..10u8 {
        a.send(&[i; 100]).await.unwrap();
        assert_eq!(b.recv().await.unwrap(), vec![i; 100]);
    }
}

/// A stream that signals after its first completed read or write of at least one byte
struct Tap {
    inner: DuplexStream,
    on_read: bool,
    fired: Arc<AtomicBool>,
    signal: Arc<Notify>,
}

impl Tap {
    fn fire(&self) {
        if !self.fired.swap(true, Ordering::SeqCst) {
            self.signal.notify_one();
        }
    }
}

impl AsyncRead for Tap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // once fired the stream stalls: the future is held at this await point until it is dropped
        if self.fired.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        if self.on_read && matches!(r, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.fire();
        }
        r
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.fired.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if !self.on_read && matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            self.fire();
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The side that was not dropped either fails its handshake, or (when the dropped side had already sent its
/// last handshake message, so nothing could tell it) holds a channel whose first receive finds the peer gone:
/// never a channel that keeps working out of step
async fn survivor_is_not_in_step(
    r: Result<AsyncSecureChannel<DuplexStream>, ChannelError>,
    on_read: bool,
) {
    if let Ok(mut ch) = r {
        let next = timeout(Duration::from_secs(5), ch.recv()).await.unwrap();
        assert!(
            matches!(next, Err(ChannelError::Closed | ChannelError::Io(_))),
            "the surviving side kept a working channel (cancel on {}): {next:?}",
            if on_read { "read" } else { "write" }
        );
    }
}

/// Drop one side's handshake future after its first read (`on_read`) or first write; the other side's
/// handshake must then fail, never return a channel
async fn cancel_handshake(cancel_initiator: bool, on_read: bool) {
    let a = device(1, "alice");
    let b = device(2, "bob");
    let (sa, sb) = duplex(64 * 1024);
    let fired = Arc::new(AtomicBool::new(false));
    let signal = Arc::new(Notify::new());
    let (pa, pb) = (knowing(&[&b]), knowing(&[&a]));
    if cancel_initiator {
        let tap = Tap {
            inner: sa,
            on_read,
            fired: fired.clone(),
            signal: signal.clone(),
        };
        let server =
            tokio::spawn(async move { AsyncSecureChannel::accept(sb, &b.cred, &pb).await });
        tokio::select! {
            biased;
            () = signal.notified() => {}
            r = AsyncSecureChannel::connect(tap, &a.cred, &pa) => panic!("the handshake finished: {:?}", r.err()),
        }
        // the connecting side's stream is dropped with its future
        let r = timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        survivor_is_not_in_step(r, on_read).await;
    } else {
        let tap = Tap {
            inner: sb,
            on_read,
            fired: fired.clone(),
            signal: signal.clone(),
        };
        let client =
            tokio::spawn(async move { AsyncSecureChannel::connect(sa, &a.cred, &pa).await });
        tokio::select! {
            biased;
            () = signal.notified() => {}
            r = AsyncSecureChannel::accept(tap, &b.cred, &pb) => panic!("the handshake finished: {:?}", r.err()),
        }
        let r = timeout(Duration::from_secs(5), client)
            .await
            .unwrap()
            .unwrap();
        survivor_is_not_in_step(r, on_read).await;
    }
    assert!(fired.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_handshake_dropped_at_any_side_and_direction_gives_the_peer_no_channel() {
    cancel_handshake(true, false).await; // initiator, after writing message 0
    cancel_handshake(true, true).await; // initiator, while reading message 1
    cancel_handshake(false, true).await; // responder, while reading message 0
    cancel_handshake(false, false).await; // responder, after writing message 1
}

#[tokio::test]
async fn connect_gives_up_on_a_responder_that_never_confirms() {
    use alice_channel::noise::{HandshakeState, Role};
    use alice_channel::{sign_handshake, PROLOGUE};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let a = device(1, "alice");
    let b = device(2, "bob");
    let (sa, mut sb) = duplex(64 * 1024);
    let pa = knowing(&[&b]);
    let silent = tokio::spawn(async move {
        let read = |len: [u8; 2]| vec![0u8; usize::from(u16::from_be_bytes(len))];
        let mut hs = HandshakeState::new(Role::Responder, PROLOGUE, b.cred.noise_static().clone());
        let mut len = [0u8; 2];
        sb.read_exact(&mut len).await.unwrap();
        let mut m0 = read(len);
        sb.read_exact(&mut m0).await.unwrap();
        hs.read_message(&m0).unwrap();
        let m1 = hs
            .write_message_with(|h| sign_handshake(&b.cred, h).unwrap().to_bytes())
            .unwrap();
        sb.write_all(&u16::try_from(m1.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        sb.write_all(&m1).await.unwrap();
        sb.read_exact(&mut len).await.unwrap();
        let mut m2 = read(len);
        sb.read_exact(&mut m2).await.unwrap();
        // never confirm; keep the stream open
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(sb);
    });
    let start = std::time::Instant::now();
    let r = AsyncSecureChannel::connect_with_timeout(sa, &a.cred, &pa, Duration::from_millis(300))
        .await;
    assert!(matches!(r, Err(ChannelError::Timeout)), "{:?}", r.err());
    assert!(start.elapsed() < Duration::from_millis(1_200));
    silent.abort();
}

#[tokio::test]
async fn a_confirmation_frame_of_another_length_is_refused_before_its_body() {
    use alice_channel::noise::{HandshakeState, NoiseError, Role};
    use alice_channel::{sign_handshake, PROLOGUE};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let a = device(1, "alice");
    let b = device(2, "bob");
    let (sa, mut sb) = duplex(64 * 1024);
    let pa = knowing(&[&b]);
    let liar = tokio::spawn(async move {
        let mut hs = HandshakeState::new(Role::Responder, PROLOGUE, b.cred.noise_static().clone());
        let mut len = [0u8; 2];
        sb.read_exact(&mut len).await.unwrap();
        let mut m0 = vec![0u8; usize::from(u16::from_be_bytes(len))];
        sb.read_exact(&mut m0).await.unwrap();
        hs.read_message(&m0).unwrap();
        let m1 = hs
            .write_message_with(|h| sign_handshake(&b.cred, h).unwrap().to_bytes())
            .unwrap();
        sb.write_all(&u16::try_from(m1.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        sb.write_all(&m1).await.unwrap();
        sb.read_exact(&mut len).await.unwrap();
        let mut m2 = vec![0u8; usize::from(u16::from_be_bytes(len))];
        sb.read_exact(&mut m2).await.unwrap();
        // announce a 65 535-byte confirmation and send nothing more
        sb.write_all(&u16::MAX.to_be_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(sb);
    });
    let start = std::time::Instant::now();
    let r =
        AsyncSecureChannel::connect_with_timeout(sa, &a.cred, &pa, Duration::from_secs(2)).await;
    assert!(
        matches!(r, Err(ChannelError::Noise(NoiseError::Decrypt))),
        "{:?}",
        r.err()
    );
    assert!(start.elapsed() < Duration::from_millis(500));
    liar.abort();
}

#[tokio::test]
async fn split_halves_send_and_receive_at_the_same_time() {
    let (a, b) = open(64 * 1024).await;
    let hash = a.handshake_hash();
    let (mut a_tx, mut a_rx) = a.into_split().unwrap_or_else(|_| panic!("split"));
    let (mut b_tx, mut b_rx) = b.into_split().unwrap_or_else(|_| panic!("split"));
    assert_eq!(a_tx.peer_cert().subject().to_string(), "did:alice:bob");
    assert_eq!(a_rx.peer_cert().subject().to_string(), "did:alice:bob");
    assert_eq!(b_rx.peer_cert().subject().to_string(), "did:alice:alice");
    assert_eq!(a_tx.handshake_hash(), hash);
    assert_eq!(b_rx.handshake_hash(), hash);
    // both directions in flight together, each half on its own task
    let sends_a = tokio::spawn(async move {
        for i in 0..50u8 {
            a_tx.send(&[i; 300]).await.unwrap();
        }
    });
    let sends_b = tokio::spawn(async move {
        for i in 0..50u8 {
            b_tx.send(&[i.wrapping_add(100); 200]).await.unwrap();
        }
    });
    let recvs_b = tokio::spawn(async move {
        for i in 0..50u8 {
            assert_eq!(b_rx.recv().await.unwrap(), vec![i; 300]);
        }
    });
    for i in 0..50u8 {
        assert_eq!(a_rx.recv().await.unwrap(), vec![i.wrapping_add(100); 200]);
    }
    timeout(Duration::from_secs(5), async {
        sends_a.await.unwrap();
        sends_b.await.unwrap();
        recvs_b.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_send_dropped_on_the_send_half_poisons_only_that_half() {
    let (a, b) = open(64).await;
    let (mut a_tx, mut a_rx) = a.into_split().unwrap_or_else(|_| panic!("split"));
    let (mut b_tx, _b_rx) = b.into_split().unwrap_or_else(|_| panic!("split"));
    assert!(
        timeout(Duration::from_millis(50), a_tx.send(&vec![7u8; 20_000]))
            .await
            .is_err()
    );
    assert!(matches!(
        timeout(Duration::from_secs(1), a_tx.send(b"x")).await,
        Ok(Err(ChannelError::Poisoned))
    ));
    // the other direction has its own stream half and nonce: it is not out of step
    b_tx.send(b"still here").await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), a_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        b"still here"
    );
}

#[tokio::test]
async fn a_receive_dropped_on_the_receive_half_poisons_only_that_half() {
    let (a, b) = open(64).await;
    let (mut a_tx, mut a_rx) = a.into_split().unwrap_or_else(|_| panic!("split"));
    let (mut b_tx, mut b_rx) = b.into_split().unwrap_or_else(|_| panic!("split"));
    assert!(
        timeout(Duration::from_millis(50), b_tx.send(&vec![9u8; 20_000]))
            .await
            .is_err()
    );
    assert!(timeout(Duration::from_millis(50), a_rx.recv())
        .await
        .is_err());
    assert!(matches!(
        timeout(Duration::from_secs(1), a_rx.recv()).await,
        Ok(Err(ChannelError::Poisoned))
    ));
    a_tx.send(b"other way").await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), b_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        b"other way"
    );
}

#[tokio::test]
async fn a_dropped_half_leaves_the_other_half_working() {
    let (a, b) = open(64 * 1024).await;
    let (a_tx, mut a_rx) = a.into_split().unwrap_or_else(|_| panic!("split"));
    let (mut b_tx, _b_rx) = b.into_split().unwrap_or_else(|_| panic!("split"));
    drop(a_tx);
    b_tx.send(b"after drop").await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(1), a_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        b"after drop"
    );
}

#[tokio::test]
async fn a_poisoned_channel_is_not_split() {
    let (mut a, _b) = open(64).await;
    assert!(
        timeout(Duration::from_millis(50), a.send(&vec![7u8; 20_000]))
            .await
            .is_err()
    );
    assert!(matches!(a.into_split(), Err(ChannelError::Poisoned)));
}
