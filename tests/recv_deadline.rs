//! Oracle for `recv_before`: one deadline for a whole frame, after the handshake.
//!
//! - a silent peer gives `Timeout`, no earlier than the deadline and well before a margin after it;
//! - a peer that sends one byte at a time still gives `Timeout` by the deadline (the deadline is not
//!   renewed by each byte);
//! - a deadline of zero, or one already past, gives `Timeout` without reading;
//! - a `Timeout` before the first byte of a frame leaves the channel usable: the next frame is received;
//! - a `Timeout` after part of a frame leaves the channel poisoned;
//! - the read timeout the stream had before the call is set back on it.
//!
//! Each holds for both channel types; the peer's bytes are written on a clone of its socket, so the
//! partial and slow frames are exactly what the test wrote.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use alice_channel::noise::Keypair;
use alice_channel::{
    AnonymousChannel, ChannelError, Credential, PeerPolicy, ReadTimeout, SecureChannel,
};
use alice_identity::artifact::Revocation;
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey};

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_086_400;
const NOW: u64 = 1_800_000_100;
const DEADLINE: Duration = Duration::from_millis(200);
const MARGIN: Duration = Duration::from_millis(1_500);
/// The read timeout the stream holds before each call (set back after it)
const STREAM_TIMEOUT: Option<Duration> = Some(Duration::from_secs(41));

struct Party {
    master: KeyPair,
    did: Did,
    cred: Credential,
}

fn party(seed: u8, name: &str) -> Party {
    let master = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let did = Did::parse(&format!("did:alice:{name}")).unwrap();
    let noise = Keypair::from_secret([seed.wrapping_add(200); 32]);
    let cert = DeviceCert::issue(
        &master,
        &did,
        device.public().0,
        noise.public(),
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap();
    Party {
        master,
        did,
        cred: Credential::new(device, cert, noise).unwrap(),
    }
}

struct Policy(BTreeMap<String, PublicKey>);

impl Policy {
    fn knowing(parties: &[&Party]) -> Self {
        Self(
            parties
                .iter()
                .map(|p| (p.did.to_string(), p.master.public()))
                .collect(),
        )
    }
}

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

/// The receiving side's stream: counts reads made after `armed`, and keeps its read timeout to look at
#[derive(Clone)]
struct Probe {
    inner: Arc<Mutex<TcpStream>>,
    reads: Arc<AtomicUsize>,
    timeout: Arc<Mutex<Option<Duration>>>,
    /// when set, setting this timeout fails (to make setting back the caller's timeout fail)
    refuse: Arc<Mutex<Option<Option<Duration>>>>,
}

impl Read for Probe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let s = self.inner.lock().unwrap().try_clone()?;
        (&s).read(buf)
    }
}

impl Write for Probe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = self.inner.lock().unwrap().try_clone()?;
        (&s).write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ReadTimeout for Probe {
    fn read_timeout(&self) -> std::io::Result<Option<Duration>> {
        Ok(*self.timeout.lock().unwrap())
    }
    fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        if *self.refuse.lock().unwrap() == Some(t) {
            return Err(std::io::Error::other("refused"));
        }
        self.inner.lock().unwrap().set_read_timeout(t)?;
        *self.timeout.lock().unwrap() = t;
        Ok(())
    }
}

fn probe(s: TcpStream) -> Probe {
    Probe {
        inner: Arc::new(Mutex::new(s)),
        reads: Arc::new(AtomicUsize::new(0)),
        timeout: Arc::new(Mutex::new(None)),
        refuse: Arc::new(Mutex::new(None)),
    }
}

/// The receiving channel, its probe, and the peer's raw socket (after the handshake)
trait Receiving {
    fn within(&mut self, d: Duration) -> Result<Vec<u8>, ChannelError>;
}

impl Receiving for AnonymousChannel<Probe> {
    fn within(&mut self, d: Duration) -> Result<Vec<u8>, ChannelError> {
        self.recv_before(d)
    }
}

impl Receiving for SecureChannel<Probe> {
    fn within(&mut self, d: Duration) -> Result<Vec<u8>, ChannelError> {
        self.recv_before(d)
    }
}

/// A peer sender: sends a whole message through its channel
type Send = Box<dyn FnMut(&[u8])>;

fn anonymous() -> (Box<dyn Receiving>, Probe, TcpStream, Send) {
    let server = party(1, "server");
    let server_cert = server.cred.cert().clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = thread::spawn(move || {
        let p = probe(listener.accept().unwrap().0);
        let ch = AnonymousChannel::accept(p.clone(), &server.cred).unwrap();
        (ch, p)
    });
    let s = TcpStream::connect(addr).unwrap();
    let raw = s.try_clone().unwrap();
    let mut client =
        AnonymousChannel::connect(s, &Policy::knowing(&[&party(1, "server")]), &server_cert)
            .unwrap();
    let (ch, p) = h.join().unwrap();
    (
        Box::new(ch),
        p,
        raw,
        Box::new(move |m: &[u8]| client.send(m).unwrap()),
    )
}

fn named() -> (Box<dyn Receiving>, Probe, TcpStream, Send) {
    let server = party(1, "server");
    let client_party = party(2, "client");
    let server_cert = server.cred.cert().clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = thread::spawn(move || {
        let p = probe(listener.accept().unwrap().0);
        let ch = SecureChannel::accept(
            p.clone(),
            &server.cred,
            &Policy::knowing(&[&party(2, "client")]),
        )
        .unwrap();
        (ch, p)
    });
    let s = TcpStream::connect(addr).unwrap();
    let raw = s.try_clone().unwrap();
    let mut client = SecureChannel::connect(
        s,
        &client_party.cred,
        &Policy::knowing(&[&party(1, "server")]),
        &server_cert,
    )
    .unwrap();
    let (ch, p) = h.join().unwrap();
    (
        Box::new(ch),
        p,
        raw,
        Box::new(move |m: &[u8]| client.send(m).unwrap()),
    )
}

/// The wall clock of the timing tests (how long a deadline takes; no Law value)
#[expect(
    clippy::disallowed_methods,
    reason = "a timing test measures a deadline on the monotonic clock"
)]
fn started() -> std::time::Instant {
    std::time::Instant::now()
}

/// The time since `start` (see [`started`])
#[expect(
    clippy::disallowed_methods,
    reason = "a timing test measures a deadline on the monotonic clock"
)]
fn waited(start: std::time::Instant) -> Duration {
    start.elapsed()
}

type Maker = fn() -> (Box<dyn Receiving>, Probe, TcpStream, Send);
const BOTH: [(&str, Maker); 2] = [("anonymous", anonymous), ("named", named)];

#[test]
fn a_silent_peer_gives_timeout_at_the_deadline() {
    for (name, make) in BOTH {
        let (mut ch, p, _raw, _send) = make();
        p.set_read_timeout(STREAM_TIMEOUT).unwrap();
        let t0 = started();
        let r = ch.within(DEADLINE);
        let took = waited(t0);
        assert!(matches!(r, Err(ChannelError::Timeout)), "{name}: {r:?}");
        assert!(took >= DEADLINE, "{name}: gave up after {took:?}");
        assert!(took < DEADLINE + MARGIN, "{name}: took {took:?}");
        assert_eq!(
            p.read_timeout().unwrap(),
            STREAM_TIMEOUT,
            "{name}: timeout not set back"
        );
    }
}

#[test]
fn a_peer_sending_one_byte_at_a_time_gives_timeout_by_the_deadline() {
    for (name, make) in BOTH {
        let (mut ch, p, mut raw, _send) = make();
        p.set_read_timeout(STREAM_TIMEOUT).unwrap();
        // a frame of 200 bytes, one byte every 40 ms: whole after 8 s, far past the deadline
        let drip = thread::spawn(move || {
            let _ = raw.write_all(&200u16.to_be_bytes());
            for _ in 0..200 {
                thread::sleep(Duration::from_millis(40));
                if raw.write_all(&[0x5a]).is_err() {
                    return;
                }
            }
        });
        let t0 = started();
        let r = ch.within(DEADLINE);
        let took = waited(t0);
        assert!(matches!(r, Err(ChannelError::Timeout)), "{name}: {r:?}");
        assert!(took < DEADLINE + MARGIN, "{name}: took {took:?}");
        assert!(
            matches!(ch.within(DEADLINE), Err(ChannelError::Poisoned)),
            "{name}: part of a frame was read, so the channel is out of step"
        );
        assert_eq!(
            p.read_timeout().unwrap(),
            STREAM_TIMEOUT,
            "{name}: timeout not set back"
        );
        drop(ch);
        drop(p);
        let _ = drip.join();
    }
}

#[test]
fn a_zero_or_past_deadline_gives_timeout_without_reading() {
    for (name, make) in BOTH {
        let (mut ch, p, _raw, mut send) = make();
        send(b"waiting");
        thread::sleep(Duration::from_millis(50));
        let before = p.reads.load(Ordering::SeqCst);
        assert!(
            matches!(ch.within(Duration::ZERO), Err(ChannelError::Timeout)),
            "{name}"
        );
        assert_eq!(
            p.reads.load(Ordering::SeqCst),
            before,
            "{name}: read with no time left"
        );
        // nothing was read, so the waiting message still comes whole
        assert_eq!(ch.within(MARGIN).unwrap(), b"waiting", "{name}");
    }
}

#[test]
fn a_timeout_before_the_first_byte_leaves_the_channel_usable() {
    for (name, make) in BOTH {
        let (mut ch, _p, _raw, mut send) = make();
        assert!(
            matches!(ch.within(DEADLINE), Err(ChannelError::Timeout)),
            "{name}"
        );
        send(b"after the wait");
        assert_eq!(ch.within(MARGIN).unwrap(), b"after the wait", "{name}");
        send(b"and the next");
        assert_eq!(ch.within(MARGIN).unwrap(), b"and the next", "{name}");
    }
}

#[test]
fn a_timeout_after_part_of_a_frame_poisons_the_channel() {
    for (name, make) in BOTH {
        let (mut ch, _p, mut raw, _send) = make();
        raw.write_all(&[0x00]).unwrap(); // the first byte of a length, and no more
        assert!(
            matches!(ch.within(DEADLINE), Err(ChannelError::Timeout)),
            "{name}"
        );
        raw.write_all(&[0x10]).unwrap();
        assert!(
            matches!(ch.within(DEADLINE), Err(ChannelError::Poisoned)),
            "{name}"
        );
    }
}

#[test]
fn a_timeout_that_cannot_set_back_the_stream_timeout_poisons_the_channel() {
    for (name, make) in BOTH {
        let (mut ch, p, _raw, mut send) = make();
        p.set_read_timeout(STREAM_TIMEOUT).unwrap();
        *p.refuse.lock().unwrap() = Some(STREAM_TIMEOUT);
        assert!(
            matches!(ch.within(DEADLINE), Err(ChannelError::Timeout)),
            "{name}"
        );
        // the stream kept the short timeout of the call: the channel is not used on as if it had not
        *p.refuse.lock().unwrap() = None;
        send(b"later");
        assert!(
            matches!(ch.within(MARGIN), Err(ChannelError::Poisoned)),
            "{name}"
        );
    }
}
