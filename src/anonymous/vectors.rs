//! The bytes of an anonymous channel with fixed keys, recorded before the stream channel was rebuilt on the
//! sans-I/O state machines ([`super::Initiate`], [`super::Respond`]): the recorded transcript comes from the
//! blocking implementation as it stood (each side's ephemeral key fixed through a test-only hook in the NK
//! handshake). The stream channel is held to it here; the state machines are held to the same bytes in
//! `tests/anonymous_vectors.rs` (feature `test-vectors`).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use alice_identity::artifact::Revocation;
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey};

use super::AnonymousChannel;
use crate::noise::nk::test_ephemeral;
use crate::noise::Keypair;
use crate::{Credential, PeerPolicy, ReadTimeout};

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_086_400;
const NOW: u64 = 1_800_000_100;
const TIMEOUT: Duration = Duration::from_secs(10);

/// The responder's Noise static secret and the two ephemeral secrets of the recorded run
const RESPONDER_STATIC: [u8; 32] = [0x07; 32];
const INITIATOR_EPHEMERAL: [u8; 32] = [0x11; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x22; 32];

/// The recorded run (`tests/data/anonymous_recorded.txt`, shared with `tests/anonymous_vectors.rs`): the
/// initiator's stream, both directions in the order it wrote and read them, recorded from the blocking
/// implementation at e7de79f, and the handshake hash
const RECORDED: &str = include_str!("../../tests/data/anonymous_recorded.txt");

fn recorded(field: &str) -> &'static str {
    RECORDED
        .lines()
        .find_map(|l| l.strip_prefix(field)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no {field} line"))
}

fn recorded_transcript() -> &'static str {
    recorded("transcript")
}

fn recorded_hash() -> &'static str {
    recorded("hash")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The frames of a stream transcript (a big-endian u16 length, then that many bytes)
fn frames(mut t: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while t.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([t[0], t[1]]));
        out.push(t[2..2 + n].to_vec());
        t = &t[2 + n..];
    }
    assert!(t.is_empty(), "a transcript ends at a frame boundary");
    out
}

struct Policy(BTreeMap<String, PublicKey>);

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

/// The responder's credential and the policy that knows its master
fn responder() -> (Credential, Policy) {
    let master = KeyPair::from_seed([0x31; 32]);
    let device = KeyPair::from_seed([0x32; 32]);
    let did = Did::parse("did:alice:responder").unwrap();
    let noise = Keypair::from_secret(RESPONDER_STATIC);
    let cert = DeviceCert::issue(
        &master,
        &did,
        device.public().0,
        noise.public(),
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap();
    let policy = Policy(std::iter::once((did.to_string(), master.public())).collect());
    (Credential::new(device, cert, noise).unwrap(), policy)
}

/// A stream that keeps a copy of every byte written and read
struct Recording {
    inner: TcpStream,
    log: Arc<Mutex<Vec<u8>>>,
}

impl Read for Recording {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.log.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for Recording {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.log.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl ReadTimeout for Recording {
    fn read_timeout(&self) -> std::io::Result<Option<Duration>> {
        self.inner.read_timeout()
    }
    fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(t)
    }
}

/// Run the stream channel with the fixed keys; returns the initiator's transcript and both handshake hashes
fn run_stream_channel() -> (Vec<u8>, [u8; 32], [u8; 32]) {
    let (cred, policy) = responder();
    let cert: DeviceCert = cred.cert().clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        test_ephemeral::set(Keypair::from_secret(RESPONDER_EPHEMERAL));
        let s = listener.accept().unwrap().0;
        let mut ch = AnonymousChannel::accept_with_timeout(s, &cred, TIMEOUT).unwrap();
        assert_eq!(ch.recv().unwrap(), b"ping");
        ch.send(b"pong").unwrap();
        ch.handshake_hash()
    });
    test_ephemeral::set(Keypair::from_secret(INITIATOR_EPHEMERAL));
    let log = Arc::new(Mutex::new(Vec::new()));
    let stream = Recording {
        inner: TcpStream::connect(addr).unwrap(),
        log: Arc::clone(&log),
    };
    let mut ch = AnonymousChannel::connect_with_timeout(stream, &policy, &cert, TIMEOUT).unwrap();
    ch.send(b"ping").unwrap();
    assert_eq!(ch.recv().unwrap(), b"pong");
    let hi = ch.handshake_hash();
    let hr = server.join().unwrap();
    let t = log.lock().unwrap().clone();
    (t, hi, hr)
}

#[test]
fn the_stream_channel_writes_the_recorded_bytes() {
    let (transcript, hi, hr) = run_stream_channel();
    assert_eq!(hi, hr);
    let got = hex(&transcript);
    assert!(
        !recorded_transcript().is_empty(),
        "no recorded transcript; this run gives\nTRANSCRIPT {got}\nHASH {}",
        hex(&hi)
    );
    assert_eq!(got, recorded_transcript());
    assert_eq!(hex(&hi), recorded_hash());
    let f = frames(&transcript);
    assert_eq!(
        f.iter().map(Vec::len).collect::<Vec<_>>(),
        [48, 48, 16, 20, 20],
        "first message, response, confirmation, two sealed 4-byte messages"
    );
}

#[test]
fn the_recorded_run_is_reproducible() {
    // the same fixed keys give the same bytes twice (nothing else random enters the transcript)
    assert_eq!(run_stream_channel().0, run_stream_channel().0);
}

#[test]
fn the_ephemeral_hook_changes_the_bytes() {
    // the tooth of the reproducibility test: without the hook the ephemeral keys come from the OS
    let (cred, policy) = responder();
    let cert = cred.cert().clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let s = listener.accept().unwrap().0;
        AnonymousChannel::accept_with_timeout(s, &cred, TIMEOUT).map(|_| ())
    });
    let log = Arc::new(Mutex::new(Vec::new()));
    let stream = Recording {
        inner: TcpStream::connect(addr).unwrap(),
        log: Arc::clone(&log),
    };
    AnonymousChannel::connect_with_timeout(stream, &policy, &cert, TIMEOUT).unwrap();
    server.join().unwrap().unwrap();
    let fresh = log.lock().unwrap().clone();
    assert_ne!(fresh, run_stream_channel().0);
}

#[test]
fn the_recorded_first_message_is_the_documented_nk_message() {
    // an oracle outside both implementations: the first frame is the NK first message with an empty
    // payload under ANONYMOUS_PROLOGUE, written by the NK layer the public NK test vector pins
    let rs = Keypair::from_secret(RESPONDER_STATIC).public();
    let mut hs = crate::noise::nk::NkHandshakeState::initiator_with_ephemeral(
        super::ANONYMOUS_PROLOGUE,
        rs,
        Keypair::from_secret(INITIATOR_EPHEMERAL),
    );
    let f = frames(&unhex(recorded_transcript()));
    assert_eq!(hs.write_message(&[]).unwrap(), f[0]);
    assert!(hs.read_message(&f[1]).unwrap().is_empty());
    assert_eq!(hex(&hs.handshake_hash()), recorded_hash());
}
