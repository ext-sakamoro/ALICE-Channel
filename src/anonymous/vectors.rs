//! The bytes of an anonymous channel with fixed keys, recorded before the stream channel was rebuilt on the
//! sans-I/O state machines ([`super::Initiate`], [`super::Respond`]): the recorded transcript comes from the
//! blocking implementation as it stood (each side's ephemeral key fixed through a test-only hook in the NK
//! handshake), so the stream channel and the state machines are both held to the same wire bytes.

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
pub(super) const RESPONDER_STATIC: [u8; 32] = [0x07; 32];
pub(super) const INITIATOR_EPHEMERAL: [u8; 32] = [0x11; 32];
pub(super) const RESPONDER_EPHEMERAL: [u8; 32] = [0x22; 32];

/// The initiator's stream, both directions in the order it wrote and read them: frame(first message),
/// frame(responder's message), frame(key confirmation), frame(seal("ping")), frame(seal("pong")); recorded
/// from the blocking implementation at e7de79f
pub(super) const RECORDED_TRANSCRIPT: &str = concat!(
    "00307b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f133ff3385aa24ecb59ce21f92c751ab272",
    "00300faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f208eb67227864f582ff5f6ec7b265fa2bf",
    "00104a0f6b5890dfdd2b8835166ce1c996fe",
    "00143d05b65583a06c15fa16cec7152b955ecb322013",
    "0014c903829f3d6f7ce4af7f23595181a3fd66e2f7d7",
);

/// The handshake hash of the recorded run
pub(super) const RECORDED_HANDSHAKE_HASH: &str =
    "9ab3284d75309cdb46e9e6663bac4df8c662bec04671c70413d679edbd83db4e";

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub(super) fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The frames of a stream transcript (a big-endian u16 length, then that many bytes)
pub(super) fn frames(mut t: &[u8]) -> Vec<Vec<u8>> {
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
        !RECORDED_TRANSCRIPT.is_empty(),
        "no recorded transcript; this run gives\nTRANSCRIPT {got}\nHASH {}",
        hex(&hi)
    );
    assert_eq!(got, RECORDED_TRANSCRIPT);
    assert_eq!(hex(&hi), RECORDED_HANDSHAKE_HASH);
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
    let f = frames(&unhex(RECORDED_TRANSCRIPT));
    assert_eq!(hs.write_message(&[]).unwrap(), f[0]);
    assert!(hs.read_message(&f[1]).unwrap().is_empty());
    assert_eq!(hex(&hs.handshake_hash()), RECORDED_HANDSHAKE_HASH);
}

#[test]
fn the_state_machines_write_the_recorded_bytes() {
    let f = frames(&unhex(RECORDED_TRANSCRIPT));
    let rs = Keypair::from_secret(RESPONDER_STATIC).public();
    let (init, first) =
        super::Initiate::start_with_ephemeral(rs, Keypair::from_secret(INITIATOR_EPHEMERAL))
            .unwrap();
    assert_eq!(first, f[0], "first message");
    let resp = super::Respond::with_ephemeral(
        Keypair::from_secret(RESPONDER_STATIC),
        Keypair::from_secret(RESPONDER_EPHEMERAL),
    );
    let (pending, response) = resp.respond(&first).unwrap();
    assert_eq!(response, f[1], "response");
    let (mut ti, confirmation) = init.finish(&response).unwrap();
    assert_eq!(confirmation, f[2], "key confirmation");
    let mut tr = pending.confirm(&confirmation).unwrap();
    let to_responder = ti.send(b"ping").unwrap();
    assert_eq!(to_responder, f[3]);
    assert_eq!(tr.recv(&to_responder).unwrap(), b"ping");
    let to_initiator = tr.send(b"pong").unwrap();
    assert_eq!(to_initiator, f[4]);
    assert_eq!(ti.recv(&to_initiator).unwrap(), b"pong");
    assert_eq!(hex(&ti.handshake_hash()), RECORDED_HANDSHAKE_HASH);
    assert_eq!(tr.handshake_hash(), ti.handshake_hash());
}
