//! The handshakes on WebAssembly (wasm32-unknown-unknown) in a JavaScript host, with a clock the caller gives.
//!
//! Every key here is drawn from the OS random source (on wasm32-unknown-unknown: `crypto.getRandomValues`
//! through alice-crypto). The standard library has no clock on that target, so every channel and init here
//! reads a [`Clock`] the test supplies (a host would give `performance.now()` and `Date.now()`); a fake clock
//! makes the deadlines and the init labels follow the time the test sets, so they behave the same on every
//! target.
//!
//! - datagram mode: the two sides run the Noise IK handshake in one process and data packets round-trip
//!   both ways; an init from a clock that stepped back is refused
//! - stream mode: a real [`SecureChannel`] on one side (initiator, then responder) and the other side played
//!   with the crate's sans-IO Noise layer behind an in-memory stream (one thread cannot block on both ends of
//!   a blocking stream); the handshake completes and data round-trips both ways; a peer that trickles its
//!   bytes is cut at the deadline of the fake time
//!
//! - anonymous handshake: the sans-I/O state machines, with the responder suspended and resumed across two
//!   evictions; data both ways
//!
//! CI runs this file under Node with `wasm-bindgen-test-runner` and fails when fewer tests pass than it
//! has; on other targets the same tests run as ordinary tests.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test;

use alice_channel::datagram::{InitTimestamp, Initiator, Responder};
use alice_channel::noise::{HandshakeState, Keypair, Transport};
use alice_channel::{
    sign_handshake, ChannelError, Clock, Credential, PeerPolicy, ReadTimeout, SecureChannel,
    PROLOGUE,
};
use alice_identity::artifact::{ArtifactSignature, Revocation};
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey};

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_086_400;
const NOW: u64 = 1_800_000_100;

struct Party {
    master: KeyPair,
    did: Did,
    cred: Credential,
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    alice_crypto::random::fill(&mut seed).unwrap();
    seed
}

/// A device with fresh keys: the master and device signing keys from OS random seeds, the Noise static key
/// from `Keypair::generate`
fn party(name: &str) -> Party {
    let master = KeyPair::from_seed(random_seed());
    let device = KeyPair::from_seed(random_seed());
    let did = Did::parse(&format!("did:alice:{name}")).unwrap();
    let noise_static = Keypair::generate().unwrap();
    let cert = DeviceCert::issue(
        &master,
        &did,
        device.public().0,
        noise_static.public(),
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap();
    Party {
        master,
        did,
        cred: Credential::new(device, cert, noise_static).unwrap(),
    }
}

struct Policy {
    masters: BTreeMap<String, PublicKey>,
}

impl PeerPolicy for Policy {
    fn master_of(&self, subject: &Did) -> Option<PublicKey> {
        self.masters.get(&subject.to_string()).copied()
    }
    fn revocation(&self) -> Revocation<'_> {
        Revocation::NoListAvailable
    }
    fn now(&self) -> u64 {
        NOW
    }
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn fresh_keys_complete_a_handshake_and_messages_round_trip() {
    let (a, b) = (party("a"), party("b"));
    assert_ne!(
        a.cred.noise_static_public(),
        b.cred.noise_static_public(),
        "two generated static keys"
    );
    let policy = Policy {
        masters: [(&a, ()), (&b, ())]
            .iter()
            .map(|(p, ())| (p.did.to_string(), p.master.public()))
            .collect(),
    };
    let at = InitTimestamp::from_unix(NOW, 0);
    let (init, first) = Initiator::start_at(&a.cred, &policy, b.cred.cert(), at).unwrap();
    let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
    let (mut ca, confirm) = init.finish(pending.response(), &policy).unwrap();
    let (mut cb, payload) = pending.confirm(&confirm).channel().unwrap();
    assert_eq!(payload, None);
    assert_eq!(ca.handshake_hash(), cb.handshake_hash());
    assert_eq!(ca.peer_cert().subject(), b.cred.cert().subject());
    assert_eq!(cb.peer_cert().subject(), a.cred.cert().subject());

    let to_b = ca.seal(b"hello from a").unwrap();
    assert_eq!(
        cb.open(&to_b).unwrap().as_deref(),
        Some(&b"hello from a"[..])
    );
    let to_a = cb.seal(b"hello from b").unwrap();
    assert_eq!(
        ca.open(&to_a).unwrap().as_deref(),
        Some(&b"hello from b"[..])
    );
    assert!(cb.open(&to_b).is_err(), "a packet opens once");
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn two_handshakes_of_the_same_parties_give_different_keys() {
    // the ephemeral keys are drawn per handshake: the same two parties get a different transcript
    let (a, b) = (party("a"), party("b"));
    let policy = Policy {
        masters: [(&a, ()), (&b, ())]
            .iter()
            .map(|(p, ())| (p.did.to_string(), p.master.public()))
            .collect(),
    };
    let mut hashes = Vec::new();
    for secs in [NOW, NOW + 1] {
        let at = InitTimestamp::from_unix(secs, 0);
        let (init, first) = Initiator::start_at(&a.cred, &policy, b.cred.cert(), at).unwrap();
        let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
        let (ca, _) = init.finish(pending.response(), &policy).unwrap();
        hashes.push(ca.handshake_hash());
    }
    assert_ne!(hashes[0], hashes[1]);
}

/// A clock that reads the time the test sets: each monotonic reading returns the current time and then
/// moves it on by `step` (time passing between readings); the wall clock is fixed until set
struct FakeClock {
    mono: Cell<Duration>,
    step: Duration,
    wall: Cell<Duration>,
}

impl FakeClock {
    fn new(step: Duration) -> Self {
        Self {
            mono: Cell::new(Duration::ZERO),
            step,
            wall: Cell::new(Duration::from_secs(NOW)),
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        let t = self.mono.get();
        self.mono.set(t + self.step);
        t
    }
    fn system_now(&self) -> SystemTime {
        UNIX_EPOCH + self.wall.get()
    }
}

fn policy_of(parties: &[&Party]) -> Policy {
    Policy {
        masters: parties
            .iter()
            .map(|p| (p.did.to_string(), p.master.public()))
            .collect(),
    }
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn the_init_label_comes_from_the_clock_and_a_clock_that_steps_back_is_refused() {
    let (a, b) = (party("a"), party("b"));
    let policy = policy_of(&[&a, &b]);
    let clock = FakeClock::new(Duration::ZERO);
    clock.wall.set(Duration::new(NOW, 500));
    assert_eq!(
        InitTimestamp::from_clock(&clock),
        InitTimestamp::from_unix(NOW, 500)
    );
    let mut responder = Responder::new();
    let (_, first) = Initiator::start_with_clock(&a.cred, &policy, b.cred.cert(), &clock).unwrap();
    assert!(responder.respond(&b.cred, &policy, &first).is_ok());
    // the clock steps back: the next init is not later than the one accepted
    clock.wall.set(Duration::new(NOW - 1, 0));
    let (_, older) = Initiator::start_with_clock(&a.cred, &policy, b.cred.cert(), &clock).unwrap();
    assert!(matches!(
        responder.respond(&b.cred, &policy, &older),
        Err(ChannelError::StaleInit)
    ));
    // once it passes the last accepted time, it is accepted again
    clock.wall.set(Duration::new(NOW, 501));
    let (_, later) = Initiator::start_with_clock(&a.cred, &policy, b.cred.cert(), &clock).unwrap();
    assert!(responder.respond(&b.cred, &policy, &later).is_ok());
}

/// The side of a stream handshake the test plays with the sans-IO Noise layer
enum Peer {
    /// plays the responder: waits for the initiator's first message
    Responder {
        hs: Box<HandshakeState>,
        cred: Box<Credential>,
    },
    /// plays the initiator: its first message is already queued, waits for the response
    Initiator {
        hs: Box<HandshakeState>,
    },
    /// waits for the initiator's key confirmation
    AwaitConfirm(Transport),
    Open(Transport),
    Taken,
}

#[derive(Default)]
struct WireState {
    /// bytes the channel under test wrote, not yet read by the peer
    written: Vec<u8>,
    /// bytes for the channel under test to read
    incoming: VecDeque<u8>,
    /// at most this many bytes per read (a peer that trickles)
    per_read: usize,
    /// bytes the channel took from `incoming`
    taken: usize,
    timeout: Option<Duration>,
    /// the subject the peer saw in the channel's handshake signature
    saw: Option<String>,
    /// messages the peer opened after the handshake
    got: Vec<Vec<u8>>,
}

/// An in-memory stream to a peer played in the same thread: a read first lets the peer answer what the
/// channel wrote
#[derive(Clone)]
struct Wire {
    state: Rc<RefCell<WireState>>,
    peer: Rc<RefCell<Peer>>,
}

fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let n = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if buf.len() < 2 + n {
        return None;
    }
    let frame = buf[2..2 + n].to_vec();
    buf.drain(..2 + n);
    Some(frame)
}

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn subject_of(payload: &[u8]) -> String {
    ArtifactSignature::from_bytes(payload)
        .unwrap()
        .cert()
        .subject()
        .to_string()
}

impl Wire {
    fn new(peer: Peer, per_read: usize) -> Self {
        Self {
            state: Rc::new(RefCell::new(WireState {
                per_read,
                ..WireState::default()
            })),
            peer: Rc::new(RefCell::new(peer)),
        }
    }

    /// Let the peer answer every whole frame the channel has written
    fn pump(&self) {
        let mut st = self.state.borrow_mut();
        let mut peer = self.peer.borrow_mut();
        while let Some(f) = take_frame(&mut st.written) {
            *peer = match std::mem::replace(&mut *peer, Peer::Taken) {
                Peer::Responder { mut hs, cred } => {
                    let (payload, _) = hs.read_message_with_hash(&f).unwrap();
                    st.saw = Some(subject_of(&payload));
                    let reply = hs
                        .write_message_with(|h| sign_handshake(&cred, h).unwrap().to_bytes())
                        .unwrap();
                    st.incoming.extend(frame(&reply));
                    Peer::AwaitConfirm(hs.into_transport().unwrap())
                }
                Peer::Initiator { mut hs } => {
                    let (payload, _) = hs.read_message_with_hash(&f).unwrap();
                    st.saw = Some(subject_of(&payload));
                    let mut t = hs.into_transport().unwrap();
                    st.incoming.extend(frame(&t.send(&[]).unwrap()));
                    Peer::Open(t)
                }
                Peer::AwaitConfirm(mut t) => {
                    assert!(t.recv(&f).unwrap().is_empty(), "an empty key confirmation");
                    Peer::Open(t)
                }
                Peer::Open(mut t) => {
                    st.got.push(t.recv(&f).unwrap());
                    Peer::Open(t)
                }
                Peer::Taken => unreachable!(),
            };
        }
    }

    /// The peer sends one message on the transport keys
    fn peer_send(&self, payload: &[u8]) {
        let mut peer = self.peer.borrow_mut();
        let Peer::Open(t) = &mut *peer else {
            panic!("the handshake is not done")
        };
        let msg = t.send(payload).unwrap();
        self.state.borrow_mut().incoming.extend(frame(&msg));
    }
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.pump();
        let mut st = self.state.borrow_mut();
        if st.incoming.is_empty() {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let n = buf.len().min(st.per_read).min(st.incoming.len());
        for b in &mut buf[..n] {
            *b = st.incoming.pop_front().unwrap();
        }
        st.taken += n;
        Ok(n)
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.borrow_mut().written.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ReadTimeout for Wire {
    fn read_timeout(&self) -> std::io::Result<Option<Duration>> {
        Ok(self.state.borrow().timeout)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.state.borrow_mut().timeout = timeout;
        Ok(())
    }
}

const TIMEOUT: Duration = Duration::from_secs(10);

/// The responder side of `b`, played with the sans-IO layer (it takes `b`'s credential)
fn responder_peer(b: Party) -> (Peer, DeviceCert, PublicKey, Did) {
    let cert = b.cred.cert().clone();
    let hs = HandshakeState::responder(PROLOGUE, b.cred.noise_static().clone());
    let peer = Peer::Responder {
        hs: Box::new(hs),
        cred: Box::new(b.cred),
    };
    (peer, cert, b.master.public(), b.did)
}

fn policy_with(a: &Party, did: &Did, master: PublicKey) -> Policy {
    let mut policy = policy_of(&[a]);
    policy.masters.insert(did.to_string(), master);
    policy
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn a_stream_channel_connects_with_a_given_clock_and_messages_round_trip() {
    let a = party("a");
    let (peer, b_cert, b_master, b_did) = responder_peer(party("b"));
    let policy = policy_with(&a, &b_did, b_master);
    let wire = Wire::new(peer, usize::MAX);
    let clock = FakeClock::new(Duration::from_millis(1));
    let mut ch =
        SecureChannel::connect_with_clock(wire.clone(), &a.cred, &policy, &b_cert, TIMEOUT, &clock)
            .unwrap();
    assert_eq!(ch.peer_cert().subject(), b_cert.subject());
    assert_eq!(wire.state.borrow().saw, Some(a.did.to_string()));
    ch.send(b"from the channel").unwrap();
    wire.pump();
    assert_eq!(wire.state.borrow().got, vec![b"from the channel".to_vec()]);
    wire.peer_send(b"from the peer");
    assert_eq!(ch.recv_before(TIMEOUT).unwrap(), b"from the peer");
    wire.peer_send(b"again");
    assert_eq!(ch.recv().unwrap(), b"again");
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn a_stream_channel_accepts_with_a_given_clock_and_messages_round_trip() {
    let (a, b) = (party("a"), party("b"));
    let policy = policy_of(&[&a, &b]);
    let mut hs = HandshakeState::initiator(
        PROLOGUE,
        a.cred.noise_static().clone(),
        b.cred.noise_static_public(),
    );
    let first = hs
        .write_message_with(|h| sign_handshake(&a.cred, h).unwrap().to_bytes())
        .unwrap();
    let wire = Wire::new(Peer::Initiator { hs: Box::new(hs) }, usize::MAX);
    wire.state.borrow_mut().incoming.extend(frame(&first));
    let clock = FakeClock::new(Duration::from_millis(1));
    let mut ch =
        SecureChannel::accept_with_clock(wire.clone(), &b.cred, &policy, TIMEOUT, &clock).unwrap();
    assert_eq!(ch.peer_cert().subject(), a.cred.cert().subject());
    assert_eq!(wire.state.borrow().saw, Some(b.did.to_string()));
    wire.peer_send(b"from the peer");
    assert_eq!(ch.recv_before(TIMEOUT).unwrap(), b"from the peer");
    ch.send(b"from the channel").unwrap();
    wire.pump();
    assert_eq!(wire.state.borrow().got, vec![b"from the channel".to_vec()]);
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn a_peer_that_trickles_is_cut_at_the_deadline_of_the_clock() {
    // the deadline is 10 s and each clock reading is 3 s later: the end is set at 0 s, bytes are read at
    // 3, 6 and 9 s (the frame's 2-byte length, then 1 byte of its body), and at 12 s nothing is left
    let a = party("a");
    let (peer, b_cert, b_master, b_did) = responder_peer(party("b"));
    let policy = policy_with(&a, &b_did, b_master);
    let wire = Wire::new(peer, 1);
    let clock = FakeClock::new(Duration::from_secs(3));
    let got =
        SecureChannel::connect_with_clock(wire.clone(), &a.cred, &policy, &b_cert, TIMEOUT, &clock);
    assert!(matches!(got, Err(ChannelError::Timeout)));
    assert_eq!(wire.state.borrow().taken, 3);
    // the stream's own read timeout is set back
    assert_eq!(wire.state.borrow().timeout, None);
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn recv_before_follows_the_clock_and_a_cut_message_poisons_the_channel() {
    let a = party("a");
    let (peer, b_cert, b_master, b_did) = responder_peer(party("b"));
    let policy = policy_with(&a, &b_did, b_master);
    let wire = Wire::new(peer, usize::MAX);
    let clock = FakeClock::new(Duration::from_secs(3));
    let mut ch =
        SecureChannel::connect_with_clock(wire.clone(), &a.cred, &policy, &b_cert, TIMEOUT, &clock)
            .unwrap();
    // nothing came: a timeout that leaves the channel usable
    assert!(matches!(
        ch.recv_before(TIMEOUT),
        Err(ChannelError::Timeout)
    ));
    ch.send(b"still usable").unwrap();
    // a message that trickles in past the deadline: cut after 3 bytes, and the channel is poisoned
    wire.peer_send(b"a message longer than three bytes");
    wire.state.borrow_mut().per_read = 1;
    let before = wire.state.borrow().taken;
    assert!(matches!(
        ch.recv_before(TIMEOUT),
        Err(ChannelError::Timeout)
    ));
    assert_eq!(wire.state.borrow().taken - before, 3);
    assert!(matches!(ch.send(b"x"), Err(ChannelError::Poisoned)));
}

/// The anonymous handshake through the sans-I/O state machines, with the responder evicted twice: once while
/// it waits for the key confirmation, once after it has replied to a message. Only the suspended bytes and the
/// floor cross each eviction (as a host that handles each message in a separate callback keeps them)
#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn an_anonymous_handshake_survives_evictions_of_the_responder() {
    use alice_channel::noise::{SuspendKey, SuspendedTransport};
    use alice_channel::{AwaitConfirmation, Initiate, Respond};

    let host_key = || SuspendKey::from_bytes(random_seed());
    let host_key = host_key();
    let responder_static = Keypair::generate().unwrap();
    let (init, first) = Initiate::start(responder_static.public()).unwrap();
    assert_eq!(first.len(), 48);

    // callback 1: the first message comes, the response leaves, the state is suspended
    let (pending, response) = Respond::new(responder_static).respond(&first).unwrap();
    // the host stores the channel id beside every copy of this channel
    let channel = pending.channel_id();
    let mut stored = pending.suspend(&host_key).unwrap().as_bytes().to_vec();
    let mut floor = 0;

    let (mut client, confirmation) = init.finish(&response).unwrap();
    assert_eq!(confirmation.len(), 16);

    // callback 2: the key confirmation, then the first request
    let copy = SuspendedTransport::from_bytes(&stored).unwrap();
    let resumed = AwaitConfirmation::resume(&copy, &host_key, floor, channel).unwrap();
    floor = resumed.next_floor();
    let server = resumed.floor_persisted().confirm(&confirmation).unwrap();
    assert_eq!(server.handshake_hash(), client.handshake_hash());
    assert_eq!(server.channel_id(), channel);
    stored = server.suspend(&host_key).unwrap().as_bytes().to_vec();

    // callbacks 3..: one request and one reply each, with an eviction between
    for round in 0..3u8 {
        let request = client.send(&[round; 8]).unwrap();
        let copy = SuspendedTransport::from_bytes(&stored).unwrap();
        let resumed =
            alice_channel::noise::Transport::resume(&copy, &host_key, floor, channel).unwrap();
        floor = resumed.next_floor();
        let mut server = resumed.floor_persisted();
        assert_eq!(server.recv(&request).unwrap(), [round; 8]);
        let reply = server.send(&[round ^ 0xff; 5]).unwrap();
        stored = server.suspend(&host_key).unwrap().as_bytes().to_vec();
        assert_eq!(client.recv(&reply).unwrap(), [round ^ 0xff; 5]);
        // the copy before this callback is refused now
        assert!(alice_channel::noise::Transport::resume(&copy, &host_key, floor, channel).is_err());
    }
    assert_eq!(floor, 4);
}
