//! Oracle for the hidden responder: a connection that does not open the first message for the responder's
//! static key, or opens it as a device the responder does not accept, reads nothing back. The responder's
//! static key and certificate never travel to such a peer; only an initiator the responder accepts gets the
//! second message. The scanner here speaks the Noise layer directly, so what it reads is what is on the wire.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use alice_channel::noise::{HandshakeState, Keypair};
use alice_channel::{sign_handshake, Credential, PeerPolicy, SecureChannel, PROLOGUE};
use alice_identity::artifact::Revocation;
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
    noise: Keypair,
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
        [seed; 16],
    )
    .unwrap();
    Party {
        master,
        did,
        cred: Credential::new(device, cert, noise.clone()).unwrap(),
        noise,
    }
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

fn knowing(ps: &[&Party]) -> Policy {
    Policy(
        ps.iter()
            .map(|p| (p.did.to_string(), p.master.public()))
            .collect(),
    )
}

fn write_frame(s: &mut TcpStream, b: &[u8]) {
    s.write_all(&u16::try_from(b.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(b).unwrap();
}

/// Accept one connection as `responder` (knowing `knows`), send `first` from a raw peer, and return what
/// the raw peer reads until the responder hangs up, with whether the responder opened a channel
fn probe(responder: Party, knows: &[&Party], first: Vec<u8>) -> (Vec<u8>, bool) {
    let policy = knowing(knows);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        SecureChannel::accept_with_timeout(s, &responder.cred, &policy, Duration::from_millis(300))
            .is_ok()
    });
    let mut raw = TcpStream::connect(addr).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write_frame(&mut raw, &first);
    let mut got = Vec::new();
    // the responder hangs up: read until the end of the stream (a reset also ends what it sent)
    let mut buf = [0u8; 4096];
    loop {
        match raw.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
        }
    }
    (got, server.join().unwrap())
}

/// The first message an initiator with `cred` and static `s` writes for the responder static `rs`
fn first_message(cred: &Credential, s: &Keypair, rs: [u8; 32]) -> Vec<u8> {
    let mut hs = HandshakeState::initiator(PROLOGUE, s.clone(), rs);
    hs.write_message_with(|h| sign_handshake(cred, h).unwrap().to_bytes())
        .unwrap()
}

#[test]
fn a_bare_ephemeral_key_reads_nothing_back() {
    // the first message of a handshake that starts with only an ephemeral key (as XX does)
    let bob = party(2, "bob");
    let alice = party(1, "alice");
    let (got, opened) = probe(bob, &[&alice], vec![0x42; 32]);
    assert!(got.is_empty(), "the scanner read {} bytes", got.len());
    assert!(!opened);
}

#[test]
fn a_first_message_for_another_static_key_reads_nothing_back() {
    // a device the responder knows, which does not hold the responder's static key
    let bob = party(2, "bob");
    let alice = party(1, "alice");
    let wrong = Keypair::from_secret([0x77; 32]).public();
    let first = first_message(&alice.cred, &alice.noise, wrong);
    let (got, opened) = probe(bob, &[&alice], first);
    assert!(got.is_empty(), "the scanner read {} bytes", got.len());
    assert!(!opened);
}

#[test]
fn a_device_the_responder_does_not_accept_reads_nothing_back_even_with_the_static_key() {
    // the scanner holds the responder's certificate (so its static key) but is not known to the responder
    let bob = party(2, "bob");
    let alice = party(1, "alice");
    let mallory = party(9, "mallory");
    let rs = *bob.cred.cert().noise_static();
    let first = first_message(&mallory.cred, &mallory.noise, rs);
    let (got, opened) = probe(bob, &[&alice], first);
    assert!(got.is_empty(), "the scanner read {} bytes", got.len());
    assert!(!opened);
}

#[test]
fn an_accepted_initiator_gets_the_second_message_and_nothing_names_the_responder_in_clear() {
    // the reference the refusals above are measured against: the same raw first message from a device the
    // responder accepts is answered with exactly one frame (e + the encrypted payload), and neither the
    // responder's static key nor its certificate's subject appears in clear
    let bob = party(2, "bob");
    let alice = party(1, "alice");
    let rs = *bob.cred.cert().noise_static();
    let subject = bob.did.to_string();
    let static_pub = bob.noise.public();
    let first = first_message(&alice.cred, &alice.noise, rs);
    let (got, opened) = probe(bob, &[&alice], first);
    assert!(
        got.len() > 2,
        "the accepted initiator read {} bytes",
        got.len()
    );
    let len = usize::from(u16::from_be_bytes([got[0], got[1]]));
    assert_eq!(got.len(), 2 + len, "exactly one frame");
    assert!(!got.windows(32).any(|w| w == static_pub));
    assert!(!got.windows(subject.len()).any(|w| w == subject.as_bytes()));
    // the raw peer sends no key confirmation, so the responder opens no channel
    assert!(!opened);
}
