//! Recorded-bit goldens of what the channel computes from fixed keys (ALICE-Law G4, the pins of
//! `CHANNEL_SEMANTICS_ID`, G6).
//!
//! Each scenario runs the channel with fixed static and ephemeral keys and records the SHA-256 of every byte it
//! produced. The digests are recorded from the current build: the Noise vector of `tests/noise_vectors.rs` is
//! the independent oracle of the handshake itself, and these goldens pin the rest of what the crate puts on the
//! wire (the transport after the handshake, the datagram sealing). Every CI leg (debug and release, x86_64 and
//! aarch64) must reproduce them bit for bit.

use alice_channel::noise::{HandshakeState, Keypair};
use alice_crypto::sha256;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The SHA-256 of `bytes` when it is not `expected`
fn golden_mismatch(bytes: &[u8], expected: &str) -> Option<String> {
    let got = hex(&sha256::digest(bytes));
    (got != expected).then_some(got)
}

/// A scenario that produced nothing compared nothing
fn produced(name: &str, bytes: &[u8]) {
    assert!(!bytes.is_empty(), "{name}: the scenario produced no bytes");
}

fn assert_golden(name: &str, bytes: &[u8], expected: &str) {
    produced(name, bytes);
    if let Some(got) = golden_mismatch(bytes, expected) {
        panic!("{name} golden moved: {got}, recorded {expected}");
    }
}

#[test]
fn checker_rejects_a_wrong_digest() {
    let recorded = hex(&sha256::digest(b"recorded bits"));
    assert_eq!(golden_mismatch(b"recorded bits", &recorded), None);
    assert!(golden_mismatch(b"moved bits", &recorded).is_some());
}

#[test]
#[should_panic(expected = "produced no bytes")]
fn checker_rejects_a_scenario_that_produced_nothing() {
    produced("empty", b"");
}

const PROLOGUE: &[u8] = b"alice-channel/semantics-golden";

fn key(fill: u8) -> Keypair {
    Keypair::from_secret([fill; 32])
}

/// A handshake of fixed keys; every handshake message is appended to `out`
fn handshake(out: &mut Vec<u8>) -> (HandshakeState, HandshakeState) {
    let responder_static = key(2);
    let mut init = HandshakeState::initiator_with_ephemeral(
        PROLOGUE,
        key(1),
        responder_static.public(),
        key(3),
    );
    let mut resp = HandshakeState::responder_with_ephemeral(PROLOGUE, responder_static, key(4));
    let m1 = init.write_message(b"hello from the initiator").unwrap();
    assert_eq!(resp.read_message(&m1).unwrap(), b"hello from the initiator");
    let m2 = resp.write_message(b"hello from the responder").unwrap();
    assert_eq!(init.read_message(&m2).unwrap(), b"hello from the responder");
    out.extend_from_slice(&m1);
    out.extend_from_slice(&m2);
    (init, resp)
}

/// The Noise IK handshake of fixed keys, then three transport messages each way
#[test]
fn the_handshake_and_transport_are_the_recorded_bits() {
    let mut out = Vec::new();
    let (init, resp) = handshake(&mut out);
    let mut a = init.into_transport().unwrap();
    let mut b = resp.into_transport().unwrap();
    for i in 0..3u8 {
        let to_b = a.send(&[i; 40]).unwrap();
        assert_eq!(b.recv(&to_b).unwrap(), vec![i; 40]);
        let to_a = b.send(&[0x80 | i; 17]).unwrap();
        assert_eq!(a.recv(&to_a).unwrap(), vec![0x80 | i; 17]);
        out.extend_from_slice(&to_b);
        out.extend_from_slice(&to_a);
    }
    assert_golden(
        "handshake and transport",
        &out,
        "79a6d33e6779591e9e232e40be4686eae8401aeee27a2a654a77e28d9b4f7e77",
    );
}

/// The datagram mode after the same handshake: five datagrams sealed with an associated-data label, each its
/// counter and ciphertext
#[test]
fn datagrams_are_the_recorded_bits() {
    let mut out = Vec::new();
    let (init, resp) = handshake(&mut out);
    let mut a = init.into_transport().unwrap().into_datagram();
    let b = resp.into_transport().unwrap().into_datagram();
    for i in 0..5u8 {
        let (counter, sealed) = a.seal(b"golden", &[i; 25]).unwrap();
        assert_eq!(b.open(counter, b"golden", &sealed).unwrap(), vec![i; 25]);
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&sealed);
    }
    assert_golden(
        "datagram transport",
        &out,
        "d6945135bfbe87700b6d99f8da9006398dfa28cd3635c248ad99bf815040f9ff",
    );
}
