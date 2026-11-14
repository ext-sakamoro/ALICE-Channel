//! The sans-I/O anonymous handshake ([`Initiate`], [`Respond`], [`AwaitConfirmation`]) against the run
//! recorded from the blocking channel before it was rebuilt on them (`tests/data/anonymous_recorded.txt`,
//! the same file `src/anonymous/vectors.rs` holds the stream channel to): with the recorded keys, every
//! message, both data messages and the handshake hash come out byte for byte.
//!
//! The constructors with a fixed ephemeral key exist only with the feature `test-vectors`, so this file is
//! empty without it; CI runs it with the feature through `scripts/run_tests.sh`, which fails when it ran
//! fewer tests than named (0 included).
//!
//! [`AwaitConfirmation`]: alice_channel::AwaitConfirmation
#![cfg(feature = "test-vectors")]

use alice_channel::noise::nk::NkHandshakeState;
use alice_channel::noise::Keypair;
use alice_channel::{Initiate, Respond, ANONYMOUS_PROLOGUE};

const RECORDED: &str = include_str!("data/anonymous_recorded.txt");
const RESPONDER_STATIC: [u8; 32] = [0x07; 32];
const INITIATOR_EPHEMERAL: [u8; 32] = [0x11; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x22; 32];

fn recorded(field: &str) -> Vec<u8> {
    let hex = RECORDED
        .lines()
        .find_map(|l| l.strip_prefix(field)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no {field} line"));
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// The frames of the recorded transcript (a big-endian u16 length, then that many bytes)
fn frames() -> Vec<Vec<u8>> {
    let all = recorded("transcript");
    let mut t = &all[..];
    let mut out = Vec::new();
    while t.len() >= 2 {
        let n = usize::from(u16::from_be_bytes([t[0], t[1]]));
        out.push(t[2..2 + n].to_vec());
        t = &t[2 + n..];
    }
    assert!(t.is_empty());
    out
}

#[test]
fn the_recording_is_the_documented_run() {
    // an oracle outside the state machines: the first frame and the hash come from the NK layer (pinned by
    // the public NK test vector) with the recorded keys
    let f = frames();
    assert_eq!(
        f.iter().map(Vec::len).collect::<Vec<_>>(),
        [48, 48, 16, 20, 20]
    );
    let mut hs = NkHandshakeState::initiator_with_ephemeral(
        ANONYMOUS_PROLOGUE,
        Keypair::from_secret(RESPONDER_STATIC).public(),
        Keypair::from_secret(INITIATOR_EPHEMERAL),
    );
    assert_eq!(hs.write_message(&[]).unwrap(), f[0]);
    assert!(hs.read_message(&f[1]).unwrap().is_empty());
    assert_eq!(hs.handshake_hash().to_vec(), recorded("hash"));
}

#[test]
fn the_state_machines_write_the_recorded_bytes() {
    let f = frames();
    let rs = Keypair::from_secret(RESPONDER_STATIC).public();
    let (init, first) =
        Initiate::start_with_ephemeral(rs, Keypair::from_secret(INITIATOR_EPHEMERAL)).unwrap();
    assert_eq!(first, f[0], "first message");
    let resp = Respond::with_ephemeral(
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
    assert_eq!(ti.handshake_hash().to_vec(), recorded("hash"));
    assert_eq!(tr.handshake_hash(), ti.handshake_hash());
}
