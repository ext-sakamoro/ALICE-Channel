//! Oracle for the Noise layer: the public test vector for `Noise_IK_25519_ChaChaPoly_SHA256` from the
//! cacophony suite (as shipped with the `snow` crate), extracted unchanged into `tests/data/`. Every handshake
//! and transport message, and the final handshake hash, must come out byte for byte; none of the expected
//! bytes comes from the code under test.

use alice_channel::noise::{HandshakeState, Keypair, NoiseError};

const VECTOR: &str = include_str!("data/noise_ik_25519_chachapoly_sha256.json");
/// SHA-256 of the extracted vector file (it holds the one `Noise_IK_25519_ChaChaPoly_SHA256` entry of the
/// suite, re-serialised with sorted keys)
const VECTOR_SHA256: &str = "87da594f2f49bae27efea92bf63cce0874e10984069b1d586f2b7395454d08c5";

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn field<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("field {k}"))
}

fn vector() -> serde_json::Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn resp_static(v: &serde_json::Value) -> Keypair {
    Keypair::from_secret(arr32(field(v, "resp_static")))
}

fn initiator(v: &serde_json::Value, prologue: &[u8], rs: [u8; 32]) -> HandshakeState {
    HandshakeState::initiator_with_ephemeral(
        prologue,
        Keypair::from_secret(arr32(field(v, "init_static"))),
        rs,
        Keypair::from_secret(arr32(field(v, "init_ephemeral"))),
    )
}

fn parties(v: &serde_json::Value) -> (HandshakeState, HandshakeState) {
    let init = initiator(
        v,
        &hex(field(v, "init_prologue")),
        arr32(field(v, "init_remote_static")),
    );
    let resp = HandshakeState::responder_with_ephemeral(
        &hex(field(v, "resp_prologue")),
        resp_static(v),
        Keypair::from_secret(arr32(field(v, "resp_ephemeral"))),
    );
    (init, resp)
}

#[test]
fn the_vector_file_is_the_extracted_one() {
    use alice_crypto::sha256::digest;
    let got: String = digest(VECTOR.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(got, VECTOR_SHA256);
    let v = vector();
    assert_eq!(
        field(&v, "protocol_name"),
        "Noise_IK_25519_ChaChaPoly_SHA256"
    );
    assert_eq!(v["messages"].as_array().unwrap().len(), 6);
    // the pre-message: the initiator holds the responder's static key before it writes
    assert_eq!(
        arr32(field(&v, "init_remote_static")),
        resp_static(&v).public()
    );
}

#[test]
fn the_handshake_and_transport_messages_match_the_vector() {
    let v = vector();
    let msgs = v["messages"].as_array().unwrap();
    let (mut init, mut resp) = parties(&v);

    // IK: <- s (known), -> e es s ss, <- e ee se
    for (i, m) in msgs.iter().take(2).enumerate() {
        let payload = hex(field(m, "payload"));
        let want = hex(field(m, "ciphertext"));
        let (sender, receiver) = if i == 0 {
            (&mut init, &mut resp)
        } else {
            (&mut resp, &mut init)
        };
        assert_eq!(sender.write_message(&payload).unwrap(), want, "message {i}");
        assert_eq!(
            receiver.read_message(&want).unwrap(),
            payload,
            "message {i}"
        );
    }
    assert!(init.is_finished() && resp.is_finished());
    let hh = arr32(field(&v, "handshake_hash"));
    assert_eq!(init.handshake_hash(), hh);
    assert_eq!(resp.handshake_hash(), hh);
    assert_eq!(init.remote_static(), Some(resp_static(&v).public()));
    assert_eq!(
        resp.remote_static(),
        Some(Keypair::from_secret(arr32(field(&v, "init_static"))).public())
    );

    let mut ti = init.into_transport().unwrap();
    let mut tr = resp.into_transport().unwrap();
    for (i, m) in msgs.iter().enumerate().skip(2) {
        let payload = hex(field(m, "payload"));
        let want = hex(field(m, "ciphertext"));
        if i % 2 == 0 {
            assert_eq!(ti.send(&payload).unwrap(), want, "message {i}");
            assert_eq!(tr.recv(&want).unwrap(), payload, "message {i}");
        } else {
            assert_eq!(tr.send(&payload).unwrap(), want, "message {i}");
            assert_eq!(ti.recv(&want).unwrap(), payload, "message {i}");
        }
    }
}

#[test]
fn a_first_message_for_another_static_key_does_not_open() {
    // an initiator holding the wrong responder key: the responder learns nothing from message 0 (its
    // static key and payload do not decrypt) and writes nothing
    let v = vector();
    let wrong = Keypair::from_secret([0x33; 32]).public();
    let mut init = initiator(&v, &hex(field(&v, "init_prologue")), wrong);
    let (_, mut resp) = parties(&v);
    let m0 = init.write_message(b"").unwrap();
    assert_eq!(resp.read_message(&m0), Err(NoiseError::Decrypt));
    assert_eq!(resp.remote_static(), None);
    assert_eq!(resp.write_message(b""), Err(NoiseError::OutOfTurn));
}

#[test]
fn a_changed_handshake_message_is_refused() {
    let v = vector();
    let msgs = v["messages"].as_array().unwrap();
    let (mut init, mut resp) = parties(&v);
    let m0 = init
        .write_message(&hex(field(&msgs[0], "payload")))
        .unwrap();
    for i in [0, 40, m0.len() - 1] {
        let (_, mut r) = parties(&v);
        let mut x = m0.clone();
        x[i] ^= 1;
        assert_eq!(r.read_message(&x), Err(NoiseError::Decrypt), "byte {i}");
    }
    resp.read_message(&m0).unwrap();
    let mut m1 = resp
        .write_message(&hex(field(&msgs[1], "payload")))
        .unwrap();
    let last = m1.len() - 1;
    m1[last] ^= 1;
    assert_eq!(init.read_message(&m1), Err(NoiseError::Decrypt));
}

#[test]
fn a_different_prologue_breaks_the_handshake() {
    let v = vector();
    let msgs = v["messages"].as_array().unwrap();
    let mut init = initiator(
        &v,
        b"another prologue",
        arr32(field(&v, "init_remote_static")),
    );
    let (_, mut resp) = parties(&v);
    let m0 = init
        .write_message(&hex(field(&msgs[0], "payload")))
        .unwrap();
    // message 0 already carries encrypted parts: the mismatch shows there
    assert_eq!(resp.read_message(&m0), Err(NoiseError::Decrypt));
}

#[test]
fn messages_out_of_turn_and_early_transport_are_refused() {
    let v = vector();
    let (mut init, mut resp) = parties(&v);
    assert_eq!(resp.write_message(b""), Err(NoiseError::OutOfTurn));
    assert_eq!(init.read_message(&[0; 48]), Err(NoiseError::OutOfTurn));
    assert!(matches!(
        init.into_transport(),
        Err(NoiseError::NotFinished)
    ));
    let _ = &mut resp;
}

#[test]
fn a_truncated_message_is_refused() {
    // message 0 = e (32) + encrypted s (32 + 16) + encrypted payload (at least a 16-byte tag)
    let v = vector();
    let (mut init, mut resp) = parties(&v);
    let m0 = init.write_message(b"").unwrap();
    assert_eq!(m0.len(), 32 + 48 + 16);
    for n in [0, 31, 32 + 47, 32 + 48 + 15] {
        let (_, mut r) = parties(&v);
        assert_eq!(r.read_message(&m0[..n]), Err(NoiseError::Truncated), "{n}");
    }
    resp.read_message(&m0).unwrap();
    // message 1 = e (32) + encrypted payload (at least a 16-byte tag)
    let m1 = resp.write_message(b"").unwrap();
    assert_eq!(m1.len(), 32 + 16);
    assert_eq!(
        init.read_message(&m1[..32 + 15]),
        Err(NoiseError::Truncated)
    );
}

fn finished_pair() -> (HandshakeState, HandshakeState) {
    let v = vector();
    let (mut init, mut resp) = parties(&v);
    let m0 = init.write_message(b"").unwrap();
    resp.read_message(&m0).unwrap();
    let m1 = resp.write_message(b"").unwrap();
    init.read_message(&m1).unwrap();
    (init, resp)
}

#[test]
fn a_transport_message_replayed_or_reordered_is_refused() {
    let (init, resp) = finished_pair();
    let mut ti = init.into_transport().unwrap();
    let mut tr = resp.into_transport().unwrap();
    let a = ti.send(b"first").unwrap();
    let b = ti.send(b"second").unwrap();
    // the nonce is a counter: the second message does not open as the first, and a replay fails
    assert_eq!(tr.recv(&b), Err(NoiseError::Decrypt));
    assert_eq!(tr.recv(&a).unwrap(), b"first");
    assert_eq!(tr.recv(&a), Err(NoiseError::Decrypt));
}

#[test]
fn a_small_order_public_key_is_refused() {
    // an all-zero ephemeral public key gives an all-zero shared secret: the responder's first
    // Diffie-Hellman (es, while reading message 0) refuses it
    let v = vector();
    let (_, mut resp) = parties(&v);
    assert_eq!(
        resp.read_message(&[0u8; 32 + 48 + 16]),
        Err(NoiseError::WeakKey)
    );
    // and an initiator given an all-zero responder key refuses to write
    let mut init = initiator(&v, b"", [0; 32]);
    assert_eq!(init.write_message(b""), Err(NoiseError::WeakKey));
}

#[test]
fn a_finished_handshake_reads_and_writes_nothing_more() {
    let (mut init, mut resp) = finished_pair();
    assert!(init.is_finished() && resp.is_finished());
    let extra = vec![0u8; 96];
    assert_eq!(init.read_message(&extra), Err(NoiseError::OutOfTurn));
    assert_eq!(resp.read_message(&extra), Err(NoiseError::OutOfTurn));
    assert_eq!(init.write_message(b""), Err(NoiseError::OutOfTurn));
    assert_eq!(resp.write_message(b""), Err(NoiseError::OutOfTurn));
}

#[test]
fn a_transport_message_over_the_noise_limit_is_refused_by_the_noise_layer() {
    use alice_channel::noise::MAX_MESSAGE;
    let (init, resp) = finished_pair();
    let mut ti = init.into_transport().unwrap();
    let mut tr = resp.into_transport().unwrap();
    // payload + 16-byte tag must fit in one Noise message
    assert_eq!(
        ti.send(&vec![0u8; MAX_MESSAGE - 15]),
        Err(NoiseError::TooLong)
    );
    let largest = ti.send(&vec![7u8; MAX_MESSAGE - 16]).unwrap();
    assert_eq!(largest.len(), MAX_MESSAGE);
    assert_eq!(tr.recv(&largest).unwrap(), vec![7u8; MAX_MESSAGE - 16]);
    assert_eq!(
        tr.recv(&vec![0u8; MAX_MESSAGE + 1]),
        Err(NoiseError::TooLong)
    );
}

#[test]
fn split_transport_halves_keep_the_nonces_and_limits_of_the_whole() {
    use alice_channel::noise::MAX_MESSAGE;
    let (init, resp) = finished_pair();
    let mut whole_i = init.into_transport().unwrap();
    let (mut tx_r, mut rx_r) = resp.into_transport().unwrap().split();
    assert_eq!(tx_r.handshake_hash(), whole_i.handshake_hash());
    assert_eq!(rx_r.handshake_hash(), whole_i.handshake_hash());
    // the split halves interoperate with an unsplit peer in both directions, in order
    for i in 0..3u8 {
        let m = whole_i.send(&[i; 10]).unwrap();
        assert_eq!(rx_r.recv(&m).unwrap(), vec![i; 10]);
        let back = tx_r.send(&[i; 5]).unwrap();
        assert_eq!(whole_i.recv(&back).unwrap(), vec![i; 5]);
    }
    // a replayed message is refused by the receiving half
    let m = whole_i.send(b"once").unwrap();
    assert_eq!(rx_r.recv(&m).unwrap(), b"once");
    assert!(matches!(rx_r.recv(&m), Err(NoiseError::Decrypt)));
    // the Noise length limits hold on each half
    assert!(matches!(
        tx_r.send(&vec![0u8; MAX_MESSAGE - 15]),
        Err(NoiseError::TooLong)
    ));
    assert!(tx_r.send(&vec![0u8; MAX_MESSAGE - 16]).is_ok());
    assert!(matches!(
        rx_r.recv(&vec![0u8; MAX_MESSAGE + 1]),
        Err(NoiseError::TooLong)
    ));
}
