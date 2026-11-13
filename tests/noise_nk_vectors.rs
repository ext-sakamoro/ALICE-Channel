//! Oracle for the NK pattern: the public test vector for `Noise_NK_25519_ChaChaPoly_SHA256` from the cacophony
//! suite (as shipped with the `snow` crate 0.9.6, `tests/vectors/cacophony.txt`), extracted unchanged into
//! `tests/data/`. Every handshake and transport message, and the final handshake hash, must come out byte for
//! byte; none of the expected bytes comes from the code under test.

use alice_channel::noise::nk::{NkHandshakeState, PROTOCOL_NAME};
use alice_channel::noise::{Keypair, NoiseError};

const VECTOR: &str = include_str!("data/noise_nk_25519_chachapoly_sha256.json");
/// SHA-256 of the extracted vector file (the one `Noise_NK_25519_ChaChaPoly_SHA256` entry of the suite,
/// re-serialised with sorted keys)
const VECTOR_SHA256: &str = "2358fda3b703d9212b087ddb09a64ee277ebe4ddc16d69db39a355ff064860e2";

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

fn parties(v: &serde_json::Value) -> (NkHandshakeState, NkHandshakeState) {
    let init = NkHandshakeState::initiator_with_ephemeral(
        &hex(field(v, "init_prologue")),
        arr32(field(v, "init_remote_static")),
        Keypair::from_secret(arr32(field(v, "init_ephemeral"))),
    );
    let resp = NkHandshakeState::responder_with_ephemeral(
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
    assert_eq!(field(&v, "protocol_name").as_bytes(), PROTOCOL_NAME);
    assert_eq!(v["messages"].as_array().unwrap().len(), 6);
    // the vector names no initiator static key: NK has none
    assert!(v.get("init_static").is_none());
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
    // NK: <- s (known), -> e es, <- e ee
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

    let mut ti = init.into_transport().unwrap();
    let mut tr = resp.into_transport().unwrap();
    let mut checked = 0;
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
        checked += 1;
    }
    assert_eq!(checked, 4);
}

#[test]
fn the_first_message_is_an_ephemeral_key_and_an_encrypted_payload_only() {
    // -> e, es: 32 bytes of e, then the payload under the es key (payload + 16-byte tag), no static key
    let v = vector();
    let m0 = &v["messages"][0];
    let payload = hex(field(m0, "payload"));
    let (mut init, _) = parties(&v);
    let out = init.write_message(&payload).unwrap();
    assert_eq!(out.len(), 32 + payload.len() + 16);
}

#[test]
fn a_first_message_for_another_static_key_does_not_open() {
    let v = vector();
    let wrong = Keypair::from_secret([0x33; 32]).public();
    let mut init = NkHandshakeState::initiator_with_ephemeral(
        &hex(field(&v, "init_prologue")),
        wrong,
        Keypair::from_secret(arr32(field(&v, "init_ephemeral"))),
    );
    let (_, mut resp) = parties(&v);
    let m0 = init.write_message(b"").unwrap();
    assert_eq!(resp.read_message(&m0), Err(NoiseError::Decrypt));
    assert_eq!(resp.write_message(b""), Err(NoiseError::OutOfTurn));
}

#[test]
fn a_changed_handshake_message_is_refused() {
    let v = vector();
    let (mut init, _) = parties(&v);
    let m0 = init.write_message(b"x").unwrap();
    for i in [0, 31, 32, m0.len() - 1] {
        let (_, mut r) = parties(&v);
        let mut x = m0.clone();
        x[i] ^= 1;
        assert_eq!(r.read_message(&x), Err(NoiseError::Decrypt), "byte {i}");
    }
}

#[test]
fn a_different_prologue_breaks_the_handshake() {
    let v = vector();
    let mut init = NkHandshakeState::initiator_with_ephemeral(
        b"another prologue",
        arr32(field(&v, "init_remote_static")),
        Keypair::from_secret(arr32(field(&v, "init_ephemeral"))),
    );
    let (_, mut resp) = parties(&v);
    let m0 = init.write_message(b"").unwrap();
    assert_eq!(resp.read_message(&m0), Err(NoiseError::Decrypt));
}

#[test]
fn messages_out_of_turn_truncated_and_early_transport_are_refused() {
    let v = vector();
    let (mut init, mut resp) = parties(&v);
    assert_eq!(resp.write_message(b""), Err(NoiseError::OutOfTurn));
    assert_eq!(init.read_message(&[0; 48]), Err(NoiseError::OutOfTurn));
    assert_eq!(resp.read_message(&[0; 47]), Err(NoiseError::Truncated));
    assert!(matches!(
        init.into_transport(),
        Err(NoiseError::NotFinished)
    ));
}

#[test]
fn an_all_zero_ephemeral_dh_is_refused() {
    // a small-order initiator ephemeral key makes es all zero: refused, not mixed in
    let v = vector();
    let (_, mut resp) = parties(&v);
    let mut m0 = vec![0u8; 32];
    m0.extend_from_slice(&[0u8; 16]);
    assert_eq!(resp.read_message(&m0), Err(NoiseError::WeakKey));
}
