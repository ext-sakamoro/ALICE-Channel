//! Oracle for suspending and resuming a transport ([`Transport::suspend`], [`Transport::resume`]), for a host
//! that may be evicted and restarted between two messages.
//!
//! The nonce rule is the core: a resumed transport continues from the nonces it was suspended at (the peer
//! opens every message in order, and equal plaintexts never give equal ciphertexts), a copy older than the
//! host's floor is refused, and a stale copy used in breach of the rule is caught by the peer. The layout is
//! checked from outside: the test opens a real copy with the documented key derivation and reads the nonce
//! counters and the handshake hash out of it, and seals copies of its own to reach the checks that need a
//! valid tag (a wrong-length key field, an unknown phase, the last epoch). Every cut length, every bit flip,
//! a changed version and trailing bytes are refused with a typed error.

use alice_channel::noise::suspend::{SUSPENDED_LEN, SUSPENDED_VERSION, SUSPEND_KEY_LABEL};
use alice_channel::noise::{
    Keypair, NoiseError, ResumeError, SuspendKey, SuspendedTransport, Transport,
};
use alice_channel::{AwaitConfirmation, Initiate, Respond};
use alice_crypto::chacha20poly1305_ietf as aead;
use alice_crypto::sha256;

const HOST_KEY: [u8; 32] = [0x5a; 32];

fn host_key() -> SuspendKey {
    SuspendKey::from_bytes(HOST_KEY)
}

fn handshake() -> (Transport, Transport) {
    let s = Keypair::from_secret([0x61; 32]);
    let (init, first) = Initiate::start(s.public()).unwrap();
    let (pending, response) = Respond::new(s).respond(&first).unwrap();
    let (ti, confirmation) = init.finish(&response).unwrap();
    (ti, pending.confirm(&confirmation).unwrap())
}

/// Suspend, keep only the bytes (the eviction), then resume at `floor`; returns the transport and the floor
/// to persist
fn evict(t: Transport, floor: u64) -> (Transport, u64) {
    let kept = t.suspend(&host_key()).unwrap().as_bytes().to_vec();
    let back = SuspendedTransport::from_bytes(&kept).unwrap();
    let resumed = Transport::resume(&back, &host_key(), floor).unwrap();
    let next = resumed.next_floor();
    (resumed.floor_persisted(), next)
}

/// The plaintext of a copy, opened with the documented layout and key derivation (not with the crate)
fn open_by_layout(bytes: &[u8]) -> (u8, u64, Vec<u8>) {
    assert_eq!(bytes.len(), 150);
    let key = sha256::hmac(&HOST_KEY, SUSPEND_KEY_LABEL);
    let (header, sealed) = bytes.split_at(22);
    let nonce: [u8; 12] = header[10..22].try_into().unwrap();
    let plain = aead::open(&key, &nonce, header, sealed).expect("the documented layout opens");
    let epoch = u64::from_le_bytes(header[2..10].try_into().unwrap());
    (header[1], epoch, plain)
}

/// A copy sealed by the test with the documented layout: `plain` as the sealed part
fn seal_by_layout(version: u8, phase: u8, epoch: u64, plain: &[u8]) -> Vec<u8> {
    let key = sha256::hmac(&HOST_KEY, SUSPEND_KEY_LABEL);
    let nonce = [0x33; 12];
    let mut header = vec![version, phase];
    header.extend_from_slice(&epoch.to_le_bytes());
    header.extend_from_slice(&nonce);
    let mut out = header.clone();
    out.extend_from_slice(&aead::seal(&key, &nonce, &header, plain));
    out
}

fn le(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

#[test]
fn the_layout_is_the_documented_one_and_carries_the_nonces() {
    assert_eq!(SUSPENDED_LEN, 150);
    assert_eq!(SUSPENDED_VERSION, 1);
    let (mut a, mut b) = handshake();
    let hash = a.handshake_hash();
    for _ in 0..3 {
        b.recv(&a.send(b"a to b").unwrap()).unwrap();
    }
    for _ in 0..5 {
        a.recv(&b.send(b"b to a").unwrap()).unwrap();
    }
    let s = a.suspend(&host_key()).unwrap();
    assert_eq!(s.as_bytes()[0], 1, "version");
    assert_eq!(s.epoch(), 0, "a channel fresh from its handshake");
    let (phase, epoch, plain) = open_by_layout(s.as_bytes());
    assert_eq!((phase, epoch), (0, 0));
    assert_eq!(plain.len(), 112);
    // the initiator's key confirmation is its first transport message (nonce 0)
    assert_eq!(
        le(&plain[32..40]),
        4,
        "send nonce: the confirmation and three messages sent"
    );
    assert_eq!(
        le(&plain[72..80]),
        5,
        "receive nonce: five messages received"
    );
    assert_eq!(&plain[80..112], &hash[..]);
    assert_ne!(&plain[0..32], &plain[40..72], "two directions, two keys");
}

#[test]
fn the_keys_are_not_readable_in_a_copy() {
    // a copy is sealed: neither transport key, nor the handshake hash, appears in its bytes
    let (a, _) = handshake();
    let s = a.suspend(&host_key()).unwrap();
    let (_, _, plain) = open_by_layout(s.as_bytes());
    for field in [&plain[0..32], &plain[40..72], &plain[80..112]] {
        assert!(!s
            .as_bytes()
            .windows(8)
            .any(|w| field.windows(8).any(|f| f == w)));
    }
}

#[test]
fn a_resumed_transport_keeps_talking_and_never_reuses_a_nonce() {
    // the same plaintext again and again across many evictions: under one key, equal ciphertexts would mean
    // an equal nonce; the peer opens each message in order (a reused nonce would not open)
    let (mut a, mut b) = handshake();
    let mut sent = Vec::new();
    let mut floor = 0;
    for round in 0..8 {
        for _ in 0..3 {
            let c = a.send(b"the same plaintext").unwrap();
            assert_eq!(b.recv(&c).unwrap(), b"the same plaintext");
            sent.push(c);
        }
        let echo = b.send(&[round; 4]).unwrap();
        (a, floor) = evict(a, floor);
        assert_eq!(
            floor,
            u64::from(round) + 1,
            "each resume moves the floor by one"
        );
        assert_eq!(
            a.recv(&echo).unwrap(),
            [round; 4],
            "the receive nonce survived"
        );
        (b, _) = evict(b, u64::from(round));
    }
    let mut distinct = sent.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(distinct.len(), sent.len(), "no ciphertext repeats");
    assert_eq!(sent.len(), 24);
}

#[test]
fn an_older_copy_is_refused_once_the_floor_has_moved() {
    let (a, mut b) = handshake();
    let old = a.suspend(&host_key()).unwrap();
    let old_bytes = old.as_bytes().to_vec();
    let resumed = Transport::resume(&old, &host_key(), 0).unwrap();
    assert_eq!(resumed.next_floor(), 1);
    // the host persists floor 1, then uses the transport
    let mut a = resumed.floor_persisted();
    b.recv(&a.send(b"first").unwrap()).unwrap();
    let newer = a.suspend(&host_key()).unwrap();
    assert_eq!(newer.epoch(), 1);
    // the older copy is refused at the floor, the newer one is accepted
    let old = SuspendedTransport::from_bytes(&old_bytes).unwrap();
    assert_eq!(
        Transport::resume(&old, &host_key(), 1)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Stale { epoch: 0, floor: 1 }
    );
    let resumed = Transport::resume(&newer, &host_key(), 1).unwrap();
    assert_eq!(resumed.next_floor(), 2);
    // and once floor 2 is persisted, the same copy is not accepted a second time
    assert_eq!(
        Transport::resume(&newer, &host_key(), 2)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Stale { epoch: 1, floor: 2 }
    );
    let mut a = resumed.floor_persisted();
    assert_eq!(b.recv(&a.send(b"second").unwrap()).unwrap(), b"second");
}

#[test]
fn an_eviction_between_a_send_and_the_next_copy_loses_the_channel_not_a_nonce() {
    // the host persisted floor 1 and sent a message, then was evicted before storing the next copy: what it
    // has is the copy at epoch 0, below its floor
    let (a, mut b) = handshake();
    let copy = a.suspend(&host_key()).unwrap();
    let resumed = Transport::resume(&copy, &host_key(), 0).unwrap();
    let floor = resumed.next_floor();
    let mut a = resumed.floor_persisted();
    b.recv(&a.send(b"left before the eviction").unwrap())
        .unwrap();
    drop(a);
    assert!(matches!(
        Transport::resume(&copy, &host_key(), floor),
        Err(ResumeError::Stale { epoch: 0, floor: 1 })
    ));
}

#[test]
fn a_stale_copy_used_anyway_is_caught_by_the_peer() {
    // a host that breaks the rule (resumes the same copy twice at floor 0): the second transport seals under
    // a nonce the peer has passed, so the peer cannot open it
    let (a, mut b) = handshake();
    let copy = a.suspend(&host_key()).unwrap();
    let mut first = Transport::resume(&copy, &host_key(), 0)
        .unwrap()
        .floor_persisted();
    let mut stale = Transport::resume(&copy, &host_key(), 0)
        .unwrap()
        .floor_persisted();
    let m1 = first.send(b"message one").unwrap();
    assert_eq!(b.recv(&m1).unwrap(), b"message one");
    let m2 = stale.send(b"message two").unwrap();
    assert_eq!(b.recv(&m2), Err(NoiseError::Decrypt));
    // the peer is still in step with the transport that followed the rule
    assert_eq!(b.recv(&first.send(b"three").unwrap()).unwrap(), b"three");
}

#[test]
fn every_cut_length_and_trailing_bytes_are_refused() {
    let (a, _) = handshake();
    let bytes = a.suspend(&host_key()).unwrap().as_bytes().to_vec();
    for n in 0..bytes.len() {
        assert_eq!(
            SuspendedTransport::from_bytes(&bytes[..n]).unwrap_err(),
            ResumeError::Length {
                expected: 150,
                got: n
            },
            "{n}"
        );
    }
    for extra in [1usize, 2, 16, 150] {
        let mut longer = bytes.clone();
        longer.extend(std::iter::repeat_n(0u8, extra));
        assert_eq!(
            SuspendedTransport::from_bytes(&longer).unwrap_err(),
            ResumeError::Length {
                expected: 150,
                got: 150 + extra
            }
        );
    }
}

#[test]
fn another_version_is_refused() {
    let (a, _) = handshake();
    let bytes = a.suspend(&host_key()).unwrap().as_bytes().to_vec();
    for v in [0u8, 2, 0x81, 0xff] {
        let mut m = bytes.clone();
        m[0] = v;
        assert_eq!(
            SuspendedTransport::from_bytes(&m).unwrap_err(),
            ResumeError::Version(v)
        );
    }
}

#[test]
fn every_bit_flip_is_refused() {
    let (a, _) = handshake();
    let bytes = a.suspend(&host_key()).unwrap().as_bytes().to_vec();
    let mut checked = 0;
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut m = bytes.clone();
            m[i] ^= 1 << bit;
            let got = SuspendedTransport::from_bytes(&m)
                .and_then(|s| Transport::resume(&s, &host_key(), 0).map(|_| ()));
            let want = if i == 0 {
                ResumeError::Version(m[0])
            } else {
                ResumeError::Authentication
            };
            assert_eq!(got.unwrap_err(), want, "byte {i} bit {bit}");
            checked += 1;
        }
    }
    assert_eq!(checked, 150 * 8);
}

#[test]
fn a_raised_epoch_does_not_pass_the_floor() {
    // the attack the header binding stops: an old copy with its epoch edited upward to get past the floor
    let (a, _) = handshake();
    let s = a.suspend(&host_key()).unwrap();
    let mut m = s.as_bytes().to_vec();
    m[2..10].copy_from_slice(&7u64.to_le_bytes());
    let edited = SuspendedTransport::from_bytes(&m).unwrap();
    assert_eq!(edited.epoch(), 7);
    assert_eq!(
        Transport::resume(&edited, &host_key(), 5)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Authentication
    );
}

#[test]
fn another_host_key_is_refused() {
    let (a, _) = handshake();
    let s = a.suspend(&host_key()).unwrap();
    assert_eq!(
        Transport::resume(&s, &SuspendKey::from_bytes([0x5b; 32]), 0)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Authentication
    );
}

#[test]
fn a_wrong_length_key_field_is_refused() {
    // copies sealed with a valid tag whose send key is 31 or 33 bytes: the whole is not 150 bytes long
    for key_len in [31usize, 33] {
        let mut plain = vec![0x11; key_len];
        plain.extend_from_slice(&0u64.to_le_bytes());
        plain.extend_from_slice(&[0x22; 32]);
        plain.extend_from_slice(&0u64.to_le_bytes());
        plain.extend_from_slice(&[0x44; 32]);
        let m = seal_by_layout(1, 0, 0, &plain);
        assert_eq!(
            SuspendedTransport::from_bytes(&m).unwrap_err(),
            ResumeError::Length {
                expected: 150,
                got: 150 - 32 + key_len
            }
        );
    }
}

fn valid_plain() -> Vec<u8> {
    let mut plain = vec![0x11; 32];
    plain.extend_from_slice(&0u64.to_le_bytes());
    plain.extend_from_slice(&[0x22; 32]);
    plain.extend_from_slice(&0u64.to_le_bytes());
    plain.extend_from_slice(&[0x44; 32]);
    plain
}

#[test]
fn a_copy_sealed_by_the_layout_resumes() {
    // the tooth of the tests that seal their own copies: a well-formed one is accepted
    let m = seal_by_layout(1, 0, 4, &valid_plain());
    let s = SuspendedTransport::from_bytes(&m).unwrap();
    let r = Transport::resume(&s, &host_key(), 4).unwrap();
    assert_eq!(r.next_floor(), 5);
    assert_eq!(r.floor_persisted().handshake_hash(), [0x44; 32]);
}

#[test]
fn an_unknown_or_other_phase_is_refused() {
    for phase in [2u8, 7, 0xff] {
        let s =
            SuspendedTransport::from_bytes(&seal_by_layout(1, phase, 0, &valid_plain())).unwrap();
        assert_eq!(
            Transport::resume(&s, &host_key(), 0)
                .map(|_| ())
                .unwrap_err(),
            ResumeError::Phase(phase)
        );
        assert_eq!(
            AwaitConfirmation::resume(&s, &host_key(), 0)
                .map(|_| ())
                .unwrap_err(),
            ResumeError::Phase(phase)
        );
    }
    let open = SuspendedTransport::from_bytes(&seal_by_layout(1, 0, 0, &valid_plain())).unwrap();
    assert_eq!(
        AwaitConfirmation::resume(&open, &host_key(), 0)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Phase(0)
    );
    let waiting = SuspendedTransport::from_bytes(&seal_by_layout(1, 1, 0, &valid_plain())).unwrap();
    assert_eq!(
        Transport::resume(&waiting, &host_key(), 0)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Phase(1)
    );
}

#[test]
fn the_last_epoch_cannot_be_resumed() {
    let s =
        SuspendedTransport::from_bytes(&seal_by_layout(1, 0, u64::MAX, &valid_plain())).unwrap();
    assert_eq!(
        Transport::resume(&s, &host_key(), 0)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::EpochExhausted
    );
    let s = SuspendedTransport::from_bytes(&seal_by_layout(1, 0, u64::MAX - 1, &valid_plain()))
        .unwrap();
    assert_eq!(
        Transport::resume(&s, &host_key(), 0).unwrap().next_floor(),
        u64::MAX
    );
}

#[test]
fn a_responder_evicted_while_it_waits_for_the_key_confirmation() {
    // the first message and the response in one callback, the key confirmation in the next, after an eviction
    let s = Keypair::from_secret([0x61; 32]);
    let (init, first) = Initiate::start(s.public()).unwrap();
    let (pending, response) = Respond::new(s).respond(&first).unwrap();
    let hash = pending.handshake_hash();
    let kept = pending.suspend(&host_key()).unwrap().as_bytes().to_vec();
    let (phase, epoch, _) = open_by_layout(&kept);
    assert_eq!((phase, epoch), (1, 0));
    let (mut ti, confirmation) = init.finish(&response).unwrap();
    let back = SuspendedTransport::from_bytes(&kept).unwrap();
    // a waiting state is not an open transport
    assert_eq!(
        Transport::resume(&back, &host_key(), 0)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Phase(1)
    );
    let resumed = AwaitConfirmation::resume(&back, &host_key(), 0).unwrap();
    assert_eq!(resumed.next_floor(), 1);
    let pending = resumed.floor_persisted();
    assert_eq!(pending.handshake_hash(), hash);
    let mut tr = pending.confirm(&confirmation).unwrap();
    assert_eq!(tr.recv(&ti.send(b"after").unwrap()).unwrap(), b"after");
    assert_eq!(
        ti.recv(&tr.send(b"both ways").unwrap()).unwrap(),
        b"both ways"
    );
    // the copy of the waiting state is refused once the floor has moved
    assert!(matches!(
        AwaitConfirmation::resume(&back, &host_key(), 1),
        Err(ResumeError::Stale { epoch: 0, floor: 1 })
    ));
}
