//! Oracle for suspending and resuming a transport ([`Transport::suspend`], [`Transport::resume`]), for a host
//! that may be evicted and restarted between two messages.
//!
//! The nonce rule is the core: a resumed transport continues from the nonces it was suspended at (the peer
//! opens every message in order, and equal plaintexts never give equal ciphertexts), a copy older than the
//! host's floor is refused, and a copy of another channel (an earlier handshake in the same storage slot) is
//! refused even at floor 0. A stale copy used in breach of the rule has already reused a (key, nonce) pair
//! when the peer refuses it: the test shows the two ciphertexts give away the XOR of the plaintexts, so the
//! peer's refusal is detection after the fact, not protection. The layout is checked from outside: the test
//! opens a real copy with the documented key derivation and reads the channel id, the nonce counters and the
//! handshake hash out of it, and seals copies of its own to reach the checks that need a valid tag (a
//! wrong-length key field, an unknown phase, the last epoch, an older version). Every cut length, every bit
//! flip, a changed version and trailing bytes are refused with a typed error.

use alice_channel::noise::suspend::{SUSPENDED_LEN, SUSPENDED_VERSION, SUSPEND_KEY_LABEL};
use alice_channel::noise::{
    ChannelId, Keypair, NoiseError, ResumeError, SuspendKey, SuspendedTransport, Transport,
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
    let id = t.channel_id();
    let kept = t.suspend(&host_key()).unwrap().as_bytes().to_vec();
    let back = SuspendedTransport::from_bytes(&kept).unwrap();
    let resumed = Transport::resume(&back, &host_key(), floor, id).unwrap();
    let next = resumed.next_floor();
    (resumed.floor_persisted(), next)
}

/// The header of version 2: version | phase | channel id (16) | epoch u64 LE | nonce (12)
const HEADER: usize = 38;
const ID: std::ops::Range<usize> = 2..18;
const EPOCH: std::ops::Range<usize> = 18..26;

/// The phase, channel id, epoch and plaintext of a copy, opened with the documented layout and key derivation
/// (not with the crate)
fn open_by_layout(bytes: &[u8]) -> (u8, [u8; 16], u64, Vec<u8>) {
    assert_eq!(bytes.len(), 166);
    let key = sha256::hmac(&HOST_KEY, SUSPEND_KEY_LABEL);
    let (header, sealed) = bytes.split_at(HEADER);
    let nonce: [u8; 12] = header[26..38].try_into().unwrap();
    let plain = aead::open(&key, &nonce, header, sealed).expect("the documented layout opens");
    let epoch = u64::from_le_bytes(header[EPOCH].try_into().unwrap());
    (header[1], header[ID].try_into().unwrap(), epoch, plain)
}

/// The channel of the copies the test seals itself: the first 16 bytes of their handshake hash (`[0x44; 32]`)
const SEALED_ID: [u8; 16] = [0x44; 16];

fn sealed_id() -> ChannelId {
    ChannelId::from_bytes(SEALED_ID)
}

/// A copy sealed by the test with the documented layout: `plain` as the sealed part
fn seal_by_layout(version: u8, phase: u8, epoch: u64, plain: &[u8]) -> Vec<u8> {
    let key = sha256::hmac(&HOST_KEY, SUSPEND_KEY_LABEL);
    let nonce = [0x33; 12];
    let mut header = vec![version, phase];
    header.extend_from_slice(&SEALED_ID);
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
    assert_eq!(SUSPENDED_LEN, 166);
    assert_eq!(SUSPENDED_VERSION, 2);
    let (mut a, mut b) = handshake();
    let hash = a.handshake_hash();
    for _ in 0..3 {
        b.recv(&a.send(b"a to b").unwrap()).unwrap();
    }
    for _ in 0..5 {
        a.recv(&b.send(b"b to a").unwrap()).unwrap();
    }
    let id = a.channel_id();
    assert_eq!(
        id.as_bytes(),
        &hash[..16],
        "the channel id is the hash's first 16 bytes"
    );
    let s = a.suspend(&host_key()).unwrap();
    assert_eq!(s.as_bytes()[0], 2, "version");
    assert_eq!(s.epoch(), 0, "a channel fresh from its handshake");
    assert_eq!(s.channel_id(), id);
    let (phase, got_id, epoch, plain) = open_by_layout(s.as_bytes());
    assert_eq!((phase, epoch), (0, 0));
    assert_eq!(&got_id, id.as_bytes());
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
    // a copy is sealed: neither transport key, nor the second half of the handshake hash (the first half is
    // the channel id, in clear in the header by design), appears in its bytes
    let (a, _) = handshake();
    let s = a.suspend(&host_key()).unwrap();
    let (_, _, _, plain) = open_by_layout(s.as_bytes());
    for field in [&plain[0..32], &plain[40..72], &plain[96..112]] {
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
    let id = a.channel_id();
    let old = a.suspend(&host_key()).unwrap();
    let old_bytes = old.as_bytes().to_vec();
    let resumed = Transport::resume(&old, &host_key(), 0, id).unwrap();
    assert_eq!(resumed.next_floor(), 1);
    // the host persists floor 1, then uses the transport
    let mut a = resumed.floor_persisted();
    b.recv(&a.send(b"first").unwrap()).unwrap();
    let newer = a.suspend(&host_key()).unwrap();
    assert_eq!(newer.epoch(), 1);
    // the older copy is refused at the floor, the newer one is accepted
    let old = SuspendedTransport::from_bytes(&old_bytes).unwrap();
    assert_eq!(
        Transport::resume(&old, &host_key(), 1, id)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Stale { epoch: 0, floor: 1 }
    );
    let resumed = Transport::resume(&newer, &host_key(), 1, id).unwrap();
    assert_eq!(resumed.next_floor(), 2);
    // and once floor 2 is persisted, the same copy is not accepted a second time
    assert_eq!(
        Transport::resume(&newer, &host_key(), 2, id)
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
    let id = a.channel_id();
    let copy = a.suspend(&host_key()).unwrap();
    let resumed = Transport::resume(&copy, &host_key(), 0, id).unwrap();
    let floor = resumed.next_floor();
    let mut a = resumed.floor_persisted();
    b.recv(&a.send(b"left before the eviction").unwrap())
        .unwrap();
    drop(a);
    assert!(matches!(
        Transport::resume(&copy, &host_key(), floor, id),
        Err(ResumeError::Stale { epoch: 0, floor: 1 })
    ));
}

#[test]
fn a_stale_copy_used_anyway_has_reused_a_nonce_before_the_peer_refuses_it() {
    // a host that breaks the rule (resumes the same copy twice at floor 0): the second transport seals under
    // the (key, nonce) pair the first already used. The peer refuses the second message, but only after the
    // fact: anyone who saw both ciphertexts has the XOR of the two plaintexts, so persisting the floor first
    // is the only protection
    let (a, mut b) = handshake();
    let id = a.channel_id();
    let copy = a.suspend(&host_key()).unwrap();
    let mut first = Transport::resume(&copy, &host_key(), 0, id)
        .unwrap()
        .floor_persisted();
    let mut stale = Transport::resume(&copy, &host_key(), 0, id)
        .unwrap()
        .floor_persisted();
    let p1 = b"message one, 23 bytes..";
    let p2 = b"MESSAGE TWO, 23 BYTES!!";
    let c1 = first.send(p1).unwrap();
    assert_eq!(b.recv(&c1).unwrap(), p1);
    let c2 = stale.send(p2).unwrap();
    // the leak: c1 XOR c2 over the plaintext part is p1 XOR p2 (the same ChaCha20 keystream)
    let leaked: Vec<u8> = c1
        .iter()
        .zip(&c2)
        .take(p1.len())
        .map(|(x, y)| x ^ y)
        .collect();
    let xor: Vec<u8> = p1.iter().zip(p2).map(|(x, y)| x ^ y).collect();
    assert_eq!(
        leaked, xor,
        "a reused nonce gives away the XOR of the plaintexts"
    );
    // the peer's refusal comes after the leak
    assert_eq!(b.recv(&c2), Err(NoiseError::Decrypt));
    assert_eq!(b.recv(&first.send(b"three").unwrap()).unwrap(), b"three");
}

#[test]
fn the_copy_of_an_earlier_channel_is_refused_after_a_new_handshake() {
    // a host reuses a storage slot: the old channel's copy is still there when a new handshake starts the
    // floor again at 0. Without the channel id the old copy would resume and seal under its old (key,
    // counter) pairs; with it, the old copy is refused
    let (old, _) = handshake();
    let old_id = old.channel_id();
    let left_over = old.suspend(&host_key()).unwrap();
    let (new, _) = handshake();
    let new_id = new.channel_id();
    assert_ne!(old_id, new_id, "every handshake is a new channel");
    assert_eq!(
        Transport::resume(&left_over, &host_key(), 0, new_id)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::OtherChannel {
            expected: new_id,
            got: old_id
        }
    );
    // the new channel's own copy resumes with its id
    let copy = new.suspend(&host_key()).unwrap();
    assert!(Transport::resume(&copy, &host_key(), 0, new_id).is_ok());
}

#[test]
fn a_changed_channel_id_in_the_header_fails_authentication() {
    // the id is in the authenticated header: editing it breaks the tag, whatever id the host expects (the
    // tag is checked before the id is compared)
    let (a, _) = handshake();
    let id = a.channel_id();
    let mut m = a.suspend(&host_key()).unwrap().as_bytes().to_vec();
    m[ID.start + 3] ^= 0x10;
    let edited = SuspendedTransport::from_bytes(&m).unwrap();
    let edited_id = edited.channel_id();
    assert_ne!(edited_id, id);
    for expected in [id, edited_id] {
        assert_eq!(
            Transport::resume(&edited, &host_key(), 0, expected)
                .map(|_| ())
                .unwrap_err(),
            ResumeError::Authentication
        );
    }
}

#[test]
fn a_copy_of_the_previous_layout_is_refused_by_its_version() {
    // version 1 (150 bytes, no channel id) is refused by its version byte, before its length is looked at
    let mut v1 = vec![1u8];
    v1.extend(std::iter::repeat_n(0u8, 149));
    assert_eq!(
        SuspendedTransport::from_bytes(&v1).unwrap_err(),
        ResumeError::Version(1)
    );
}

#[test]
fn every_cut_length_and_trailing_bytes_are_refused() {
    let (a, _) = handshake();
    let bytes = a.suspend(&host_key()).unwrap().as_bytes().to_vec();
    for n in 0..bytes.len() {
        assert_eq!(
            SuspendedTransport::from_bytes(&bytes[..n]).unwrap_err(),
            ResumeError::Length {
                expected: 166,
                got: n
            },
            "{n}"
        );
    }
    for extra in [1usize, 2, 16, 166] {
        let mut longer = bytes.clone();
        longer.extend(std::iter::repeat_n(0u8, extra));
        assert_eq!(
            SuspendedTransport::from_bytes(&longer).unwrap_err(),
            ResumeError::Length {
                expected: 166,
                got: 166 + extra
            }
        );
    }
}

#[test]
fn another_version_is_refused() {
    let (a, _) = handshake();
    let bytes = a.suspend(&host_key()).unwrap().as_bytes().to_vec();
    for v in [0u8, 1, 3, 0x81, 0xff] {
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
    let id = a.channel_id();
    let bytes = a.suspend(&host_key()).unwrap().as_bytes().to_vec();
    let mut checked = 0;
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut m = bytes.clone();
            m[i] ^= 1 << bit;
            let got = SuspendedTransport::from_bytes(&m)
                .and_then(|s| Transport::resume(&s, &host_key(), 0, id).map(|_| ()));
            let want = if i == 0 {
                ResumeError::Version(m[0])
            } else {
                ResumeError::Authentication
            };
            assert_eq!(got.unwrap_err(), want, "byte {i} bit {bit}");
            checked += 1;
        }
    }
    assert_eq!(checked, 166 * 8);
}

#[test]
fn a_raised_epoch_does_not_pass_the_floor() {
    // the attack the header binding stops: an old copy with its epoch edited upward to get past the floor
    let (a, _) = handshake();
    let id = a.channel_id();
    let s = a.suspend(&host_key()).unwrap();
    let mut m = s.as_bytes().to_vec();
    m[EPOCH].copy_from_slice(&7u64.to_le_bytes());
    let edited = SuspendedTransport::from_bytes(&m).unwrap();
    assert_eq!(edited.epoch(), 7);
    assert_eq!(
        Transport::resume(&edited, &host_key(), 5, id)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Authentication
    );
}

#[test]
fn another_host_key_is_refused() {
    let (a, _) = handshake();
    let id = a.channel_id();
    let s = a.suspend(&host_key()).unwrap();
    assert_eq!(
        Transport::resume(&s, &SuspendKey::from_bytes([0x5b; 32]), 0, id)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Authentication
    );
}

#[test]
fn a_wrong_length_key_field_is_refused() {
    // copies sealed with a valid tag whose send key is 31 or 33 bytes: the whole is not 166 bytes long
    for key_len in [31usize, 33] {
        let mut plain = vec![0x11; key_len];
        plain.extend_from_slice(&0u64.to_le_bytes());
        plain.extend_from_slice(&[0x22; 32]);
        plain.extend_from_slice(&0u64.to_le_bytes());
        plain.extend_from_slice(&[0x44; 32]);
        let m = seal_by_layout(2, 0, 0, &plain);
        assert_eq!(
            SuspendedTransport::from_bytes(&m).unwrap_err(),
            ResumeError::Length {
                expected: 166,
                got: 166 - 32 + key_len
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
    let m = seal_by_layout(2, 0, 4, &valid_plain());
    let s = SuspendedTransport::from_bytes(&m).unwrap();
    let r = Transport::resume(&s, &host_key(), 4, sealed_id()).unwrap();
    assert_eq!(r.next_floor(), 5);
    assert_eq!(r.floor_persisted().handshake_hash(), [0x44; 32]);
}

#[test]
fn an_unknown_or_other_phase_is_refused() {
    for phase in [2u8, 7, 0xff] {
        let s =
            SuspendedTransport::from_bytes(&seal_by_layout(2, phase, 0, &valid_plain())).unwrap();
        assert_eq!(
            Transport::resume(&s, &host_key(), 0, sealed_id())
                .map(|_| ())
                .unwrap_err(),
            ResumeError::Phase(phase)
        );
        assert_eq!(
            AwaitConfirmation::resume(&s, &host_key(), 0, sealed_id())
                .map(|_| ())
                .unwrap_err(),
            ResumeError::Phase(phase)
        );
    }
    let open = SuspendedTransport::from_bytes(&seal_by_layout(2, 0, 0, &valid_plain())).unwrap();
    assert_eq!(
        AwaitConfirmation::resume(&open, &host_key(), 0, sealed_id())
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Phase(0)
    );
    let waiting = SuspendedTransport::from_bytes(&seal_by_layout(2, 1, 0, &valid_plain())).unwrap();
    assert_eq!(
        Transport::resume(&waiting, &host_key(), 0, sealed_id())
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Phase(1)
    );
}

#[test]
fn the_last_epoch_cannot_be_resumed() {
    let s =
        SuspendedTransport::from_bytes(&seal_by_layout(2, 0, u64::MAX, &valid_plain())).unwrap();
    assert_eq!(
        Transport::resume(&s, &host_key(), 0, sealed_id())
            .map(|_| ())
            .unwrap_err(),
        ResumeError::EpochExhausted
    );
    let s = SuspendedTransport::from_bytes(&seal_by_layout(2, 0, u64::MAX - 1, &valid_plain()))
        .unwrap();
    assert_eq!(
        Transport::resume(&s, &host_key(), 0, sealed_id())
            .unwrap()
            .next_floor(),
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
    let id = pending.channel_id();
    let kept = pending.suspend(&host_key()).unwrap().as_bytes().to_vec();
    let (phase, got_id, epoch, _) = open_by_layout(&kept);
    assert_eq!((phase, epoch), (1, 0));
    assert_eq!(&got_id, id.as_bytes());
    let (mut ti, confirmation) = init.finish(&response).unwrap();
    let back = SuspendedTransport::from_bytes(&kept).unwrap();
    // a waiting state is not an open transport
    assert_eq!(
        Transport::resume(&back, &host_key(), 0, id)
            .map(|_| ())
            .unwrap_err(),
        ResumeError::Phase(1)
    );
    let resumed = AwaitConfirmation::resume(&back, &host_key(), 0, id).unwrap();
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
        AwaitConfirmation::resume(&back, &host_key(), 1, id),
        Err(ResumeError::Stale { epoch: 0, floor: 1 })
    ));
}
