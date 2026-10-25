//! Oracle for the datagram mode: the same Noise IK handshake and identity binding as the stream channel,
//! carried in datagrams that may be lost, reordered or duplicated. Each data packet is sealed on its own
//! with an explicit 64-bit counter as its nonce, and the receiver keeps a sliding window of the counters it
//! has opened, so a packet opens at most once and in any order within the window. The handshake survives a
//! lost or repeated packet: the initiator repeats its first packet, the responder answers a repeated first
//! packet with the same response, and the first data packet that opens confirms the keys.

use std::collections::BTreeMap;

use alice_channel::datagram::{
    Confirmed, DatagramChannel, DatagramError, InitTimestamp, Initiator, Pending, Responder,
    DATAGRAM_AD, KIND_DATA, REPLAY_WINDOW,
};
use alice_channel::noise::Keypair;
use alice_channel::{ChannelError, Credential, PeerPolicy};
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
}

fn party(seed: u8, name: &str) -> Party {
    let master = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let did = Did::parse(&format!("did:alice:{name}")).unwrap();
    let noise_static = Keypair::from_secret([seed.wrapping_add(200); 32]);
    let cert = DeviceCert::issue(
        &master,
        &did,
        device.public().0,
        noise_static.public(),
        ISSUED_AT,
        NOT_AFTER,
        [seed; 16],
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

impl Policy {
    fn knowing(parties: &[&Party]) -> Self {
        Self {
            masters: parties
                .iter()
                .map(|p| (p.did.to_string(), p.master.public()))
                .collect(),
        }
    }
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

fn cert(p: &Party) -> DeviceCert {
    p.cred.cert().clone()
}

/// A completed handshake: (initiator's channel, responder's channel)
fn connected(a: &Party, b: &Party) -> (DatagramChannel, DatagramChannel) {
    let policy = Policy::knowing(&[a, b]);
    let (init, first) = Initiator::start(&a.cred, &policy, &cert(b)).unwrap();
    let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
    let (ca, confirm) = init.finish(pending.response(), &policy).unwrap();
    let (cb, payload) = pending.confirm(&confirm).channel().unwrap();
    assert_eq!(payload, None, "the key confirmation carries no payload");
    (ca, cb)
}

#[test]
fn a_handshake_gives_both_sides_the_peer_and_the_same_binding() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (ca, cb) = connected(&a, &b);
    assert_eq!(ca.peer_cert().subject(), cert(&b).subject());
    assert_eq!(cb.peer_cert().subject(), cert(&a).subject());
    assert_eq!(ca.handshake_hash(), cb.handshake_hash());
}

#[test]
fn packets_open_in_any_order_and_each_only_once() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, mut cb) = connected(&a, &b);
    let sent: Vec<Vec<u8>> = (0..64u8).map(|i| ca.seal(&[i; 40]).unwrap()).collect();
    // a fixed shuffle: reversed halves, interleaved
    let mut order: Vec<usize> = (32..64).rev().chain(0..32).collect();
    order.swap(3, 40);
    let mut got = Vec::new();
    for &i in &order {
        got.push(cb.open(&sent[i]).unwrap().expect("a data packet"));
    }
    let mut want: Vec<Vec<u8>> = order
        .iter()
        .map(|&i| vec![u8::try_from(i).unwrap(); 40])
        .collect();
    want.sort();
    got.sort();
    assert_eq!(got, want);
    for p in &sent {
        assert!(
            matches!(cb.open(p), Err(DatagramError::Replayed)),
            "a second copy opens"
        );
    }
}

#[test]
fn a_lost_packet_does_not_stop_the_ones_after_it() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, mut cb) = connected(&a, &b);
    let sent: Vec<Vec<u8>> = (0..10u8).map(|i| ca.seal(&[i]).unwrap()).collect();
    for (i, p) in sent.iter().enumerate() {
        if i % 3 == 1 {
            continue; // lost
        }
        assert_eq!(cb.open(p).unwrap(), Some(vec![u8::try_from(i).unwrap()]));
    }
}

#[test]
fn a_packet_older_than_the_window_is_refused() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, mut cb) = connected(&a, &b);
    let window = usize::try_from(REPLAY_WINDOW).unwrap();
    // counters 1 ..= window + 1 (counter 0 was the key confirmation)
    let sent: Vec<Vec<u8>> = (0..=window).map(|_| ca.seal(b"x").unwrap()).collect();
    // open the newest first: the oldest is then window + 1 counters behind the next expected one
    cb.open(sent.last().unwrap()).unwrap();
    assert!(matches!(cb.open(&sent[0]), Err(DatagramError::TooOld)));
    // the oldest one still in the window opens
    assert_eq!(cb.open(&sent[1]).unwrap(), Some(b"x".to_vec()));
}

#[test]
fn a_changed_packet_is_refused_and_does_not_move_the_window() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, mut cb) = connected(&a, &b);
    let good = ca.seal(b"hello").unwrap();
    // the same counter with a flipped ciphertext byte
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(matches!(cb.open(&bad), Err(DatagramError::Decrypt)));
    assert_eq!(
        cb.open(&good).unwrap(),
        Some(b"hello".to_vec()),
        "the genuine packet still opens"
    );
    // a forged counter far ahead does not advance the window either
    let mut far = ca.seal(b"later").unwrap();
    far[1..9].copy_from_slice(&(u64::MAX - 2).to_le_bytes());
    assert!(matches!(cb.open(&far), Err(DatagramError::Decrypt)));
    let next = ca.seal(b"next").unwrap();
    assert_eq!(cb.open(&next).unwrap(), Some(b"next".to_vec()));
}

#[test]
fn a_packet_that_is_not_a_data_packet_is_refused() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, mut cb) = connected(&a, &b);
    let good = ca.seal(b"x").unwrap();
    assert_eq!(good[0], KIND_DATA);
    for bad in [vec![], vec![KIND_DATA], good[..12].to_vec(), {
        let mut p = good.clone();
        p[0] = 9;
        p
    }] {
        assert!(
            matches!(cb.open(&bad), Err(DatagramError::Malformed)),
            "{bad:?}"
        );
    }
}

#[test]
fn an_empty_payload_is_not_sent() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, _) = connected(&a, &b);
    assert!(matches!(ca.seal(&[]), Err(DatagramError::Empty)));
}

#[test]
fn a_repeated_first_packet_gets_the_same_response_not_a_new_handshake() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let policy = Policy::knowing(&[&a, &b]);
    let (init, first) = Initiator::start(&a.cred, &policy, &cert(&b)).unwrap();
    assert_eq!(
        init.first(),
        &first[..],
        "the initiator repeats the same bytes"
    );
    let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
    assert!(pending.is_first(&first));
    assert!(!pending.is_first(&[first.clone(), vec![0]].concat()));
    let response = pending.response().to_vec();
    // the responder answers the repeat with the bytes it already sent
    assert_eq!(pending.response(), &response[..]);
    let (_, confirm) = init.finish(&response, &policy).unwrap();
    pending.confirm(&confirm).channel().unwrap();
}

#[test]
fn a_lost_confirmation_is_replaced_by_the_first_data_packet() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let policy = Policy::knowing(&[&a, &b]);
    let (init, first) = Initiator::start(&a.cred, &policy, &cert(&b)).unwrap();
    let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
    let (mut ca, _lost) = init.finish(pending.response(), &policy).unwrap();
    let data = ca.seal(b"first message").unwrap();
    let (_cb, payload) = pending.confirm(&data).channel().unwrap();
    assert_eq!(payload, Some(b"first message".to_vec()));
}

#[test]
fn a_repeated_response_after_the_handshake_gets_a_fresh_confirmation() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let policy = Policy::knowing(&[&a, &b]);
    let (init, first) = Initiator::start(&a.cred, &policy, &cert(&b)).unwrap();
    let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
    let response = pending.response().to_vec();
    let (mut ca, lost) = init.finish(&response, &policy).unwrap();
    let again = ca
        .answer_repeated_response(&response)
        .expect("the response it finished on")
        .unwrap();
    assert_ne!(again, lost, "a new counter");
    assert!(ca.answer_repeated_response(b"\x02other").is_none());
    let (_cb, payload) = pending.confirm(&again).channel().unwrap();
    assert_eq!(payload, None);
}

#[test]
fn a_stray_packet_leaves_the_pending_responder_waiting() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let policy = Policy::knowing(&[&a, &b]);
    let (init, first) = Initiator::start(&a.cred, &policy, &cert(&b)).unwrap();
    let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
    let (_, confirm) = init.finish(pending.response(), &policy).unwrap();
    let mut stray = confirm.clone();
    *stray.last_mut().unwrap() ^= 1;
    let pending: Pending = match pending.confirm(&stray) {
        Confirmed::Waiting(p, DatagramError::Decrypt) => p,
        Confirmed::Waiting(_, e) => panic!("{e}"),
        Confirmed::Open(..) => panic!("a changed packet opened"),
    };
    pending.confirm(&confirm).channel().unwrap();
}

#[test]
fn an_unknown_initiator_gets_no_response() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let knows_b_only = Policy::knowing(&[&b]);
    let both = Policy::knowing(&[&a, &b]);
    let (_, first) = Initiator::start(&a.cred, &both, &cert(&b)).unwrap();
    assert!(matches!(
        Responder::new().respond(&b.cred, &knows_b_only, &first),
        Err(ChannelError::UnknownPeer)
    ));
}

#[test]
fn a_first_packet_for_another_device_does_not_open() {
    let (a, b, c) = (party(1, "a"), party(2, "b"), party(3, "c"));
    let policy = Policy::knowing(&[&a, &b, &c]);
    let (_, first) = Initiator::start(&a.cred, &policy, &cert(&b)).unwrap();
    assert!(matches!(
        Responder::new().respond(&c.cred, &policy, &first),
        Err(ChannelError::Noise(_))
    ));
}

#[test]
fn the_two_directions_are_independent() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, mut cb) = connected(&a, &b);
    let to_b = ca.seal(b"to b").unwrap();
    let to_a = cb.seal(b"to a").unwrap();
    assert_eq!(cb.open(&to_b).unwrap(), Some(b"to b".to_vec()));
    assert_eq!(ca.open(&to_a).unwrap(), Some(b"to a".to_vec()));
    // a packet sealed by a side does not open on that side
    let own = ca.seal(b"own").unwrap();
    assert!(matches!(ca.open(&own), Err(DatagramError::Decrypt)));
}

#[test]
fn a_long_run_in_order_opens_past_the_window_size() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, mut cb) = connected(&a, &b);
    let n = usize::try_from(REPLAY_WINDOW).unwrap() * 3 + 7;
    for i in 0..n {
        let p = ca.seal(&i.to_le_bytes()).unwrap();
        assert_eq!(
            cb.open(&p).unwrap(),
            Some(i.to_le_bytes().to_vec()),
            "packet {i}"
        );
    }
}

#[test]
fn a_jump_ahead_forgets_the_counters_it_leaves_behind_and_only_those() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, mut cb) = connected(&a, &b);
    let window = usize::try_from(REPLAY_WINDOW).unwrap();
    // sent[i] carries counter i + 1
    let sent: Vec<Vec<u8>> = (0..2 * window)
        .map(|i| ca.seal(&i.to_le_bytes()).unwrap())
        .collect();
    for p in &sent[..window] {
        cb.open(p).unwrap();
    }
    // jump by less than the window: counter 1.5 * window opens
    cb.open(&sent[window + window / 2 - 1]).unwrap();
    // a counter the jump passed over, in the window, whose slot an older counter used, opens once
    let back = window + window / 4;
    assert_eq!(
        cb.open(&sent[back]).unwrap(),
        Some(back.to_le_bytes().to_vec())
    );
    assert!(matches!(cb.open(&sent[back]), Err(DatagramError::Replayed)));
}

#[test]
fn a_packet_of_the_wrong_kind_does_not_start_or_finish_a_handshake() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let policy = Policy::knowing(&[&a, &b]);
    let (init, first) = Initiator::start(&a.cred, &policy, &cert(&b)).unwrap();
    let mut as_data = first.clone();
    as_data[0] = KIND_DATA;
    assert!(Responder::new()
        .respond(&b.cred, &policy, &as_data)
        .is_err());
    let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
    let mut as_init = pending.response().to_vec();
    as_init[0] = first[0];
    assert!(init.finish(&as_init, &policy).is_err());
}

#[test]
fn a_replayed_init_is_refused_and_a_later_one_is_answered() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let policy = Policy::knowing(&[&a, &b]);
    let mut responder = Responder::new();
    let t = InitTimestamp::from_unix(1_800_000_000, 5);
    let (_, first) = Initiator::start_at(&a.cred, &policy, &cert(&b), t).unwrap();
    responder.respond(&b.cred, &policy, &first).unwrap();
    // the same init again, or one made earlier, starts nothing
    assert!(matches!(
        responder.respond(&b.cred, &policy, &first),
        Err(ChannelError::StaleInit)
    ));
    let earlier = InitTimestamp::from_unix(1_800_000_000, 4);
    let (_, old) = Initiator::start_at(&a.cred, &policy, &cert(&b), earlier).unwrap();
    assert!(matches!(
        responder.respond(&b.cred, &policy, &old),
        Err(ChannelError::StaleInit)
    ));
    let (_, same_time) = Initiator::start_at(&a.cred, &policy, &cert(&b), t).unwrap();
    assert!(matches!(
        responder.respond(&b.cred, &policy, &same_time),
        Err(ChannelError::StaleInit)
    ));
    // a later init is answered
    let later = InitTimestamp::from_unix(1_800_000_000, 6);
    let (init, fresh) = Initiator::start_at(&a.cred, &policy, &cert(&b), later).unwrap();
    let pending = responder.respond(&b.cred, &policy, &fresh).unwrap();
    let (_, confirm) = init.finish(pending.response(), &policy).unwrap();
    pending.confirm(&confirm).channel().unwrap();
}

#[test]
fn the_timestamps_of_two_initiators_are_kept_apart() {
    let (a, b, c) = (party(1, "a"), party(2, "b"), party(3, "c"));
    let policy = Policy::knowing(&[&a, &b, &c]);
    let mut responder = Responder::new();
    let t = InitTimestamp::from_unix(1_800_000_000, 0);
    let (_, from_a) = Initiator::start_at(&a.cred, &policy, &cert(&b), t).unwrap();
    let (_, from_c) = Initiator::start_at(&c.cred, &policy, &cert(&b), t).unwrap();
    responder.respond(&b.cred, &policy, &from_a).unwrap();
    responder.respond(&b.cred, &policy, &from_c).unwrap();
}

#[test]
fn timestamps_order_by_seconds_then_nanoseconds() {
    let t = |s, n| InitTimestamp::from_unix(s, n);
    assert!(t(1, 999_999_999) < t(2, 0));
    assert!(t(2, 0) < t(2, 1));
    assert_eq!(t(0, 0).0, [0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(t(1, 2_000_000_000), t(1, 999_999_999));
}

#[test]
fn every_packet_of_a_long_run_has_its_own_ciphertext() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let (mut ca, _) = connected(&a, &b);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..600 {
        let p = ca.seal(b"the same payload").unwrap();
        assert!(
            seen.insert(p[9..].to_vec()),
            "a ciphertext came twice (a nonce was reused)"
        );
    }
}

/// The handshake and the first data packets with fixed ephemeral keys and timestamp, byte for byte: the
/// packet layout, the counter as the nonce and the associated data are all in these bytes
#[test]
fn a_fixed_handshake_gives_fixed_packets() {
    let (a, b) = (party(1, "a"), party(2, "b"));
    let policy = Policy::knowing(&[&a, &b]);
    let at = InitTimestamp::from_unix(1_800_000_000, 123);
    let (init, first) = Initiator::start_with_ephemeral(
        &a.cred,
        &policy,
        &cert(&b),
        at,
        Keypair::from_secret([41; 32]),
    )
    .unwrap();
    let pending = Responder::new()
        .respond_with_ephemeral(&b.cred, &policy, &first, Keypair::from_secret([42; 32]))
        .unwrap();
    let (mut ca, confirm) = init.finish(pending.response(), &policy).unwrap();
    let data = ca.seal(b"datagram").unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let digest = |b: &[u8]| hex(&alice_crypto::sha256::digest(b));
    assert_eq!(DATAGRAM_AD, b"alice-channel/datagram/v1");
    assert_eq!(confirm.len(), 1 + 8 + 16);
    assert_eq!(&confirm[..9], &[KIND_DATA, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(&data[..9], &[KIND_DATA, 1, 0, 0, 0, 0, 0, 0, 0]);
    let got = [
        digest(&first),
        digest(pending.response()),
        hex(&confirm),
        hex(&data),
    ];
    assert_eq!(got, GOLDEN);
    pending.confirm(&confirm).channel().unwrap();
}

/// Recorded from this implementation (2026-10-25): the SHA-256 of the init and the response, and the
/// confirmation and first data packet in full. A change to the layout, the nonce or the associated data
/// changes them
const GOLDEN: [&str; 4] = [
    "ab84378931721e64eb6d2c6b15771f5bc316637a590eb14a9676b43687a03f04",
    "2d4235b476dbe04df52e5b9f3941bc6010f57ba28dad7f7475d93555bf750b3e",
    "030000000000000000f17a11c0798cee7d0f7c0cb64bd4c539",
    "030100000000000000a1d945b97d8e5e23b43a82c5742a4a64f865b2345ae446d2",
];
