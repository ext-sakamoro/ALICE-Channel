//! Oracle for the sans-I/O anonymous handshake ([`Initiate`], [`Respond`], [`AwaitConfirmation`]): bytes in,
//! bytes out, no stream and no clock. Every message has exactly one length (the first message and the
//! response are an ephemeral key and the tag of an empty payload, 32 + 16 bytes; the key confirmation is the
//! tag of an empty transport message, 16 bytes); any other length, any changed byte and any payload is a
//! typed error, and the step's state is consumed by it. The byte-for-byte equality with the stream channel
//! is pinned in `src/anonymous/vectors.rs` (it needs a test-only hook to fix the stream channel's ephemeral
//! keys).

use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use alice_channel::noise::{Keypair, NoiseError};
use alice_channel::{
    AnonymousChannel, AnonymousError, ChannelError, Credential, Initiate, Respond,
    FIRST_MESSAGE_LEN, KEY_CONFIRMATION_LEN, RESPONSE_LEN,
};
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_sign::KeyPair;

fn responder_static() -> Keypair {
    Keypair::from_secret([0x41; 32])
}

/// A whole handshake; returns both transports
fn handshake() -> (
    alice_channel::noise::Transport,
    alice_channel::noise::Transport,
) {
    let s = responder_static();
    let (init, first) = Initiate::start(s.public()).unwrap();
    let (pending, response) = Respond::new(s).respond(&first).unwrap();
    let (ti, confirmation) = init.finish(&response).unwrap();
    let tr = pending.confirm(&confirmation).unwrap();
    (ti, tr)
}

#[test]
fn the_lengths_are_the_documented_ones() {
    assert_eq!(FIRST_MESSAGE_LEN, 48);
    assert_eq!(RESPONSE_LEN, 48);
    assert_eq!(KEY_CONFIRMATION_LEN, 16);
    let s = responder_static();
    let (init, first) = Initiate::start(s.public()).unwrap();
    assert_eq!(first.len(), 48);
    let (_, response) = Respond::new(s).respond(&first).unwrap();
    assert_eq!(response.len(), 48);
    let (_, confirmation) = init.finish(&response).unwrap();
    assert_eq!(confirmation.len(), 16);
}

#[test]
fn a_handshake_carries_messages_both_ways() {
    let (mut ti, mut tr) = handshake();
    assert_eq!(ti.handshake_hash(), tr.handshake_hash());
    for i in 0..5u8 {
        let m = ti.send(&[i; 10]).unwrap();
        assert_eq!(tr.recv(&m).unwrap(), [i; 10]);
        let m = tr.send(&[i ^ 0xff; 3]).unwrap();
        assert_eq!(ti.recv(&m).unwrap(), [i ^ 0xff; 3]);
    }
}

#[test]
fn a_first_message_of_any_other_length_is_refused() {
    let s = responder_static();
    let (_, first) = Initiate::start(s.public()).unwrap();
    let mut refused = 0;
    for n in 0..=200 {
        if n == FIRST_MESSAGE_LEN {
            continue;
        }
        let mut m = first.clone();
        m.resize(n, 0);
        let got = Respond::new(s.clone()).respond(&m).map(|_| ());
        assert_eq!(
            got,
            Err(AnonymousError::Length {
                expected: 48,
                got: n
            }),
            "{n}"
        );
        refused += 1;
    }
    assert_eq!(refused, 200);
}

#[test]
fn a_changed_first_message_or_another_static_key_does_not_open() {
    let s = responder_static();
    let (_, first) = Initiate::start(s.public()).unwrap();
    for i in 0..first.len() {
        let mut m = first.clone();
        m[i] ^= 0x01;
        assert_eq!(
            Respond::new(s.clone()).respond(&m).map(|_| ()),
            Err(AnonymousError::Noise(NoiseError::Decrypt)),
            "byte {i}"
        );
    }
    // a responder holding another static key cannot open it
    assert_eq!(
        Respond::new(Keypair::from_secret([0x42; 32]))
            .respond(&first)
            .map(|_| ()),
        Err(AnonymousError::Noise(NoiseError::Decrypt))
    );
}

#[test]
fn a_response_of_any_other_length_or_changed_is_refused() {
    let s = responder_static();
    for n in (0..=200).filter(|&n| n != RESPONSE_LEN) {
        let (init, first) = Initiate::start(s.public()).unwrap();
        let (_, mut response) = Respond::new(s.clone()).respond(&first).unwrap();
        response.resize(n, 0);
        assert_eq!(
            init.finish(&response).map(|_| ()),
            Err(AnonymousError::Length {
                expected: 48,
                got: n
            }),
            "{n}"
        );
    }
    for i in 0..RESPONSE_LEN {
        let (init, first) = Initiate::start(s.public()).unwrap();
        let (_, mut response) = Respond::new(s.clone()).respond(&first).unwrap();
        response[i] ^= 0x80;
        assert!(
            matches!(
                init.finish(&response),
                Err(AnonymousError::Noise(
                    NoiseError::Decrypt | NoiseError::WeakKey
                ))
            ),
            "byte {i}"
        );
    }
}

#[test]
fn a_key_confirmation_of_any_other_length_or_changed_is_refused() {
    let s = responder_static();
    for n in (0..=100).filter(|&n| n != KEY_CONFIRMATION_LEN) {
        let (init, first) = Initiate::start(s.public()).unwrap();
        let (pending, response) = Respond::new(s.clone()).respond(&first).unwrap();
        let (_, mut confirmation) = init.finish(&response).unwrap();
        confirmation.resize(n, 0);
        assert_eq!(
            pending.confirm(&confirmation).map(|_| ()),
            Err(AnonymousError::Length {
                expected: 16,
                got: n
            }),
            "{n}"
        );
    }
    for i in 0..KEY_CONFIRMATION_LEN {
        let (init, first) = Initiate::start(s.public()).unwrap();
        let (pending, response) = Respond::new(s.clone()).respond(&first).unwrap();
        let (_, mut confirmation) = init.finish(&response).unwrap();
        confirmation[i] ^= 0x01;
        assert_eq!(
            pending.confirm(&confirmation).map(|_| ()),
            Err(AnonymousError::Noise(NoiseError::Decrypt)),
            "byte {i}"
        );
    }
}

#[test]
fn a_first_transport_message_is_not_a_key_confirmation() {
    // the initiator's first data message on the new keys (17 bytes for one byte of payload) is refused by
    // length; a sealed one-byte message cut to 16 bytes does not open
    let s = responder_static();
    let (init, first) = Initiate::start(s.public()).unwrap();
    let (pending, response) = Respond::new(s).respond(&first).unwrap();
    let (mut ti, _confirmation) = init.finish(&response).unwrap();
    let data = ti.send(b"x").unwrap();
    assert_eq!(
        pending.confirm(&data).map(|_| ()),
        Err(AnonymousError::Length {
            expected: 16,
            got: 17
        })
    );
}

#[test]
fn errors_map_to_the_stream_channel_errors() {
    assert!(matches!(
        ChannelError::from(AnonymousError::Length {
            expected: 48,
            got: 1
        }),
        ChannelError::Noise(NoiseError::Decrypt)
    ));
    assert!(matches!(
        ChannelError::from(AnonymousError::Noise(NoiseError::WeakKey)),
        ChannelError::Noise(NoiseError::WeakKey)
    ));
}

#[test]
fn the_initiator_machine_talks_to_the_stream_channel() {
    // a host running Initiate over its own transport (here: a TCP stream with the frames written by hand)
    // against the blocking responder
    use std::io::{Read, Write};
    let master = KeyPair::from_seed([0x51; 32]);
    let device = KeyPair::from_seed([0x52; 32]);
    let did = Did::parse("did:alice:relay").unwrap();
    let noise = responder_static();
    let cert = DeviceCert::issue(
        &master,
        &did,
        device.public().0,
        noise.public(),
        1_800_000_000,
        1_800_086_400,
    )
    .unwrap();
    let cred = Credential::new(device, cert, noise).unwrap();
    let rs = cred.noise_static_public();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let s = listener.accept().unwrap().0;
        let mut ch = AnonymousChannel::accept_with_timeout(s, &cred, Duration::from_secs(10))?;
        let got = ch.recv()?;
        ch.send(&got)?;
        Ok::<_, ChannelError>(got)
    });
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    let frame = |s: &mut std::net::TcpStream, b: &[u8]| {
        s.write_all(&u16::try_from(b.len()).unwrap().to_be_bytes())
            .unwrap();
        s.write_all(b).unwrap();
    };
    let read = |s: &mut std::net::TcpStream| {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).unwrap();
        let mut b = vec![0u8; usize::from(u16::from_be_bytes(h))];
        s.read_exact(&mut b).unwrap();
        b
    };
    let (init, first) = Initiate::start(rs).unwrap();
    frame(&mut s, &first);
    let response = read(&mut s);
    let (mut t, confirmation) = init.finish(&response).unwrap();
    frame(&mut s, &confirmation);
    frame(&mut s, &t.send(b"through the machine").unwrap());
    let echoed = read(&mut s);
    assert_eq!(t.recv(&echoed).unwrap(), b"through the machine");
    assert_eq!(server.join().unwrap().unwrap(), b"through the machine");
}
