//! Oracle for [`PinnedPeer`] (a policy that trusts one subject under one master key) and for the anonymous
//! handshake over a message transport ([`connect_messages`] / [`accept_messages`]).
//!
//! A pinned service applies every rule `verify_service_cert` applies, so the dial path never accepts a
//! certificate the service certificate rules refuse: a 31-day service certificate is refused for its
//! lifetime (and `DeviceCert::verify`, the rules of a person's device, refuses every service certificate). Each refusal is checked to happen before any byte is sent
//! (the recording transport counts the calls), and each loop over cases counts what it compared, so an empty
//! loop fails instead of passing.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use alice_channel::datagram::{InitTimestamp, Initiator, Responder};
use alice_channel::noise::{Keypair, NoiseError, Transport};
use alice_channel::{
    accept_messages, check_cert, connect_messages, AnonymousChannel, AwaitConfirmation,
    ChannelError, Credential, Initiate, MessageIo, PeerPolicy, PinnedPeer, Respond,
    FIRST_MESSAGE_LEN, KEY_CONFIRMATION_LEN, RESPONSE_LEN,
};
use alice_identity::artifact::{ArtifactError, Revocation};
use alice_identity::cert_revocation::{CertRevocations, RevocationList};
use alice_identity::device_cert::{
    DeviceCert, DeviceCertError, DeviceId, DEVICE_CERT_CONTEXT, DEVICE_CERT_VERSION,
};
use alice_identity::did::Did;
use alice_identity::service_cert::{
    issue_service_cert, service_subject, ServiceCertError, SERVICE_CERT_MAX_LIFETIME_SECS,
};
use alice_sign::KeyPair;

const ISSUED_AT: u64 = 1_800_000_000;
const NOW: u64 = ISSUED_AT + 100;
const SERVICE: &str = "relay";

/// The operator's master key of the fixture (a fixed seed: test only, never a deployed key)
fn fixture_master() -> KeyPair {
    KeyPair::from_seed([0x5a; 32])
}

/// The service's signing key of the fixture (test only)
fn service_device() -> KeyPair {
    KeyPair::from_seed([0x5b; 32])
}

/// The service's Noise static key of the fixture (test only)
fn service_static() -> Keypair {
    Keypair::from_secret([0x5c; 32])
}

/// The fixture service certificate, valid for `lifetime` seconds from `ISSUED_AT`
///
/// Up to the bound it is issued by `issue_service_cert`. A longer one, which no issuing function makes
/// (`issue_service_cert` refuses the lifetime and `DeviceCert::issue` the reserved subject), is the
/// documented version 3 layout signed by hand, as an operator signing by hand could make it
fn service_cert_for(master: &KeyPair, service: &str, lifetime: u64) -> DeviceCert {
    if lifetime <= SERVICE_CERT_MAX_LIFETIME_SECS {
        return issue_service_cert(
            master,
            service,
            service_device().public().0,
            service_static().public(),
            ISSUED_AT,
            ISSUED_AT + lifetime,
        )
        .unwrap();
    }
    let subject = service_subject(service).unwrap();
    let text = subject.to_string();
    let key = service_device().public().0;
    let mut body = vec![DEVICE_CERT_VERSION];
    body.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
    body.extend_from_slice(text.as_bytes());
    body.extend_from_slice(&key);
    body.extend_from_slice(&service_static().public());
    body.extend_from_slice(&ISSUED_AT.to_be_bytes());
    body.extend_from_slice(&(ISSUED_AT + lifetime).to_be_bytes());
    body.extend_from_slice(DeviceId::derive(&subject, &key).unwrap().as_bytes());
    body.extend_from_slice(&master.public().0);
    let mut signed = DEVICE_CERT_CONTEXT.to_vec();
    signed.extend_from_slice(&body);
    body.extend_from_slice(&master.sign(&signed).0);
    DeviceCert::from_bytes(&body).unwrap()
}

/// The fixture service certificate at the longest lifetime a service certificate may have
fn service_cert() -> DeviceCert {
    let cert = issue_service_cert(
        &fixture_master(),
        SERVICE,
        service_device().public().0,
        service_static().public(),
        ISSUED_AT,
        ISSUED_AT + SERVICE_CERT_MAX_LIFETIME_SECS,
    )
    .unwrap();
    assert_eq!(
        cert,
        service_cert_for(&fixture_master(), SERVICE, SERVICE_CERT_MAX_LIFETIME_SECS)
    );
    cert
}

fn pinned(now: u64) -> PinnedPeer<'static> {
    PinnedPeer::service(
        SERVICE,
        fixture_master().public(),
        now,
        Revocation::NoListAvailable,
    )
    .unwrap()
}

/// A message transport that records every call and answers from a queue
#[derive(Default)]
struct Scripted {
    sent: Vec<Vec<u8>>,
    replies: VecDeque<Vec<u8>>,
    recvs: Vec<usize>,
}

impl MessageIo for Scripted {
    fn send(&mut self, message: &[u8]) -> Result<(), ChannelError> {
        self.sent.push(message.to_vec());
        Ok(())
    }
    fn recv(&mut self, max: usize) -> Result<Vec<u8>, ChannelError> {
        self.recvs.push(max);
        self.replies.pop_front().ok_or(ChannelError::Closed)
    }
}

/// A message transport whose other end is the sans-I/O responder [`Respond`] / [`AwaitConfirmation`]: it
/// answers the first message and opens the key confirmation, in the same thread
struct WithResponder {
    respond: Option<Respond>,
    waiting: Option<AwaitConfirmation>,
    reply: Option<Vec<u8>>,
    transport: Option<Transport>,
    sent: Vec<Vec<u8>>,
}

impl WithResponder {
    fn new(static_key: Keypair) -> Self {
        Self {
            respond: Some(Respond::new(static_key)),
            waiting: None,
            reply: None,
            transport: None,
            sent: Vec::new(),
        }
    }
}

impl MessageIo for WithResponder {
    fn send(&mut self, message: &[u8]) -> Result<(), ChannelError> {
        self.sent.push(message.to_vec());
        if let Some(respond) = self.respond.take() {
            let (waiting, response) = respond.respond(message)?;
            self.waiting = Some(waiting);
            self.reply = Some(response);
        } else if let Some(waiting) = self.waiting.take() {
            self.transport = Some(waiting.confirm(message)?);
        } else {
            return Err(ChannelError::Poisoned);
        }
        Ok(())
    }
    fn recv(&mut self, _max: usize) -> Result<Vec<u8>, ChannelError> {
        self.reply.take().ok_or(ChannelError::Closed)
    }
}

/// One end of an in-memory message pipe
struct Pipe {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

fn pipe_pair() -> (Pipe, Pipe) {
    let (a_tx, b_rx) = mpsc::channel();
    let (b_tx, a_rx) = mpsc::channel();
    (Pipe { tx: a_tx, rx: a_rx }, Pipe { tx: b_tx, rx: b_rx })
}

impl MessageIo for Pipe {
    fn send(&mut self, message: &[u8]) -> Result<(), ChannelError> {
        self.tx
            .send(message.to_vec())
            .map_err(|_| ChannelError::Closed)
    }
    fn recv(&mut self, _max: usize) -> Result<Vec<u8>, ChannelError> {
        self.rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| ChannelError::Timeout)
    }
}

/// Exchange `rounds` messages each way between two transports and count the opened ones
fn exchange(a: &mut Transport, b: &mut Transport, rounds: usize) -> usize {
    let mut opened = 0;
    for i in 0..rounds {
        let m = format!("a to b {i}");
        assert_eq!(
            b.recv(&a.send(m.as_bytes()).unwrap()).unwrap(),
            m.as_bytes()
        );
        let m = format!("b to a {i}");
        assert_eq!(
            a.recv(&b.send(m.as_bytes()).unwrap()).unwrap(),
            m.as_bytes()
        );
        opened += 2;
    }
    assert_eq!(a.handshake_hash(), b.handshake_hash());
    opened
}

#[test]
fn a_pinned_service_accepts_the_fixture_signed_service_cert() {
    let cert = service_cert();
    let policy = pinned(NOW);
    check_cert(&cert, &policy).unwrap();
    let (_, first) = Initiate::dial(&cert, &policy).unwrap();
    assert_eq!(first.len(), FIRST_MESSAGE_LEN);

    let mut io = WithResponder::new(service_static());
    let mut client = connect_messages(&mut io, &cert, &policy).unwrap();
    let mut server = io
        .transport
        .take()
        .expect("the responder opened the key confirmation");
    assert_eq!(exchange(&mut client, &mut server, 3), 6);
}

#[test]
fn pinned_peer_trusts_only_its_subject() {
    let policy = pinned(NOW);
    let master = fixture_master().public();
    assert_eq!(policy.subject(), &service_subject(SERVICE).unwrap());
    assert_eq!(
        policy.master_of(&service_subject(SERVICE).unwrap()),
        Some(master)
    );
    let others = [
        service_subject("relay2").unwrap(),
        service_subject("rela").unwrap(),
        Did::new("alice", SERVICE),
        Did::new("alice-service", "Relay"),
        Did::parse("did:alice:bob").unwrap(),
        Did::key_ed25519(&master),
    ];
    let mut compared = 0;
    for other in &others {
        assert_eq!(policy.master_of(other), None, "{other}");
        compared += 1;
    }
    assert_eq!(compared, others.len());
    assert!(compared > 0);
    assert_eq!(policy.now(), NOW);
    assert!(matches!(policy.revocation(), Revocation::NoListAvailable));
}

#[test]
fn a_service_name_off_the_rule_makes_no_policy() {
    let mut compared = 0;
    for bad in ["", "Relay", "-relay", "relay-", "re lay", "re:lay"] {
        assert_eq!(
            PinnedPeer::service(
                bad,
                fixture_master().public(),
                NOW,
                Revocation::NoListAvailable
            )
            .unwrap_err(),
            ServiceCertError::BadServiceName,
            "{bad:?}"
        );
        compared += 1;
    }
    assert_eq!(compared, 6);
}

/// What `connect_messages` (and `Initiate::dial` and `check_cert`) report for `cert` under `policy`, after
/// checking that nothing was sent or received
fn refused_at_dial(cert: &DeviceCert, policy: &impl PeerPolicy) -> ChannelError {
    let mut io = Scripted::default();
    let err = connect_messages(&mut io, cert, policy)
        .err()
        .expect("refused");
    assert!(io.sent.is_empty(), "sent {} messages", io.sent.len());
    assert!(io.recvs.is_empty(), "received {} times", io.recvs.len());
    let dial = Initiate::dial(cert, policy).err().expect("dial refuses");
    assert_eq!(format!("{dial:?}"), format!("{err:?}"));
    let check = check_cert(cert, policy).unwrap_err();
    assert_eq!(format!("{check:?}"), format!("{err:?}"));
    err
}

#[test]
fn each_refused_certificate_is_refused_at_dial_with_nothing_sent() {
    let other_master = KeyPair::from_seed([0x6a; 32]);
    let non_service = DeviceCert::issue(
        &fixture_master(),
        &Did::new("alice", SERVICE),
        service_device().public().0,
        service_static().public(),
        ISSUED_AT,
        ISSUED_AT + 86_400,
    )
    .unwrap();
    let max = SERVICE_CERT_MAX_LIFETIME_SECS;
    let cases: Vec<(&str, DeviceCert, PinnedPeer<'static>, String)> = vec![
        (
            "another master",
            service_cert_for(&other_master, SERVICE, max),
            pinned(NOW),
            format!(
                "{:?}",
                ChannelError::Rejected(ArtifactError::Cert(DeviceCertError::IssuerMismatch))
            ),
        ),
        (
            "expired",
            service_cert(),
            pinned(ISSUED_AT + max),
            format!(
                "{:?}",
                ChannelError::Rejected(ArtifactError::Cert(DeviceCertError::Expired {
                    now: ISSUED_AT + max,
                    not_after: ISSUED_AT + max,
                }))
            ),
        ),
        (
            "another service",
            service_cert_for(&fixture_master(), "relay2", max),
            pinned(NOW),
            format!("{:?}", ChannelError::UnknownPeer),
        ),
        (
            "not a service",
            non_service,
            pinned(NOW),
            format!("{:?}", ChannelError::UnknownPeer),
        ),
        (
            "31 days through service()",
            service_cert_for(&fixture_master(), SERVICE, 31 * 86_400),
            pinned(NOW),
            format!(
                "{:?}",
                ChannelError::Rejected(ArtifactError::Cert(DeviceCertError::InvalidValidity))
            ),
        ),
        (
            "one second over through new()",
            service_cert_for(&fixture_master(), SERVICE, max + 1),
            PinnedPeer::new(
                service_subject(SERVICE).unwrap(),
                fixture_master().public(),
                NOW,
                Revocation::NoListAvailable,
            ),
            format!(
                "{:?}",
                ChannelError::Rejected(ArtifactError::Cert(DeviceCertError::InvalidValidity))
            ),
        ),
    ];
    let mut compared = 0;
    for (what, cert, policy, want) in &cases {
        assert_eq!(
            &format!("{:?}", refused_at_dial(cert, policy)),
            want,
            "{what}"
        );
        compared += 1;
    }
    assert_eq!(compared, 6);
}

#[test]
fn a_31_day_service_cert_is_refused_at_dial_and_by_the_device_cert_rules() {
    let cert = service_cert_for(&fixture_master(), SERVICE, 31 * 86_400);
    // the device certificate rules (a person's device) refuse every service certificate
    assert_eq!(
        cert.verify(&fixture_master().public(), NOW),
        Err(DeviceCertError::ReservedSubject)
    );
    // the service rules refuse its lifetime
    assert!(matches!(
        refused_at_dial(&cert, &pinned(NOW)),
        ChannelError::Rejected(ArtifactError::Cert(DeviceCertError::InvalidValidity))
    ));
}

#[test]
fn a_pinned_peer_that_is_not_a_service_keeps_the_device_cert_rules() {
    let master = KeyPair::from_seed([0x7a; 32]);
    let subject = Did::parse("did:alice:carol").unwrap();
    // a 400-day device certificate: no lifetime bound applies outside service subjects
    let cert = DeviceCert::issue(
        &master,
        &subject,
        service_device().public().0,
        service_static().public(),
        ISSUED_AT,
        ISSUED_AT + 400 * 86_400,
    )
    .unwrap();
    let policy = PinnedPeer::new(subject, master.public(), NOW, Revocation::NoListAvailable);
    check_cert(&cert, &policy).unwrap();
    let mut io = WithResponder::new(service_static());
    connect_messages(&mut io, &cert, &policy).unwrap();
    assert_eq!(io.sent.len(), 2);
}

#[test]
fn a_revoked_service_cert_is_refused_at_dial() {
    let cert = service_cert();
    let mut list = CertRevocations::new();
    list.accept(
        RevocationList::issue(&fixture_master(), 1, ISSUED_AT, &[cert.device_id()]),
        &fixture_master().public(),
    )
    .unwrap();
    let policy = PinnedPeer::service(
        SERVICE,
        fixture_master().public(),
        NOW,
        Revocation::Checked(&list),
    )
    .unwrap();
    assert!(matches!(
        refused_at_dial(&cert, &policy),
        ChannelError::Rejected(ArtifactError::Revoked)
    ));
    // the control: the same list without that id accepts
    let mut empty = CertRevocations::new();
    empty
        .accept(
            RevocationList::issue(&fixture_master(), 1, ISSUED_AT, &[]),
            &fixture_master().public(),
        )
        .unwrap();
    let policy = PinnedPeer::service(
        SERVICE,
        fixture_master().public(),
        NOW,
        Revocation::Checked(&empty),
    )
    .unwrap();
    check_cert(&cert, &policy).unwrap();
}

#[test]
fn the_lifetime_rule_also_holds_for_the_certificate_a_responder_proves() {
    // a mutually authenticated datagram handshake: the initiator dials the 30-day certificate, and the
    // responder proves the same subject, signing key and static key with a 31-day one
    let client_master = KeyPair::from_seed([0x8a; 32]);
    let client_did = Did::parse("did:alice:client").unwrap();
    let client_device = KeyPair::from_seed([0x8b; 32]);
    let client_static = Keypair::from_secret([0x8c; 32]);
    let client_cert = DeviceCert::issue(
        &client_master,
        &client_did,
        client_device.public().0,
        client_static.public(),
        ISSUED_AT,
        ISSUED_AT + 86_400,
    )
    .unwrap();
    let client = Credential::new(client_device, client_cert, client_static).unwrap();
    let server_policy = PinnedPeer::new(
        client_did,
        client_master.public(),
        NOW,
        Revocation::NoListAvailable,
    );
    let dialled = service_cert();
    let run = |proved: DeviceCert| {
        let server = Credential::new(service_device(), proved, service_static()).unwrap();
        let (init, packet) = Initiator::start_at(
            &client,
            &pinned(NOW),
            &dialled,
            InitTimestamp::from_unix(NOW, 0),
        )
        .unwrap();
        let pending = Responder::new()
            .respond(&server, &server_policy, &packet)
            .unwrap();
        init.finish(pending.response(), &pinned(NOW)).map(|_| ())
    };
    run(service_cert()).unwrap();
    let refused = run(service_cert_for(&fixture_master(), SERVICE, 31 * 86_400)).unwrap_err();
    assert!(
        matches!(
            refused,
            ChannelError::Rejected(ArtifactError::Cert(DeviceCertError::InvalidValidity))
        ),
        "{refused:?}"
    );
}

#[test]
fn connect_messages_and_respond_exchange_messages_both_ways() {
    let mut io = WithResponder::new(service_static());
    let mut client = connect_messages(&mut io, &service_cert(), &pinned(NOW)).unwrap();
    // the first message and the key confirmation, at their lengths
    let lens: Vec<usize> = io.sent.iter().map(Vec::len).collect();
    assert_eq!(lens, [FIRST_MESSAGE_LEN, KEY_CONFIRMATION_LEN]);
    let mut server = io
        .transport
        .take()
        .expect("the key confirmation was sent and opened");
    assert_eq!(exchange(&mut client, &mut server, 4), 8);
}

#[test]
fn connect_messages_asks_for_the_response_length_only() {
    let mut io = Scripted::default();
    let _ = connect_messages(&mut io, &service_cert(), &pinned(NOW));
    assert_eq!(io.recvs, [RESPONSE_LEN]);
}

#[test]
fn connect_messages_and_accept_messages_exchange_messages_both_ways() {
    let (mut a, mut b) = pipe_pair();
    let server = thread::spawn(move || accept_messages(&mut b, &service_static()));
    let mut client = connect_messages(&mut a, &service_cert(), &pinned(NOW)).unwrap();
    let mut server = server.join().unwrap().unwrap();
    assert_eq!(exchange(&mut client, &mut server, 4), 8);
}

#[test]
fn a_responder_with_another_static_key_is_refused_at_finish() {
    // a response made by a real responder with another static key, to another first message
    let other = Keypair::from_secret([0x9c; 32]);
    let (_, first) = Initiate::start(other.public()).unwrap();
    let (_, response) = Respond::new(other).respond(&first).unwrap();
    assert_eq!(response.len(), RESPONSE_LEN);
    let mut io = Scripted {
        replies: VecDeque::from([response]),
        ..Scripted::default()
    };
    let err = connect_messages(&mut io, &service_cert(), &pinned(NOW))
        .err()
        .expect("refused");
    assert!(
        matches!(err, ChannelError::Noise(NoiseError::Decrypt)),
        "{err:?}"
    );
    // the first message went out, no key confirmation did
    assert_eq!(io.sent.len(), 1);
}

#[test]
fn a_response_of_another_length_is_refused() {
    let mut compared = 0;
    for len in [0, 1, 16, 31, 32, 47, 49, 64, 200] {
        let mut io = Scripted {
            replies: VecDeque::from([vec![0x11; len]]),
            ..Scripted::default()
        };
        let err = connect_messages(&mut io, &service_cert(), &pinned(NOW))
            .err()
            .expect("refused");
        assert!(
            matches!(err, ChannelError::Noise(NoiseError::Decrypt)),
            "{len}: {err:?}"
        );
        assert_eq!(io.sent.len(), 1, "{len}: no key confirmation is sent");
        compared += 1;
    }
    assert_eq!(compared, 9);
}

#[test]
fn accept_messages_refuses_messages_of_another_length_and_sends_nothing() {
    let mut compared = 0;
    for len in [0, 16, 32, 47, 49] {
        let mut io = Scripted {
            replies: VecDeque::from([vec![0x22; len]]),
            ..Scripted::default()
        };
        let err = accept_messages(&mut io, &service_static())
            .err()
            .expect("refused");
        assert!(
            matches!(err, ChannelError::Noise(NoiseError::Decrypt)),
            "{len}: {err:?}"
        );
        assert!(io.sent.is_empty(), "{len}");
        assert_eq!(io.recvs, [FIRST_MESSAGE_LEN]);
        compared += 1;
    }
    // a right first message, then a confirmation of another length
    for len in [0, 15, 17, 48] {
        let (_, first) = Initiate::start(service_static().public()).unwrap();
        let mut io = Scripted {
            replies: VecDeque::from([first, vec![0x33; len]]),
            ..Scripted::default()
        };
        let err = accept_messages(&mut io, &service_static())
            .err()
            .expect("refused");
        assert!(
            matches!(err, ChannelError::Noise(NoiseError::Decrypt)),
            "{len}: {err:?}"
        );
        assert_eq!(io.sent.len(), 1);
        assert_eq!(io.sent[0].len(), RESPONSE_LEN);
        assert_eq!(io.recvs, [FIRST_MESSAGE_LEN, KEY_CONFIRMATION_LEN]);
        compared += 1;
    }
    assert_eq!(compared, 9);
}

/// A message transport over a stream with the `u16` frames of the stream channels
struct Framed(TcpStream);

impl MessageIo for Framed {
    fn send(&mut self, message: &[u8]) -> Result<(), ChannelError> {
        let len = u16::try_from(message.len()).map_err(|_| ChannelError::TooLong)?;
        self.0
            .write_all(&len.to_be_bytes())
            .and_then(|()| self.0.write_all(message))
            .map_err(|e| ChannelError::Io(e.kind()))
    }
    fn recv(&mut self, max: usize) -> Result<Vec<u8>, ChannelError> {
        let mut head = [0u8; 2];
        self.0
            .read_exact(&mut head)
            .map_err(|e| ChannelError::Io(e.kind()))?;
        let n = usize::from(u16::from_be_bytes(head));
        if n > max {
            return Err(ChannelError::TooLong);
        }
        let mut body = vec![0u8; n];
        self.0
            .read_exact(&mut body)
            .map_err(|e| ChannelError::Io(e.kind()))?;
        Ok(body)
    }
}

#[test]
fn connect_messages_speaks_to_the_stream_channel() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let cred = Credential::new(service_device(), service_cert(), service_static()).unwrap();
        let mut ch = AnonymousChannel::accept(stream, &cred).unwrap();
        let got = ch.recv().unwrap();
        ch.send(b"from the stream channel").unwrap();
        got
    });
    let stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut io = Framed(stream);
    let mut client = connect_messages(&mut io, &service_cert(), &pinned(NOW)).unwrap();
    io.send(&client.send(b"from the message transport").unwrap())
        .unwrap();
    let reply = io.recv(usize::from(u16::MAX)).unwrap();
    assert_eq!(client.recv(&reply).unwrap(), b"from the stream channel");
    assert_eq!(server.join().unwrap(), b"from the message transport");
}
