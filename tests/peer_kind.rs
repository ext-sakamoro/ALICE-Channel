//! Oracle for [`PeerKind`]: the policy, not the certificate a peer presents, says whether a device of a
//! person or a named service is expected, and the other kind is refused at the dial and in the handshake.
//!
//! The two policies below trust one master key for every subject, the shape in which the kinds could be
//! confused (one operator key signing both a person's devices and a service): a person policy is given a
//! service certificate and a service policy a person's, under that same key. Each refusal is checked at
//! the dial ([`check_cert`] / [`Initiate::dial`]) and at the responder of a mutually authenticated datagram
//! handshake (the certificate a peer proves), and each loop counts what it compared.

use alice_channel::datagram::{InitTimestamp, Initiator, Responder};
use alice_channel::noise::Keypair;
use alice_channel::{
    check_cert, ChannelError, Credential, Initiate, PeerKind, PeerPolicy, PinnedPeer,
};
use alice_identity::artifact::{ArtifactError, Revocation};
use alice_identity::device_cert::{DeviceCert, DeviceCertError};
use alice_identity::did::Did;
use alice_identity::service_cert::{issue_service_cert, service_subject};
use alice_sign::{KeyPair, PublicKey};

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = ISSUED_AT + 30 * 86_400;
const NOW: u64 = ISSUED_AT + 100;
const SERVICE: &str = "relay";

/// The one master key of the fixture (a fixed seed: test only, never a deployed key)
fn master() -> KeyPair {
    KeyPair::from_seed([0x5a; 32])
}

/// Signing and Noise static keys of the fixture (test only)
fn device() -> KeyPair {
    KeyPair::from_seed([0x5b; 32])
}

fn noise_static() -> Keypair {
    Keypair::from_secret([0x5c; 32])
}

/// A person policy: every subject under `master()`, a device of a person (the default kind)
struct AnyPerson;

impl PeerPolicy for AnyPerson {
    fn master_of(&self, _subject: &Did) -> Option<PublicKey> {
        Some(master().public())
    }
    fn revocation(&self) -> Revocation<'_> {
        Revocation::NoListAvailable
    }
    fn now(&self) -> u64 {
        NOW
    }
}

/// A service policy: every subject under `master()`, the service `SERVICE` expected
struct AnyService;

impl PeerPolicy for AnyService {
    fn master_of(&self, _subject: &Did) -> Option<PublicKey> {
        Some(master().public())
    }
    fn revocation(&self) -> Revocation<'_> {
        Revocation::NoListAvailable
    }
    fn now(&self) -> u64 {
        NOW
    }
    fn expected_peer(&self) -> PeerKind<'_> {
        PeerKind::Service(SERVICE)
    }
}

fn service_cert() -> DeviceCert {
    issue_service_cert(
        &master(),
        SERVICE,
        device().public().0,
        noise_static().public(),
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap()
}

fn person_cert() -> DeviceCert {
    DeviceCert::issue(
        &master(),
        &Did::key_ed25519(&master().public()),
        device().public().0,
        noise_static().public(),
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap()
}

/// The refusal at the dial; `Initiate::dial` and `check_cert` report the same
fn at_dial(cert: &DeviceCert, policy: &impl PeerPolicy) -> Result<(), String> {
    let check = check_cert(cert, policy).map_err(|e| format!("{e:?}"));
    let dial = Initiate::dial(cert, policy)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"));
    assert_eq!(check, dial);
    check
}

/// The responder's verdict on a peer that proves `proved` in a datagram handshake, the responder
/// trusting peers by `policy`; the responder itself is a person under another master, dialled as such
fn at_responder(proved: DeviceCert, policy: &impl PeerPolicy) -> Result<(), String> {
    let server_master = KeyPair::from_seed([0x7a; 32]);
    let server_subject = Did::parse("did:alice:server").unwrap();
    let server_device = KeyPair::from_seed([0x7b; 32]);
    let server_static = Keypair::from_secret([0x7c; 32]);
    let server_cert = DeviceCert::issue(
        &server_master,
        &server_subject,
        server_device.public().0,
        server_static.public(),
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap();
    let server = Credential::new(server_device, server_cert.clone(), server_static).unwrap();
    let dial_policy = PinnedPeer::new(
        server_subject,
        server_master.public(),
        NOW,
        Revocation::NoListAvailable,
    );
    let client = Credential::new(device(), proved, noise_static()).unwrap();
    let (_init, packet) = Initiator::start_at(
        &client,
        &dial_policy,
        &server_cert,
        InitTimestamp::from_unix(NOW, 0),
    )
    .unwrap();
    Responder::new()
        .respond(&server, policy, &packet)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

fn reserved() -> String {
    format!(
        "{:?}",
        ChannelError::Rejected(ArtifactError::Cert(DeviceCertError::ReservedSubject))
    )
}

fn unknown() -> String {
    format!("{:?}", ChannelError::UnknownPeer)
}

#[test]
fn a_person_policy_refuses_a_service_certificate_at_dial() {
    assert_eq!(at_dial(&service_cert(), &AnyPerson), Err(reserved()));
    // the control: a person's certificate under the same key passes
    assert_eq!(at_dial(&person_cert(), &AnyPerson), Ok(()));
}

#[test]
fn a_person_policy_refuses_a_service_certificate_in_the_handshake() {
    assert_eq!(at_responder(service_cert(), &AnyPerson), Err(reserved()));
    assert_eq!(at_responder(person_cert(), &AnyPerson), Ok(()));
}

#[test]
fn a_service_policy_refuses_a_person_certificate_at_dial() {
    assert_eq!(at_dial(&person_cert(), &AnyService), Err(unknown()));
    assert_eq!(at_dial(&service_cert(), &AnyService), Ok(()));
}

#[test]
fn a_service_policy_refuses_a_person_certificate_in_the_handshake() {
    assert_eq!(at_responder(person_cert(), &AnyService), Err(unknown()));
    assert_eq!(at_responder(service_cert(), &AnyService), Ok(()));
}

#[test]
fn a_service_policy_refuses_another_service() {
    let other = issue_service_cert(
        &master(),
        "push",
        device().public().0,
        noise_static().public(),
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap();
    assert_eq!(at_dial(&other, &AnyService), Err(unknown()));
    assert_eq!(at_responder(other, &AnyService), Err(unknown()));
}

#[test]
fn every_kind_and_certificate_pair_is_decided_by_the_policy() {
    // (policy kind, certificate kind) -> accepted only when they agree, on both paths
    let mut compared = 0;
    for (cert, is_service) in [(person_cert(), false), (service_cert(), true)] {
        let as_person = at_dial(&cert, &AnyPerson).is_ok();
        let as_service = at_dial(&cert, &AnyService).is_ok();
        assert_eq!((as_person, as_service), (!is_service, is_service));
        let hs_person = at_responder(cert.clone(), &AnyPerson).is_ok();
        let hs_service = at_responder(cert, &AnyService).is_ok();
        assert_eq!((hs_person, hs_service), (!is_service, is_service));
        compared += 1;
    }
    assert_eq!(compared, 2);
}

#[test]
fn pinned_peer_expects_the_kind_of_its_subject() {
    let m = master().public();
    let service = PinnedPeer::service(SERVICE, m, NOW, Revocation::NoListAvailable).unwrap();
    assert_eq!(service.expected_peer(), PeerKind::Service(SERVICE));
    let mut compared = 0;
    for subject in [
        Did::key_ed25519(&m),
        Did::parse("did:alice:carol").unwrap(),
        // near the reserved method is not a service
        Did::new("alice-services", SERVICE),
    ] {
        let p = PinnedPeer::new(subject, m, NOW, Revocation::NoListAvailable);
        assert_eq!(p.expected_peer(), PeerKind::Person, "{}", p.subject());
        compared += 1;
    }
    assert_eq!(compared, 3);
    let through_new = PinnedPeer::new(
        service_subject(SERVICE).unwrap(),
        m,
        NOW,
        Revocation::NoListAvailable,
    );
    assert_eq!(through_new.expected_peer(), PeerKind::Service(SERVICE));
}

#[test]
fn the_default_kind_is_a_person() {
    assert_eq!(AnyPerson.expected_peer(), PeerKind::Person);
}
