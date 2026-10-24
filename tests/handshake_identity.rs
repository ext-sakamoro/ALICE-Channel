//! Oracle for the identity binding of the handshake. Each side's Noise static key is named by its device
//! certificate (layout version 2) and bound to the handshake: the encrypted handshake payload is an artifact signature (`alice-identity`) by the device key
//! over SHA-256(handshake hash at that point || the sender's Noise static public key), for the context
//! `alice-channel/handshake/v1`. The receiver checks the certificate against the subject's master key, its
//! revocation list and the time, then the signature over its own transcript. The digest is recomputed here
//! from that rule, not taken from the code under test.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use alice_channel::noise::{HandshakeState, Keypair, NoiseError};
use alice_channel::{
    sign_handshake, ChannelError, Credential, PeerPolicy, SecureChannel, HANDSHAKE_CONTEXT,
    MAX_FRAME, PROLOGUE,
};
use alice_identity::artifact::{
    sha256_payload, sign_artifact, verify_artifact, ArtifactError, ArtifactSignature, Revocation,
};
use alice_identity::cert_revocation::{CertRevocations, RevocationList};
use alice_identity::device_cert::{DeviceCert, DeviceCertError};
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

fn party(seed: u8, name: &str, cert_id: [u8; 16]) -> Party {
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
        cert_id,
    )
    .unwrap();
    Party {
        master,
        did,
        cred: Credential::new(device, cert, noise_static).unwrap(),
    }
}

struct Policy {
    masters: HashMap<String, PublicKey>,
    revocations: Option<CertRevocations>,
    now: u64,
}

impl Policy {
    fn knowing(parties: &[&Party]) -> Self {
        Self {
            masters: parties
                .iter()
                .map(|p| (p.did.to_string(), p.master.public()))
                .collect(),
            revocations: None,
            now: NOW,
        }
    }
}

impl PeerPolicy for Policy {
    fn master_of(&self, subject: &Did) -> Option<PublicKey> {
        self.masters.get(&subject.to_string()).copied()
    }
    fn revocation(&self) -> Revocation<'_> {
        self.revocations
            .as_ref()
            .map_or(Revocation::NoListAvailable, Revocation::Checked)
    }
    fn now(&self) -> u64 {
        self.now
    }
}

/// Run `server` on an accepted connection in a thread and `client` on the connecting side
fn pair<A, B, RA, RB>(server: A, client: B) -> (RA, RB)
where
    A: FnOnce(TcpStream) -> RA + Send + 'static,
    B: FnOnce(TcpStream) -> RB,
    RA: Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = thread::spawn(move || server(listener.accept().unwrap().0));
    let rb = client(TcpStream::connect(addr).unwrap());
    (h.join().unwrap(), rb)
}

// the frame of the channel: u16 big-endian length, then that many bytes
fn write_frame(s: &mut TcpStream, b: &[u8]) {
    s.write_all(&u16::try_from(b.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(b).unwrap();
}

fn read_frame(s: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut b = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut b).unwrap();
    b
}

fn digest_for(h: [u8; 32], static_pub: [u8; 32]) -> alice_identity::artifact::PayloadDigest {
    let mut joined = h.to_vec();
    joined.extend_from_slice(&static_pub);
    sha256_payload(&joined)
}

#[test]
fn the_constants_are_the_documented_ones() {
    assert_eq!(HANDSHAKE_CONTEXT, b"alice-channel/handshake/v1");
    assert_eq!(MAX_FRAME, 65_535);
    assert_eq!(PROLOGUE, b"alice-channel v3");
}

#[test]
fn two_certified_devices_connect_and_exchange_messages() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_b = Policy::knowing(&[&a]);
    let policy_a = Policy::knowing(&[&b]);
    let b_cert = b.cred.cert().clone();
    let cred_b = b.cred;
    let (server, client) = pair(
        move |s| {
            let mut ch = SecureChannel::accept(s, &cred_b, &policy_b).unwrap();
            let got = ch.recv().unwrap();
            ch.send(b"pong").unwrap();
            (got, ch.peer_cert().subject().to_string())
        },
        |s| {
            let mut ch = SecureChannel::connect(s, &a.cred, &policy_a, &b_cert).unwrap();
            ch.send(b"ping").unwrap();
            (ch.recv().unwrap(), ch.peer_cert().subject().to_string())
        },
    );
    assert_eq!(server, (b"ping".to_vec(), "did:alice:alice".to_owned()));
    assert_eq!(client, (b"pong".to_vec(), "did:alice:bob".to_owned()));
}

/// Run a refused handshake: bob accepts under `policy_b`, alice dials bob's certificate under `policy_a`
fn refused(
    a: &Party,
    b: Party,
    policy_a: &Policy,
    policy_b: Policy,
) -> (Option<ChannelError>, Option<ChannelError>) {
    let b_cert = b.cred.cert().clone();
    let cred_b = b.cred;
    pair(
        move |s| SecureChannel::accept(s, &cred_b, &policy_b).err(),
        |s| SecureChannel::connect(s, &a.cred, policy_a, &b_cert).err(),
    )
}

#[test]
fn a_device_whose_master_is_unknown_is_refused_in_the_handshake() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_a = Policy::knowing(&[&b]);
    // bob knows nobody
    let (server, client) = refused(&a, b, &policy_a, Policy::knowing(&[]));
    assert!(
        matches!(server, Some(ChannelError::UnknownPeer)),
        "{server:?}"
    );
    // bob wrote nothing back, so connect sees the connection end, not a channel
    assert!(
        matches!(client, Some(ChannelError::Closed | ChannelError::Io(_))),
        "{client:?}"
    );
}

#[test]
fn a_revoked_device_is_refused_in_the_handshake() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let mut policy_b = Policy::knowing(&[&a]);
    let mut list = CertRevocations::new();
    list.accept(
        RevocationList::issue(&a.master, 1, ISSUED_AT, &[[1; 16]]),
        &a.master.public(),
    )
    .unwrap();
    policy_b.revocations = Some(list);
    let policy_a = Policy::knowing(&[&b]);
    let (server, _) = refused(&a, b, &policy_a, policy_b);
    assert!(
        matches!(server, Some(ChannelError::Rejected(ArtifactError::Revoked))),
        "{server:?}"
    );
}

/// Bytes a raw listener reads until the client closes, with the client's result
fn wire_bytes<B, RB>(client: B) -> (usize, RB)
where
    B: FnOnce(TcpStream) -> RB,
{
    pair(
        |mut s| {
            let mut all = Vec::new();
            let _ = s.read_to_end(&mut all);
            all.len()
        },
        client,
    )
}

#[test]
fn an_expired_certificate_is_refused_before_dialling() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_b = Policy::knowing(&[&a]);
    let mut policy_a = Policy::knowing(&[&b]);
    policy_a.now = NOT_AFTER; // the client judges bob's certificate at its expiry
    let b_cert = b.cred.cert().clone();
    let (server, client) = refused(&a, b, &policy_a, policy_b);
    assert!(
        matches!(
            client,
            Some(ChannelError::Rejected(ArtifactError::Cert(
                DeviceCertError::Expired { .. }
            )))
        ),
        "{client:?}"
    );
    assert!(matches!(server, Some(ChannelError::Closed)), "{server:?}");
    // nothing was written: the refusal comes before the first message
    let (written, err) =
        wire_bytes(|s| SecureChannel::connect(s, &a.cred, &policy_a, &b_cert).err());
    assert_eq!(written, 0);
    assert!(err.is_some());
}

#[test]
fn dialling_a_certificate_the_policy_does_not_know_writes_nothing() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_b = Policy::knowing(&[&a]);
    let b_cert = b.cred.cert().clone();
    let nobody = Policy::knowing(&[]);
    let (server, client) = refused(&a, b, &nobody, policy_b);
    assert!(
        matches!(client, Some(ChannelError::UnknownPeer)),
        "{client:?}"
    );
    assert!(matches!(server, Some(ChannelError::Closed)), "{server:?}");
    let (written, err) = wire_bytes(|s| SecureChannel::connect(s, &a.cred, &nobody, &b_cert).err());
    assert_eq!(written, 0);
    assert!(matches!(err, Some(ChannelError::UnknownPeer)), "{err:?}");
}

#[test]
fn dialling_a_certificate_for_another_static_key_does_not_open() {
    // bob's master certifies bob for a static key bob does not hold: the first message is made for that
    // key, does not open at bob, and bob writes nothing
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let not_bobs = DeviceCert::issue(
        &b.master,
        &b.did,
        KeyPair::from_seed([102; 32]).public().0,
        Keypair::from_secret([0x99; 32]).public(),
        ISSUED_AT,
        NOT_AFTER,
        [7; 16],
    )
    .unwrap();
    let policy_a = Policy::knowing(&[&b]);
    let policy_b = Policy::knowing(&[&a]);
    let cred_b = b.cred;
    let (server, client) = pair(
        move |s| SecureChannel::accept(s, &cred_b, &policy_b).err(),
        |s| SecureChannel::connect(s, &a.cred, &policy_a, &not_bobs).err(),
    );
    assert!(
        matches!(server, Some(ChannelError::Noise(NoiseError::Decrypt))),
        "{server:?}"
    );
    assert!(
        matches!(client, Some(ChannelError::Closed | ChannelError::Io(_))),
        "{client:?}"
    );
}

#[test]
fn a_responder_proving_another_subject_than_the_one_dialled_is_refused() {
    // bob's master also certifies bob's static key under a second subject; alice dials that one, and bob
    // proves his own: the handshake completes cryptographically, connect refuses the subject
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let alias = Did::parse("did:alice:bob-alias").unwrap();
    let alias_cert = DeviceCert::issue(
        &b.master,
        &alias,
        KeyPair::from_seed([102; 32]).public().0,
        b.cred.noise_static_public(),
        ISSUED_AT,
        NOT_AFTER,
        [8; 16],
    )
    .unwrap();
    let mut policy_a = Policy::knowing(&[&b]);
    policy_a
        .masters
        .insert(alias.to_string(), b.master.public());
    let policy_b = Policy::knowing(&[&a]);
    let cred_b = b.cred;
    let (_, client) = pair(
        move |s| SecureChannel::accept(s, &cred_b, &policy_b).err(),
        |s| SecureChannel::connect(s, &a.cred, &policy_a, &alias_cert).err(),
    );
    assert!(
        matches!(client, Some(ChannelError::UnexpectedPeer)),
        "{client:?}"
    );
}

#[test]
fn the_handshake_signature_covers_the_transcript_and_the_static_key() {
    let a = party(1, "alice", [1; 16]);
    let h = [0x42; 32];
    let sig = sign_handshake(&a.cred, &h).unwrap();
    let s_pub = a.cred.noise_static_public();
    assert_eq!(
        verify_artifact(
            &sig,
            &a.master.public(),
            HANDSHAKE_CONTEXT,
            &digest_for(h, s_pub),
            NOW,
            Revocation::NoListAvailable,
        ),
        Ok(())
    );
    // another transcript or another static key: the digest differs
    let mut other_h = h;
    other_h[0] ^= 1;
    assert_eq!(
        verify_artifact(
            &sig,
            &a.master.public(),
            HANDSHAKE_CONTEXT,
            &digest_for(other_h, s_pub),
            NOW,
            Revocation::NoListAvailable,
        ),
        Err(ArtifactError::DigestMismatch)
    );
}

#[test]
fn a_certificate_naming_another_static_key_than_the_handshake_used_is_refused() {
    // mallory signs the right digest (her transcript and the static key she uses) under a certificate that
    // names another static key: the signature verifies, the certificate does not cover the key
    let mallory = party(3, "mallory", [3; 16]);
    let b = party(2, "bob", [2; 16]);
    let used = Keypair::from_secret([0x55; 32]);
    let device = KeyPair::from_seed([103; 32]);
    let cert = mallory.cred.cert().clone();
    assert_ne!(cert.noise_static(), &used.public());
    let policy_b = Policy::knowing(&[&mallory]);
    let rs = b.cred.noise_static_public();
    let cred_b = b.cred;
    let (server, ()) = pair(
        move |s| SecureChannel::accept(s, &cred_b, &policy_b).err(),
        move |mut s| {
            let mut hs = HandshakeState::initiator(PROLOGUE, used.clone(), rs);
            let m0 = hs
                .write_message_with(|h| {
                    sign_artifact(
                        &device,
                        &cert,
                        HANDSHAKE_CONTEXT,
                        &digest_for(*h, used.public()),
                    )
                    .unwrap()
                    .to_bytes()
                })
                .unwrap();
            write_frame(&mut s, &m0);
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
        },
    );
    assert!(
        matches!(server, Some(ChannelError::StaticKeyMismatch)),
        "{server:?}"
    );
}

#[test]
fn a_handshake_signature_relayed_from_another_session_is_refused() {
    // the victim connects to the attacker, who acts as an honest responder and so reads the victim's
    // signature; the attacker then presents that signature to a server in a second session
    let victim = party(1, "victim", [1; 16]);
    let attacker = party(3, "mallory", [3; 16]);
    let server = party(2, "server", [2; 16]);

    // session 1: victim -> attacker (the attacker drives the Noise layer itself)
    let victim_policy = Policy::knowing(&[&attacker]);
    let att_cert = attacker.cred.cert().clone();
    let att_cred_1 = party(3, "mallory", [3; 16]).cred;
    let (captured, _victim_side) = pair(
        move |mut s| {
            let mut hs = HandshakeState::responder(PROLOGUE, att_cred_1.noise_static().clone());
            // the victim's payload, in clear for the responder it chose
            hs.read_message(&read_frame(&mut s)).unwrap()
        },
        |s| SecureChannel::connect(s, &victim.cred, &victim_policy, &att_cert).map(|_| ()),
    );
    let stolen = ArtifactSignature::from_bytes(&captured).unwrap();
    assert_eq!(stolen.cert().subject().to_string(), "did:alice:victim");

    // session 2: attacker -> server, presenting the victim's signature
    let server_policy = Policy::knowing(&[&victim, &attacker]);
    let rs = server.cred.noise_static_public();
    let server_cred = server.cred;
    let (server_result, ()) = pair(
        move |s| SecureChannel::accept(s, &server_cred, &server_policy).err(),
        |mut s| {
            let mut hs = HandshakeState::initiator(PROLOGUE, Keypair::from_secret([203; 32]), rs);
            write_frame(&mut s, &hs.write_message(&stolen.to_bytes()).unwrap());
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
        },
    );
    assert!(
        matches!(
            server_result,
            Some(ChannelError::Rejected(ArtifactError::DigestMismatch))
        ),
        "{server_result:?}"
    );
}

#[test]
fn a_credential_needs_the_device_key_and_the_static_key_its_certificate_names() {
    let a = party(1, "alice", [1; 16]);
    let wrong = KeyPair::from_seed([77; 32]);
    assert!(matches!(
        Credential::new(
            wrong,
            a.cred.cert().clone(),
            Keypair::from_secret([201; 32])
        ),
        Err(ChannelError::Credential(ArtifactError::KeyMismatch))
    ));
    assert!(matches!(
        Credential::new(
            KeyPair::from_seed([101; 32]),
            a.cred.cert().clone(),
            Keypair::from_secret([5; 32])
        ),
        Err(ChannelError::StaticKeyMismatch)
    ));
    // the keys the certificate names make a credential
    assert!(Credential::new(
        KeyPair::from_seed([101; 32]),
        a.cred.cert().clone(),
        Keypair::from_secret([201; 32])
    )
    .is_ok());
}

#[test]
fn connect_gives_up_on_a_responder_that_never_answers() {
    // a responder that reads the first message and stays silent: connect ends with Timeout
    use std::time::{Duration, Instant};
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_a = Policy::knowing(&[&b]);
    let b_cert = b.cred.cert().clone();
    let (_, client) = pair(
        move |mut s| {
            let _ = read_frame(&mut s);
            std::thread::sleep(Duration::from_millis(1_500));
        },
        |s| {
            let start = Instant::now();
            let r = SecureChannel::connect_with_timeout(
                s,
                &a.cred,
                &policy_a,
                &b_cert,
                Duration::from_millis(300),
            );
            (r.err(), start.elapsed())
        },
    );
    let (err, took) = client;
    assert!(matches!(err, Some(ChannelError::Timeout)), "{err:?}");
    assert!(
        took < Duration::from_millis(1_200),
        "connect waited {took:?}"
    );
}

#[test]
fn an_operation_that_did_not_finish_poisons_the_blocking_channel() {
    // the peer writes half a frame and stops; the receive times out mid-frame, and the channel then
    // refuses every further operation instead of reading the rest as the start of the next frame
    use std::time::Duration;
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_b = Policy::knowing(&[&a]);
    let policy_a = Policy::knowing(&[&b]);
    let b_cert = b.cred.cert().clone();
    let cred_b = b.cred;
    let (_, result) = pair(
        move |s| {
            let mut ch = SecureChannel::accept(s.try_clone().unwrap(), &cred_b, &policy_b).unwrap();
            let mut raw = s;
            // a frame header announcing 100 bytes, then only 10 of them
            raw.write_all(&100u16.to_be_bytes()).unwrap();
            raw.write_all(&[0u8; 10]).unwrap();
            std::thread::sleep(Duration::from_millis(800));
            drop(ch.recv());
        },
        |s| {
            s.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut ch = SecureChannel::connect(s, &a.cred, &policy_a, &b_cert).unwrap();
            let first = ch.recv().err();
            (first, ch.recv().err(), ch.send(b"x").err())
        },
    );
    let (first, second, third) = result;
    assert!(matches!(first, Some(ChannelError::Io(_))), "{first:?}");
    assert!(matches!(second, Some(ChannelError::Poisoned)), "{second:?}");
    assert!(matches!(third, Some(ChannelError::Poisoned)), "{third:?}");
}

/// What a raw initiator sends after reading the responder's message
#[derive(Clone, Copy)]
enum Confirm {
    /// A message on the new keys carrying this payload
    Payload(&'static [u8]),
    /// 16 bytes that are not a message on the new keys
    Garbage,
    /// The frame of an empty message, with this length in its header, one byte every `gap`
    Drip(Option<u16>, std::time::Duration),
}

/// A raw initiator `a` that completes the handshake with the responder `rs` and then confirms as `confirm`
fn raw_initiator(a: Party, rs: [u8; 32], confirm: Confirm) -> impl FnOnce(TcpStream) {
    move |mut s| {
        let mut hs = HandshakeState::initiator(PROLOGUE, a.cred.noise_static().clone(), rs);
        let m0 = hs
            .write_message_with(|h| sign_handshake(&a.cred, h).unwrap().to_bytes())
            .unwrap();
        write_frame(&mut s, &m0);
        hs.read_message(&read_frame(&mut s)).unwrap();
        let mut t = hs.into_transport().unwrap();
        match confirm {
            Confirm::Payload(p) => write_frame(&mut s, &t.send(p).unwrap()),
            Confirm::Garbage => write_frame(&mut s, &[0x5a; 16]),
            Confirm::Drip(len, gap) => {
                let body = t.send(&[]).unwrap();
                let mut bytes = len.unwrap_or(16).to_be_bytes().to_vec();
                bytes.extend_from_slice(&body);
                for b in bytes {
                    std::thread::sleep(gap);
                    if s.write_all(&[b]).is_err() {
                        return;
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

/// Bob accepts with `deadline` while a raw alice confirms as `confirm`; the error and the time accept took
fn accept_against(
    confirm: Confirm,
    deadline: std::time::Duration,
) -> (Option<ChannelError>, std::time::Duration) {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_b = Policy::knowing(&[&a]);
    let rs = b.cred.noise_static_public();
    let cred_b = b.cred;
    let (server, ()) = pair(
        move |s| {
            let start = std::time::Instant::now();
            let r = SecureChannel::accept_with_timeout(s, &cred_b, &policy_b, deadline);
            (r.err(), start.elapsed())
        },
        raw_initiator(a, rs, confirm),
    );
    server
}

#[test]
fn a_confirmation_that_is_not_an_empty_message_on_the_new_keys_is_refused() {
    use std::time::Duration;
    for confirm in [Confirm::Payload(b"not empty"), Confirm::Garbage] {
        let (err, _) = accept_against(confirm, Duration::from_secs(5));
        assert!(
            matches!(err, Some(ChannelError::Noise(NoiseError::Decrypt))),
            "{err:?}"
        );
    }
    // the reference: an empty message on the new keys opens a channel
    let (err, _) = accept_against(Confirm::Payload(b""), Duration::from_secs(5));
    assert!(err.is_none(), "{err:?}");
}

#[test]
fn the_confirmation_deadline_is_total_not_per_read() {
    use std::time::Duration;
    let deadline = Duration::from_millis(500);
    // 18 bytes, one every 0.6 × the deadline: each read would finish in time, the whole never does
    let (err, took) = accept_against(Confirm::Drip(None, deadline * 6 / 10), deadline);
    assert!(matches!(err, Some(ChannelError::Timeout)), "{err:?}");
    assert!(took < deadline * 2, "accept waited {took:?}");
}

#[test]
fn a_confirmation_frame_of_another_length_is_refused_before_its_body() {
    use std::time::Duration;
    // the header announces 65 535 bytes; accept must refuse it at once, not wait for the body
    let (err, took) = accept_against(
        Confirm::Drip(Some(u16::MAX), Duration::from_millis(1)),
        Duration::from_secs(5),
    );
    assert!(
        matches!(err, Some(ChannelError::Noise(NoiseError::Decrypt))),
        "{err:?}"
    );
    assert!(took < Duration::from_secs(1), "accept waited {took:?}");
}

#[test]
fn a_replayed_first_message_yields_no_channel() {
    // an observer replays an accepted initiator's first message: the responder answers, but without the
    // initiator's ephemeral key the observer cannot make the confirmation, and a guess does not open
    use std::time::Duration;
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let rs = b.cred.noise_static_public();
    let mut hs = HandshakeState::initiator(PROLOGUE, a.cred.noise_static().clone(), rs);
    let m0 = hs
        .write_message_with(|h| sign_handshake(&a.cred, h).unwrap().to_bytes())
        .unwrap();
    let policy_b = Policy::knowing(&[&a]);
    let cred_b = b.cred;
    let (server, ()) = pair(
        move |s| {
            SecureChannel::accept_with_timeout(s, &cred_b, &policy_b, Duration::from_millis(300))
                .err()
        },
        move |mut s| {
            write_frame(&mut s, &m0);
            let _ = read_frame(&mut s);
            // a guess at the confirmation does not open on keys the observer does not have
            write_frame(&mut s, &[0u8; 16]);
            std::thread::sleep(Duration::from_millis(500));
        },
    );
    assert!(
        matches!(server, Some(ChannelError::Noise(NoiseError::Decrypt))),
        "{server:?}"
    );
}
