//! Oracle for the identity binding of the handshake. Each side's Noise static key is bound to its device
//! certificate: the encrypted handshake payload is an artifact signature (`alice-identity`) by the device key
//! over SHA-256(handshake hash at that point || the sender's Noise static public key), for the context
//! `alice-channel/handshake/v1`. The receiver checks the certificate against the subject's master key, its
//! revocation list and the time, then the signature over its own transcript. The digest is recomputed here
//! from that rule, not taken from the code under test.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use alice_channel::noise::{HandshakeState, Keypair, NoiseError, Role};
use alice_channel::{
    sign_handshake, ChannelError, Credential, PeerPolicy, SecureChannel, HANDSHAKE_CONTEXT,
    MAX_FRAME, PROLOGUE,
};
use alice_identity::artifact::{
    sha256_payload, verify_artifact, ArtifactError, ArtifactSignature, Revocation,
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
    let cert = DeviceCert::issue(
        &master,
        &did,
        device.public().0,
        ISSUED_AT,
        NOT_AFTER,
        cert_id,
    )
    .unwrap();
    let noise_static = Keypair::from_secret([seed.wrapping_add(200); 32]);
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
    assert_eq!(PROLOGUE, b"alice-channel v2");
}

#[test]
fn two_certified_devices_connect_and_exchange_messages() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_b = Policy::knowing(&[&a]);
    let policy_a = Policy::knowing(&[&b]);
    let cred_b = b.cred;
    let (server, client) = pair(
        move |s| {
            let mut ch = SecureChannel::accept(s, &cred_b, &policy_b).unwrap();
            let got = ch.recv().unwrap();
            ch.send(b"pong").unwrap();
            (got, ch.peer_cert().subject().to_string())
        },
        |s| {
            let mut ch = SecureChannel::connect(s, &a.cred, &policy_a).unwrap();
            ch.send(b"ping").unwrap();
            (ch.recv().unwrap(), ch.peer_cert().subject().to_string())
        },
    );
    assert_eq!(server, (b"ping".to_vec(), "did:alice:alice".to_owned()));
    assert_eq!(client, (b"pong".to_vec(), "did:alice:bob".to_owned()));
}

#[test]
fn a_device_whose_master_is_unknown_is_refused_in_the_handshake() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let stranger_policy = Policy::knowing(&[]); // bob knows nobody
    let policy_a = Policy::knowing(&[&b]);
    let cred_b = b.cred;
    let (server, _client) = pair(
        move |s| SecureChannel::accept(s, &cred_b, &stranger_policy).err(),
        |s| SecureChannel::connect(s, &a.cred, &policy_a).err(),
    );
    assert!(
        matches!(server, Some(ChannelError::UnknownPeer)),
        "{server:?}"
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
    let cred_b = b.cred;
    let (server, _client) = pair(
        move |s| SecureChannel::accept(s, &cred_b, &policy_b).err(),
        |s| SecureChannel::connect(s, &a.cred, &policy_a).err(),
    );
    assert!(
        matches!(server, Some(ChannelError::Rejected(ArtifactError::Revoked))),
        "{server:?}"
    );
}

#[test]
fn an_expired_certificate_is_refused_in_the_handshake() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_b = Policy::knowing(&[&a]);
    let mut policy_a = Policy::knowing(&[&b]);
    policy_a.now = NOT_AFTER; // the client judges bob's certificate at its expiry
    let cred_b = b.cred;
    let (_server, client) = pair(
        move |s| SecureChannel::accept(s, &cred_b, &policy_b).err(),
        |s| SecureChannel::connect(s, &a.cred, &policy_a).err(),
    );
    assert!(
        matches!(
            client,
            Some(ChannelError::Rejected(ArtifactError::Cert(
                DeviceCertError::Expired { .. }
            )))
        ),
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
fn a_handshake_signature_relayed_from_another_session_is_refused() {
    // the victim connects to the attacker, who acts as an honest responder and so reads the victim's
    // signature; the attacker then presents that signature to a server in a second session
    let victim = party(1, "victim", [1; 16]);
    let attacker = party(3, "mallory", [3; 16]);
    let server = party(2, "server", [2; 16]);

    // session 1: victim -> attacker (the attacker drives the Noise layer itself)
    let victim_policy = Policy::knowing(&[&attacker]);
    let att_cred_1 = Credential::new(
        KeyPair::from_seed([103; 32]),
        attacker.cred.cert().clone(),
        Keypair::from_secret([203; 32]),
    )
    .unwrap();
    let (captured, _victim_side) = pair(
        move |mut s| {
            let mut hs =
                HandshakeState::new(Role::Responder, PROLOGUE, att_cred_1.noise_static().clone());
            hs.read_message(&read_frame(&mut s)).unwrap();
            // the payload is signed over the handshake hash at the point it is encrypted
            let m1 = hs
                .write_message_with(|h| sign_handshake(&att_cred_1, h).unwrap().to_bytes())
                .unwrap();
            write_frame(&mut s, &m1);
            // the victim's payload, in clear for its peer
            hs.read_message(&read_frame(&mut s)).unwrap()
        },
        |s| SecureChannel::connect(s, &victim.cred, &victim_policy).map(|_| ()),
    );
    let stolen = ArtifactSignature::from_bytes(&captured).unwrap();
    assert_eq!(stolen.cert().subject().to_string(), "did:alice:victim");

    // session 2: attacker -> server, presenting the victim's signature
    let server_policy = Policy::knowing(&[&victim, &attacker]);
    let server_cred = server.cred;
    let (server_result, ()) = pair(
        move |s| SecureChannel::accept(s, &server_cred, &server_policy).err(),
        |mut s| {
            let mut hs =
                HandshakeState::new(Role::Initiator, PROLOGUE, Keypair::from_secret([203; 32]));
            write_frame(&mut s, &hs.write_message(b"").unwrap());
            let _server_sig = hs.read_message(&read_frame(&mut s)).unwrap();
            write_frame(&mut s, &hs.write_message(&stolen.to_bytes()).unwrap());
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
fn a_credential_needs_the_device_key_its_certificate_names() {
    let a = party(1, "alice", [1; 16]);
    let wrong = KeyPair::from_seed([77; 32]);
    assert!(matches!(
        Credential::new(wrong, a.cred.cert().clone(), Keypair::from_secret([5; 32])),
        Err(ChannelError::Credential(ArtifactError::KeyMismatch))
    ));
}

#[test]
fn connect_does_not_return_a_channel_the_responder_refused() {
    // key confirmation: the initiator's handshake ends only when the responder, having verified the
    // initiator, answers on the new keys; a refusal is seen by connect itself, not by the first message
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let nobody = Policy::knowing(&[]);
    let policy_a = Policy::knowing(&[&b]);
    let cred_b = b.cred;
    let (server, client) = pair(
        move |s| SecureChannel::accept(s, &cred_b, &nobody).err(),
        |s| SecureChannel::connect(s, &a.cred, &policy_a).err(),
    );
    assert!(
        matches!(server, Some(ChannelError::UnknownPeer)),
        "{server:?}"
    );
    assert!(
        matches!(client, Some(ChannelError::Closed | ChannelError::Io(_))),
        "connect returned a channel the responder refused: {client:?}"
    );
}

#[test]
fn connect_gives_up_on_a_responder_that_never_confirms() {
    // a responder that reads the handshake but never answers on the new keys: connect ends with Timeout
    use std::time::{Duration, Instant};
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_a = Policy::knowing(&[&b]);
    let cred_b = b.cred;
    let (_, client) = pair(
        move |mut s| {
            let mut hs =
                HandshakeState::new(Role::Responder, PROLOGUE, cred_b.noise_static().clone());
            hs.read_message(&read_frame(&mut s)).unwrap();
            let m1 = hs
                .write_message_with(|h| sign_handshake(&cred_b, h).unwrap().to_bytes())
                .unwrap();
            write_frame(&mut s, &m1);
            let _ = read_frame(&mut s);
            // stay silent, holding the connection open
            std::thread::sleep(Duration::from_millis(1_500));
        },
        |s| {
            let start = Instant::now();
            let r = SecureChannel::connect_with_timeout(
                s,
                &a.cred,
                &policy_a,
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
            let mut ch = SecureChannel::connect(s, &a.cred, &policy_a).unwrap();
            let first = ch.recv().err();
            (first, ch.recv().err(), ch.send(b"x").err())
        },
    );
    let (first, second, third) = result;
    assert!(matches!(first, Some(ChannelError::Io(_))), "{first:?}");
    assert!(matches!(second, Some(ChannelError::Poisoned)), "{second:?}");
    assert!(matches!(third, Some(ChannelError::Poisoned)), "{third:?}");
}

/// A responder that completes the handshake and then sends `confirmation` (a frame, or one built on the
/// new keys from `payload`)
fn confirming_responder(
    cred: Credential,
    payload: Option<&'static [u8]>,
    garbage: bool,
) -> impl FnOnce(TcpStream) + Send + 'static {
    move |mut s| {
        let mut hs = HandshakeState::new(Role::Responder, PROLOGUE, cred.noise_static().clone());
        hs.read_message(&read_frame(&mut s)).unwrap();
        let m1 = hs
            .write_message_with(|h| sign_handshake(&cred, h).unwrap().to_bytes())
            .unwrap();
        write_frame(&mut s, &m1);
        hs.read_message(&read_frame(&mut s)).unwrap();
        let mut t = hs.into_transport().unwrap();
        let frame = if garbage {
            vec![0x5a; 16]
        } else {
            t.send(payload.unwrap()).unwrap()
        };
        write_frame(&mut s, &frame);
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
}

#[test]
fn a_confirmation_that_is_not_an_empty_message_on_the_new_keys_is_refused() {
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_a = Policy::knowing(&[&b]);
    for (payload, garbage) in [(Some(&b"not empty"[..]), false), (None, true)] {
        let cred_b = Credential::new(
            KeyPair::from_seed([102; 32]),
            b.cred.cert().clone(),
            Keypair::from_secret([202; 32]),
        )
        .unwrap();
        let (_, client) = pair(confirming_responder(cred_b, payload, garbage), |s| {
            SecureChannel::connect(s, &a.cred, &policy_a).err()
        });
        assert!(
            matches!(client, Some(ChannelError::Noise(NoiseError::Decrypt))),
            "garbage={garbage}: {client:?}"
        );
    }
}

/// A responder that completes the handshake, then sends the confirmation frame `frame` one byte every `gap`
fn dripping_responder(
    cred: Credential,
    frame_len: Option<u16>,
    gap: std::time::Duration,
) -> impl FnOnce(TcpStream) + Send + 'static {
    move |mut s| {
        let mut hs = HandshakeState::new(Role::Responder, PROLOGUE, cred.noise_static().clone());
        hs.read_message(&read_frame(&mut s)).unwrap();
        let m1 = hs
            .write_message_with(|h| sign_handshake(&cred, h).unwrap().to_bytes())
            .unwrap();
        write_frame(&mut s, &m1);
        hs.read_message(&read_frame(&mut s)).unwrap();
        let mut t = hs.into_transport().unwrap();
        let body = t.send(&[]).unwrap();
        let mut bytes = frame_len.unwrap_or(16).to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);
        for b in bytes {
            std::thread::sleep(gap);
            if s.write_all(&[b]).is_err() {
                return;
            }
        }
    }
}

#[test]
fn the_confirmation_deadline_is_total_not_per_read() {
    use std::time::{Duration, Instant};
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_a = Policy::knowing(&[&b]);
    let deadline = Duration::from_millis(500);
    // 18 bytes, one every 0.6 × the deadline: each read would finish in time, the whole never does
    let (_, (err, took)) = pair(
        dripping_responder(b.cred, None, deadline * 6 / 10),
        move |s| {
            let start = Instant::now();
            let r = SecureChannel::connect_with_timeout(s, &a.cred, &policy_a, deadline);
            (r.err(), start.elapsed())
        },
    );
    assert!(matches!(err, Some(ChannelError::Timeout)), "{err:?}");
    assert!(took < deadline * 2, "connect waited {took:?}");
}

#[test]
fn a_confirmation_frame_of_another_length_is_refused_before_its_body() {
    use std::time::{Duration, Instant};
    let a = party(1, "alice", [1; 16]);
    let b = party(2, "bob", [2; 16]);
    let policy_a = Policy::knowing(&[&b]);
    // the header announces 65 535 bytes; connect must refuse it at once, not wait for the body
    let (_, (err, took)) = pair(
        dripping_responder(b.cred, Some(u16::MAX), Duration::from_millis(1)),
        move |s| {
            let start = Instant::now();
            let r =
                SecureChannel::connect_with_timeout(s, &a.cred, &policy_a, Duration::from_secs(5));
            (r.err(), start.elapsed())
        },
    );
    assert!(
        matches!(err, Some(ChannelError::Noise(NoiseError::Decrypt))),
        "{err:?}"
    );
    assert!(took < Duration::from_secs(1), "connect waited {took:?}");
}
