//! Oracle for the anonymous channel ([`AnonymousChannel`], `Noise_NK_25519_ChaChaPoly_SHA256`): only the
//! responder is authenticated, and nothing that names the initiator crosses the wire. The transcript test
//! records every byte both ways on the initiator's stream and searches it for every identifying value the
//! initiator's device holds; the search itself is checked to find a planted value, so an empty result means
//! the values are absent and not that nothing was searched.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use alice_channel::noise::nk::NkHandshakeState;
use alice_channel::noise::{HandshakeState, Keypair};
use alice_channel::{
    AnonymousChannel, ChannelError, Credential, PeerPolicy, ReadTimeout, SecureChannel,
    ANONYMOUS_PROLOGUE, PROLOGUE,
};
use alice_identity::artifact::Revocation;
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey};

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_086_400;
const NOW: u64 = 1_800_000_100;
const SHORT: Duration = Duration::from_millis(300);

struct Party {
    master: KeyPair,
    did: Did,
    cred: Credential,
    device_public: [u8; 32],
}

fn party(seed: u8, name: &str) -> Party {
    let master = KeyPair::from_seed([seed; 32]);
    let device = KeyPair::from_seed([seed.wrapping_add(100); 32]);
    let device_public = device.public().0;
    let did = Did::parse(&format!("did:alice:{name}")).unwrap();
    let noise = Keypair::from_secret([seed.wrapping_add(200); 32]);
    let cert = DeviceCert::issue(
        &master,
        &did,
        device_public,
        noise.public(),
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap();
    Party {
        master,
        did,
        cred: Credential::new(device, cert, noise).unwrap(),
        device_public,
    }
}

struct Policy(BTreeMap<String, PublicKey>);

impl Policy {
    fn knowing(parties: &[&Party]) -> Self {
        Self(
            parties
                .iter()
                .map(|p| (p.did.to_string(), p.master.public()))
                .collect(),
        )
    }
}

impl PeerPolicy for Policy {
    fn master_of(&self, subject: &Did) -> Option<PublicKey> {
        self.0.get(&subject.to_string()).copied()
    }
    fn revocation(&self) -> Revocation<'_> {
        Revocation::NoListAvailable
    }
    fn now(&self) -> u64 {
        NOW
    }
}

/// A stream that keeps a copy of every byte written and read
struct Recording {
    inner: TcpStream,
    log: Arc<Mutex<Vec<u8>>>,
}

impl Read for Recording {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.log.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for Recording {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.log.lock().unwrap().extend_from_slice(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl ReadTimeout for Recording {
    fn read_timeout(&self) -> std::io::Result<Option<Duration>> {
        self.inner.read_timeout()
    }
    fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(t)
    }
}

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

fn write_frame(s: &mut TcpStream, b: &[u8]) {
    s.write_all(&u16::try_from(b.len()).unwrap().to_be_bytes())
        .unwrap();
    s.write_all(b).unwrap();
}

/// What the peer wrote back within `SHORT` (nothing, for a refused first message)
fn read_back(s: &mut TcpStream) -> Vec<u8> {
    s.set_read_timeout(Some(SHORT)).unwrap();
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

/// Every identifying value a device holds, as byte strings to search for
fn identifying_values(p: &Party) -> Vec<(&'static str, Vec<u8>)> {
    let cert = p.cred.cert();
    vec![
        ("certificate", cert.to_bytes()),
        ("did", p.did.to_string().into_bytes()),
        ("device id", cert.device_id().as_bytes().to_vec()),
        ("device public key", p.device_public.to_vec()),
        (
            "noise static public key",
            p.cred.noise_static_public().to_vec(),
        ),
        ("master public key", p.master.public().0.to_vec()),
        ("certificate signature", cert.signature().to_vec()),
    ]
}

/// The (name, offset) of every 8-byte window of every value found in `hay`, and the number of windows searched
fn find_windows(
    hay: &[u8],
    values: &[(&'static str, Vec<u8>)],
) -> (Vec<(&'static str, usize)>, usize) {
    let mut found = Vec::new();
    let mut searched = 0;
    for (name, v) in values {
        for w in v.windows(8) {
            searched += 1;
            if let Some(at) = hay.windows(8).position(|h| h == w) {
                found.push((*name, at));
            }
        }
    }
    (found, searched)
}

#[test]
fn the_constants_are_the_documented_ones() {
    assert_eq!(ANONYMOUS_PROLOGUE, b"alice-channel anonymous v1");
    assert_ne!(ANONYMOUS_PROLOGUE, PROLOGUE);
}

#[test]
fn an_anonymous_channel_opens_to_the_dialled_responder_and_carries_messages() {
    let relay = party(1, "relay");
    let relay_cert = relay.cred.cert().clone();
    let policy = Policy::knowing(&[&relay]);
    let (server, client) = pair(
        move |s| {
            let mut ch = AnonymousChannel::accept(s, &relay.cred).unwrap();
            assert!(ch.responder_cert().is_none());
            let got = ch.recv().unwrap();
            ch.send(b"pong").unwrap();
            (got, ch.handshake_hash())
        },
        |s| {
            let mut ch = AnonymousChannel::connect(s, &policy, &relay_cert).unwrap();
            assert_eq!(ch.responder_cert(), Some(&relay_cert));
            ch.send(b"ping").unwrap();
            (ch.recv().unwrap(), ch.handshake_hash())
        },
    );
    assert_eq!(server.0, b"ping");
    assert_eq!(client.0, b"pong");
    assert_eq!(server.1, client.1);
}

#[test]
fn nothing_on_the_wire_names_the_initiator() {
    let relay = party(1, "relay");
    let me = party(2, "sender");
    let relay_cert = relay.cred.cert().clone();
    let policy = Policy::knowing(&[&relay, &me]);
    let log = Arc::new(Mutex::new(Vec::new()));
    let log2 = Arc::clone(&log);
    pair(
        move |s| {
            let mut ch = AnonymousChannel::accept(s, &relay.cred).unwrap();
            let got = ch.recv().unwrap();
            ch.send(&got).unwrap();
        },
        move |s| {
            let rec = Recording {
                inner: s,
                log: log2,
            };
            let mut ch = AnonymousChannel::connect(rec, &policy, &relay_cert).unwrap();
            ch.send(b"an opaque request").unwrap();
            ch.recv().unwrap();
        },
    );
    let transcript = log.lock().unwrap().clone();
    assert!(
        transcript.len() > 2 * (32 + 16),
        "a whole handshake was recorded"
    );
    let values = identifying_values(&me);
    let (found, searched) = find_windows(&transcript, &values);
    assert!(searched > 100, "searched {searched} windows");
    assert!(
        found.is_empty(),
        "the initiator is named on the wire: {found:?}"
    );
}

#[test]
fn the_search_finds_a_planted_certificate() {
    // the tooth of the test above: a transcript that leaks the certificate (the mutant "the initiator sends
    // its certificate in the first payload") is found
    let me = party(2, "sender");
    let mut transcript = vec![0xAB; 200];
    transcript.extend_from_slice(&me.cred.cert().to_bytes());
    transcript.extend_from_slice(&[0xCD; 50]);
    let (found, _) = find_windows(&transcript, &identifying_values(&me));
    assert!(found.iter().any(|(n, _)| *n == "certificate"));
    assert!(found.iter().any(|(n, _)| *n == "noise static public key"));
}

#[test]
fn two_connections_from_one_device_share_no_bytes() {
    let relay = party(1, "relay");
    let relay_cert = relay.cred.cert().clone();
    let mut firsts = Vec::new();
    for _ in 0..2 {
        // the relay's own keys again (party(1) derives them from seeds 101 and 201): a credential is not Clone
        let cred = Credential::new(
            KeyPair::from_seed([101; 32]),
            relay_cert.clone(),
            Keypair::from_secret([201; 32]),
        )
        .unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = Arc::clone(&log);
        let rc = relay_cert.clone();
        let pol = Policy::knowing(&[&relay]);
        pair(
            move |s| {
                AnonymousChannel::accept(s, &cred).unwrap();
            },
            move |s| {
                AnonymousChannel::connect(
                    Recording {
                        inner: s,
                        log: log2,
                    },
                    &pol,
                    &rc,
                )
                .unwrap();
            },
        );
        // the first frame: u16 length, then -> e, es
        let t = log.lock().unwrap().clone();
        let len = usize::from(u16::from_be_bytes([t[0], t[1]]));
        firsts.push(t[2..2 + len].to_vec());
    }
    assert_eq!(firsts[0].len(), 32 + 16);
    let common = firsts[0]
        .windows(8)
        .filter(|w| firsts[1].windows(8).any(|v| v == *w))
        .count();
    assert_eq!(common, 0);
}

#[test]
fn dialling_a_certificate_the_policy_does_not_know_writes_nothing() {
    let relay = party(1, "relay");
    let relay_cert = relay.cred.cert().clone();
    let policy = Policy::knowing(&[]);
    let (written, r) = pair(
        |mut s| read_back(&mut s),
        |s| AnonymousChannel::connect(s, &policy, &relay_cert).map(|_| ()),
    );
    assert!(matches!(r, Err(ChannelError::UnknownPeer)));
    assert!(written.is_empty());
}

#[test]
fn a_responder_without_the_dialled_static_key_cannot_finish() {
    // an impostor holding another static key answers: the initiator's es key does not match, so the first
    // message does not open there and nothing comes back
    let relay = party(1, "relay");
    let impostor = party(3, "impostor");
    let relay_cert = relay.cred.cert().clone();
    let policy = Policy::knowing(&[&relay]);
    let (server, client) = pair(
        move |s| AnonymousChannel::accept_with_timeout(s, &impostor.cred, SHORT).map(|_| ()),
        |s| AnonymousChannel::connect_with_timeout(s, &policy, &relay_cert, SHORT).map(|_| ()),
    );
    assert!(matches!(server, Err(ChannelError::Noise(_))));
    assert!(client.is_err());
}

#[test]
fn a_mutual_first_message_does_not_open_as_anonymous_and_nothing_is_written() {
    let relay = party(1, "relay");
    let me = party(2, "sender");
    let rs = relay.cred.noise_static_public();
    let (server, written) = pair(
        move |s| AnonymousChannel::accept_with_timeout(s, &relay.cred, SHORT).map(|_| ()),
        move |mut s| {
            let mut hs = HandshakeState::initiator(PROLOGUE, me.cred.noise_static().clone(), rs);
            write_frame(&mut s, &hs.write_message(b"").unwrap());
            read_back(&mut s)
        },
    );
    assert!(matches!(server, Err(ChannelError::Noise(_))));
    assert!(written.is_empty());
}

#[test]
fn an_anonymous_first_message_does_not_open_as_mutual_and_nothing_is_written() {
    let relay = party(1, "relay");
    let rs = relay.cred.noise_static_public();
    let policy = Policy::knowing(&[&relay]);
    let (server, written) = pair(
        move |s| SecureChannel::accept_with_timeout(s, &relay.cred, &policy, SHORT).map(|_| ()),
        move |mut s| {
            let mut hs = NkHandshakeState::initiator(ANONYMOUS_PROLOGUE, rs);
            write_frame(&mut s, &hs.write_message(b"").unwrap());
            read_back(&mut s)
        },
    );
    assert!(server.is_err());
    assert!(written.is_empty());
}

#[test]
fn a_first_message_with_a_payload_is_refused_and_nothing_is_written() {
    // the initiator's first payload must be empty: a payload is where a careless caller would put a name
    let relay = party(1, "relay");
    let rs = relay.cred.noise_static_public();
    let (server, written) = pair(
        move |s| AnonymousChannel::accept_with_timeout(s, &relay.cred, SHORT).map(|_| ()),
        move |mut s| {
            let mut hs = NkHandshakeState::initiator(ANONYMOUS_PROLOGUE, rs);
            write_frame(&mut s, &hs.write_message(b"did:alice:sender").unwrap());
            read_back(&mut s)
        },
    );
    assert!(matches!(server, Err(ChannelError::Noise(_))));
    assert!(written.is_empty());
}

#[test]
fn a_replayed_first_message_never_yields_a_channel() {
    // the replayer cannot derive the keys, so no key confirmation comes and accept times out
    let relay = party(1, "relay");
    let rs = relay.cred.noise_static_public();
    let mut hs = NkHandshakeState::initiator(ANONYMOUS_PROLOGUE, rs);
    let first = hs.write_message(b"").unwrap();
    let (server, ()) = pair(
        move |s| AnonymousChannel::accept_with_timeout(s, &relay.cred, SHORT).map(|_| ()),
        move |mut s| {
            write_frame(&mut s, &first);
            let _ = read_back(&mut s);
        },
    );
    assert!(matches!(server, Err(ChannelError::Timeout)));
}
