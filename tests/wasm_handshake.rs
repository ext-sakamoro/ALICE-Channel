//! The datagram handshake on WebAssembly (wasm32-unknown-unknown) in a JavaScript host.
//!
//! Every key here is drawn from the OS random source (on wasm32-unknown-unknown: `crypto.getRandomValues`
//! through alice-crypto), the two sides run the Noise IK handshake of the datagram mode in one process, and
//! data packets round-trip both ways. The init's timestamp is passed in (`Initiator::start_at`): the
//! standard library has no system clock on wasm32-unknown-unknown, so a host gives the time (in a
//! JavaScript host, `Date.now()`). CI runs this file under Node with `wasm-bindgen-test-runner` and fails
//! when fewer tests pass than it has; on other targets the same tests run as ordinary tests.

use std::collections::BTreeMap;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test;

use alice_channel::datagram::{InitTimestamp, Initiator, Responder};
use alice_channel::noise::Keypair;
use alice_channel::{Credential, PeerPolicy};
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

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    alice_crypto::random::fill(&mut seed).unwrap();
    seed
}

/// A device with fresh keys: the master and device signing keys from OS random seeds, the Noise static key
/// from `Keypair::generate`
fn party(name: &str) -> Party {
    let master = KeyPair::from_seed(random_seed());
    let device = KeyPair::from_seed(random_seed());
    let did = Did::parse(&format!("did:alice:{name}")).unwrap();
    let noise_static = Keypair::generate().unwrap();
    let cert = DeviceCert::issue(
        &master,
        &did,
        device.public().0,
        noise_static.public(),
        ISSUED_AT,
        NOT_AFTER,
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

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn fresh_keys_complete_a_handshake_and_messages_round_trip() {
    let (a, b) = (party("a"), party("b"));
    assert_ne!(
        a.cred.noise_static_public(),
        b.cred.noise_static_public(),
        "two generated static keys"
    );
    let policy = Policy {
        masters: [(&a, ()), (&b, ())]
            .iter()
            .map(|(p, ())| (p.did.to_string(), p.master.public()))
            .collect(),
    };
    let at = InitTimestamp::from_unix(NOW, 0);
    let (init, first) = Initiator::start_at(&a.cred, &policy, b.cred.cert(), at).unwrap();
    let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
    let (mut ca, confirm) = init.finish(pending.response(), &policy).unwrap();
    let (mut cb, payload) = pending.confirm(&confirm).channel().unwrap();
    assert_eq!(payload, None);
    assert_eq!(ca.handshake_hash(), cb.handshake_hash());
    assert_eq!(ca.peer_cert().subject(), b.cred.cert().subject());
    assert_eq!(cb.peer_cert().subject(), a.cred.cert().subject());

    let to_b = ca.seal(b"hello from a").unwrap();
    assert_eq!(
        cb.open(&to_b).unwrap().as_deref(),
        Some(&b"hello from a"[..])
    );
    let to_a = cb.seal(b"hello from b").unwrap();
    assert_eq!(
        ca.open(&to_a).unwrap().as_deref(),
        Some(&b"hello from b"[..])
    );
    assert!(cb.open(&to_b).is_err(), "a packet opens once");
}

#[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test)]
#[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
fn two_handshakes_of_the_same_parties_give_different_keys() {
    // the ephemeral keys are drawn per handshake: the same two parties get a different transcript
    let (a, b) = (party("a"), party("b"));
    let policy = Policy {
        masters: [(&a, ()), (&b, ())]
            .iter()
            .map(|(p, ())| (p.did.to_string(), p.master.public()))
            .collect(),
    };
    let mut hashes = Vec::new();
    for secs in [NOW, NOW + 1] {
        let at = InitTimestamp::from_unix(secs, 0);
        let (init, first) = Initiator::start_at(&a.cred, &policy, b.cred.cert(), at).unwrap();
        let pending = Responder::new().respond(&b.cred, &policy, &first).unwrap();
        let (ca, _) = init.finish(pending.response(), &policy).unwrap();
        hashes.push(ca.handshake_hash());
    }
    assert_ne!(hashes[0], hashes[1]);
}
