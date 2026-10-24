# ALICE-Channel

Mutually authenticated, encrypted channels between certified devices.

Two devices run the Noise handshake `Noise_IK_25519_ChaChaPoly_SHA256` on ALICE-Crypto's X25519, SHA-256 and ChaCha20-Poly1305 (RFC 8439). Each device's certificate (ALICE-Identity, layout version 2) names its Noise static key under the master key's signature. The initiator dials a peer whose certificate it already holds: it checks that certificate against its `PeerPolicy` and takes the responder's static key from it, so the responder's static key never travels. Each side's handshake payload is an artifact signature by its certified device key, for the context `alice-channel/handshake/v1`, over SHA-256 of the handshake hash at that point and the sender's static key, and the certificate in it must name that static key.

The responder answers only an initiator it accepts. A first message made for another static key does not open, and one from a device the policy refuses is dropped; in both cases nothing is written back, so a peer without the responder's static key and an accepted certificate learns nothing from it. The receiver resolves the certificate's subject to a master key through its `PeerPolicy` and checks the certificate (issuer, validity at the policy's time, revocation), the static key it names, and the signature over its own transcript. A device without a known master, a revoked or expired certificate, or a signature taken from another session or made for another static key never gets a channel.

```rust,ignore
let mut ch = SecureChannel::connect(stream, &credential, &policy, &peer_cert)?;
ch.send(b"hello")?;
let reply = ch.recv()?;
let who = ch.peer_cert().subject();
```

The responder writes its message only after verifying the initiator, so `connect` returning means the responder accepted this side; it also checks that the responder proved the subject of the certificate it dialled (`UnexpectedPeer` otherwise). The initiator then sends one empty message on the new keys, and `accept` returns only once it has opened it (within `DEFAULT_CONFIRM_TIMEOUT`, or `accept_with_timeout`), so a replayed first message never yields a channel. `connect` waits for the responder's message with the same deadline (`connect_with_timeout`). A channel returned by `accept` means the peer completed the handshake, not that it is still there: if it has gone, the first operation reports it.

On the wire every Noise message is one frame: a big-endian `u16` length, then that many bytes. The prologue is `alice-channel v3`. Transport messages are encrypted under a counter nonce, so a changed, replayed or reordered message is refused. An operation that did not finish leaves the channel `Poisoned`, never out of step with its peer.

With the `async` feature, `AsyncSecureChannel` runs the same handshake over tokio streams. Its futures are safe to drop: a dropped handshake gives no channel, and a dropped send or receive poisons the channel.

## Tests

- `tests/noise_vectors.rs`: the public test vector of `Noise_IK_25519_ChaChaPoly_SHA256` (cacophony), every handshake and transport message and the handshake hash byte for byte; a first message for another static key, changed, truncated, out-of-turn, replayed and small-order inputs
- `tests/handshake_identity.rs`: two devices over TCP; unknown master and revoked certificates refused in the handshake, an expired or unknown dialled certificate refused before a byte is written; a certificate for another static key, a certificate naming another static key than the handshake used, a responder proving another subject; the signature covers the transcript and the static key; a signature relayed from another session refused; a responder that never answers, a missing, invalid or slow confirmation, a replayed first message, a receive cut mid-frame
- `tests/responder_hidden.rs`: a scanner speaking the Noise layer reads nothing back for a bare ephemeral key, a first message for another static key, or a first message from a device the responder does not accept; an accepted initiator gets exactly one frame, without the responder's static key or subject in clear
- `tests/async_channel.rs` (feature `async`): the same over tokio; the handshake dropped at each side and direction; a send or receive dropped mid-frame; the confirmation deadline; a refused initiator reads nothing back

## License

`LicenseRef-Proprietary`. The text is [LICENSE-Proprietary](LICENSE-Proprietary).

Enquiries: https://extoria.co.jp/
