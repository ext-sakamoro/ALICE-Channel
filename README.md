# ALICE-Channel

Mutually authenticated, encrypted channels between certified devices.

Two devices run the Noise handshake `Noise_XX_25519_ChaChaPoly_SHA256` on ALICE-Crypto's X25519, SHA-256 and ChaCha20-Poly1305 (RFC 8439). Each side's Noise static key is bound to its device certificate (ALICE-Identity): the encrypted payload of its handshake message is an artifact signature by the certified device key, for the context `alice-channel/handshake/v1`, over SHA-256 of the handshake hash at that point and the sender's static key.

The receiver resolves the certificate's subject to a master key through its `PeerPolicy`, checks the certificate (issuer, validity at the policy's time, revocation) and the signature over its own transcript, and drops the connection inside the handshake when any check fails. A device without a known master, a revoked or expired certificate, or a signature taken from another session or made for another static key never gets a channel.

```rust,ignore
let mut ch = SecureChannel::connect(stream, &credential, &policy)?;
ch.send(b"hello")?;
let reply = ch.recv()?;
let who = ch.peer_cert().subject();
```

The handshake ends with a key confirmation: after verifying the initiator, the responder sends one empty message on the new keys, and `connect` returns only once it has opened it (within `DEFAULT_CONFIRM_TIMEOUT`, or `connect_with_timeout`), so an initiator never holds a channel the responder refused. A channel returned by `accept` means the peer completed the handshake, not that it is still there: if it has gone, the first operation reports it.

On the wire every Noise message is one frame: a big-endian `u16` length, then that many bytes. The prologue is `alice-channel v2`. Transport messages are encrypted under a counter nonce, so a changed, replayed or reordered message is refused. An operation that did not finish leaves the channel `Poisoned`, never out of step with its peer.

With the `async` feature, `AsyncSecureChannel` runs the same handshake over tokio streams. Its futures are safe to drop: a dropped handshake gives no channel, and a dropped send or receive poisons the channel.

## Tests

- `tests/noise_vectors.rs`: the public test vector of `Noise_XX_25519_ChaChaPoly_SHA256` (cacophony), every handshake and transport message and the handshake hash byte for byte; changed, truncated, out-of-turn, replayed and small-order inputs
- `tests/handshake_identity.rs`: two devices over TCP; unknown master, revoked and expired certificates refused in the handshake; the signature covers the transcript and the static key; a signature relayed from another session refused; connect refused by the responder, a missing or invalid confirmation, a receive cut mid-frame
- `tests/async_channel.rs` (feature `async`): the same over tokio; the handshake dropped at each side and direction; a send or receive dropped mid-frame; the confirmation deadline

## License

`LicenseRef-Proprietary`. The text is [LICENSE-Proprietary](LICENSE-Proprietary).

Enquiries: https://extoria.co.jp/
