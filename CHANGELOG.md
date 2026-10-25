# Changelog

All notable changes to ALICE-Channel are documented here. While crates.io is frozen the crate version does not change; a commit is identified by its full git revision.

## [Unreleased]

### 破壊的変更

- `SecureChannel::accept_with_timeout` / `AsyncSecureChannel::accept_with_timeout` の期限は発信側の 1 通目にも掛かる (何も送らない接続は期限で何も書かずに切る、1 byte ずつ送る相手でも延びない) 引数は `confirm_timeout` から `timeout` にした `accept` は `DEFAULT_CONFIRM_TIMEOUT` を両方に使う
- handshake を `Noise_IK_25519_ChaChaPoly_SHA256` にした (XX をやめた): 発信側は相手の証明書 (ALICE-Identity の layout version 2、Noise の静的鍵を master が署名する) を持って dial し、そこから応答側の静的鍵を取る 応答側の静的鍵は wire に出ない 応答側は 1 通目が自分の静的鍵で開かない時、または発信側を policy が拒む時に何も書かずに切る 応答側は発信側を確かめてから 2 通目を書き、発信側は新しい鍵で空の message を 1 つ送って確認し、`accept` はそれを開けてから channel を返す prologue は `alice-channel v3`
- `SecureChannel::connect` / `connect_with_timeout` と `AsyncSecureChannel` の同名の関数は dial する相手の `DeviceCert` を取る その証明書は書く前に policy で検査し (`check_cert`)、応答側が示した subject が違えば `ChannelError::UnexpectedPeer` `connect_with_timeout` の期限は応答側の 2 通目を待つ時間 `SecureChannel::accept` は stream に `ReadTimeout` を求め、確認を `DEFAULT_CONFIRM_TIMEOUT` (`accept_with_timeout` で指定) まで待つ
- `Credential::new` と handshake の検査は、証明書が名指す Noise の静的鍵と実際の静的鍵が違えば `ChannelError::StaticKeyMismatch` で拒む
- noise 層の `HandshakeState::new` / `with_ephemeral` を `initiator` / `responder` / `initiator_with_ephemeral` / `responder_with_ephemeral` にした 読めなかった handshake の message は状態を変えない
- alice-identity を DeviceCert version 2 (Noise の静的鍵、subject は 255 byte まで) の rev にした

- handshake の最後に鍵の確認を足した: 応答側は発信側を確かめた後、新しい鍵で空の message を 1 つ送り、`connect` はそれを開けてから channel を返す 応答側が拒んだ発信側は channel を得ない (以前は 3 通目を送った時点で `connect` が終わり、拒まれたことは最初の送受信で分かった) wire が変わったので prologue を `alice-channel v2` にした (v1 の相手とは handshake で失敗する)
- `SecureChannel::connect` は stream に `ReadTimeout` (`TcpStream` と unix の `UnixStream` に実装) を求める 確認を待つ期限は `DEFAULT_CONFIRM_TIMEOUT` (10 秒)、`connect_with_timeout` で指定でき、確認の読み全体に掛かる (1 byte ずつ送る相手でも延びない) 来なければ `ChannelError::Timeout` 確認の frame の長さは空の message の tag (16 byte) だけで、他の長さは本体を読む前に拒む stream の read timeout は待った後に元へ戻す
- `ChannelError` に `Timeout` と `Poisoned` を足した 終わらなかった送受信 (I/O の error、async では future を落とした時) の後、channel は `Poisoned` を返して使えなくなる (相手とずれたまま続けない)

### Added

- `check_cert`: 証明書を policy の今の状態 (master key、時刻、revocation list) で検査する
- `SecureChannel::accept_with_timeout` / `AsyncSecureChannel::accept_with_timeout`
- 試験 `tests/responder_hidden.rs` (鍵を持たない scanner は何も読めない)、`tests/noise_vectors.rs` は IK の公開 test vector (cacophony) に置き換えた

- feature `async`: `AsyncSecureChannel` (tokio の `AsyncRead + AsyncWrite` の上、同じ handshake・証明書への結び付け・鍵の確認) future を落とせる: handshake の途中で落とすと channel は得られず、送受信の途中で落とすと `Poisoned` 試験 `tests/async_channel.rs` (handshake の 4 か所での取り消し、送受信の frame の途中の取り消し、確認の期限)
- `AsyncSecureChannel::into_split`: 送る半分 (`AsyncSendHalf`) と受ける半分 (`AsyncRecvHalf`) に分け、両方向を別の task で同時に動かせる 半分ごとに stream の半分と nonce を持ち、`Poisoned` も半分ごと (送信を落としても受信側は使える、逆も同じ) 既に `Poisoned` の channel は分けない noise 層に `Transport::split` (`TransportSender` / `TransportReceiver`) を足した

### Changed

- 依存: alice-identity の git rev を 68b8141 にする (did:key の変換と base58 を足しただけで、既存の API と bytes は変わらない)
- 試験: async の `accept_with_timeout` の試験 3 本は await を外側の `tokio::time::timeout` で包む accept が期限を守らなければ数秒で失敗する (以前は job の上限まで終わらなかった)
- README の licence の節を `LicenseRef-Proprietary` の一文と問い合わせ先にした
- alice-identity を path でなく git の rev (公開 repo の root) で取るようにした clone 1 つで build でき、CI は隣の checkout と deploy key を使わない

