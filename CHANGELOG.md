# Changelog

All notable changes to ALICE-Channel are documented here. While crates.io is frozen the crate version does not change; a commit is identified by its full git revision.

## [Unreleased]

### 破壊的変更

- handshake の最後に鍵の確認を足した: 応答側は発信側を確かめた後、新しい鍵で空の message を 1 つ送り、`connect` はそれを開けてから channel を返す 応答側が拒んだ発信側は channel を得ない (以前は 3 通目を送った時点で `connect` が終わり、拒まれたことは最初の送受信で分かった) wire が変わったので prologue を `alice-channel v2` にした (v1 の相手とは handshake で失敗する)
- `SecureChannel::connect` は stream に `ReadTimeout` (`TcpStream` と unix の `UnixStream` に実装) を求める 確認を待つ期限は `DEFAULT_CONFIRM_TIMEOUT` (10 秒)、`connect_with_timeout` で指定でき、確認の読み全体に掛かる (1 byte ずつ送る相手でも延びない) 来なければ `ChannelError::Timeout` 確認の frame の長さは空の message の tag (16 byte) だけで、他の長さは本体を読む前に拒む stream の read timeout は待った後に元へ戻す
- `ChannelError` に `Timeout` と `Poisoned` を足した 終わらなかった送受信 (I/O の error、async では future を落とした時) の後、channel は `Poisoned` を返して使えなくなる (相手とずれたまま続けない)

### Added

- feature `async`: `AsyncSecureChannel` (tokio の `AsyncRead + AsyncWrite` の上、同じ handshake・証明書への結び付け・鍵の確認) future を落とせる: handshake の途中で落とすと channel は得られず、送受信の途中で落とすと `Poisoned` 試験 `tests/async_channel.rs` (handshake の 4 か所での取り消し、送受信の frame の途中の取り消し、確認の期限)
- `AsyncSecureChannel::into_split`: 送る半分 (`AsyncSendHalf`) と受ける半分 (`AsyncRecvHalf`) に分け、両方向を別の task で同時に動かせる 半分ごとに stream の半分と nonce を持ち、`Poisoned` も半分ごと (送信を落としても受信側は使える、逆も同じ) 既に `Poisoned` の channel は分けない noise 層に `Transport::split` (`TransportSender` / `TransportReceiver`) を足した

### Changed

- alice-identity を path でなく git の rev (公開 repo の root) で取るようにした clone 1 つで build でき、CI は隣の checkout と deploy key を使わない

