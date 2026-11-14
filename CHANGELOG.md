# Changelog

All notable changes to ALICE-Channel are documented here. While crates.io is frozen the crate version does not change; a commit is identified by its full git revision.

## [Unreleased]

### Added
- 時計を呼び出し側から渡す `Clock` (`now`: 単調な時刻を起点からの `Duration` で、`system_now`: 壁時計の `SystemTime`) と、標準 library の時計の `SystemClock`、名前を書かない時の型 `DefaultClock` stream の handshake の読み取り期限と datagram の init の TAI64N の時刻は全てこの trait を通して読む (`src/clock.rs` の外で時計を読む箇所は無い) 単調な時刻を `Instant` でなく `Duration` にしたのは、`Instant` は `Instant::now` 以外に作る方法が無く、呼び出し側の時計が値を作れないため
  - `SecureChannel` / `AnonymousChannel` に時計の型引数 `C` (既定 `DefaultClock`) と、時計を取る `connect_with_clock` / `accept_with_clock` 時計を取らない `connect` / `accept` / `connect_with_timeout` / `accept_with_timeout` は `SystemClock` を使い、型と呼び方は変わらない (既存の呼び出しはそのまま compile する) `recv_before` は channel の時計を読む
  - `Initiator::start_with_clock` と `InitTimestamp::from_clock` (`Initiator::start` / `InitTimestamp::now` は `SystemClock` で同じ値)
  - WebAssembly (wasm32-unknown-unknown) では標準 library に時計が無い (読むと panic) ため、`SystemClock` と時計を取らない constructor (`connect` / `accept` / その `_with_timeout`、`Initiator::start`、`InitTimestamp::now`) はこの target に無く、`DefaultClock` は値も `Clock` の実装も無い型 `NoDefaultClock` になる 時計を渡さない code は実行時の panic でなく compile error になる
  - 試験 `tests/wasm_handshake.rs` に 5 本: 偽の時計から init の時刻が決まり、時計が戻った init は `StaleInit`、時刻が過ぎれば受け入れる / stream の `SecureChannel` が時計を渡して connect し (相手は crate の sans-IO の Noise 層で、同じ thread の in-memory stream の向こうで動かす、1 つの thread は blocking stream の両端で待てないため)、両方向に data を送る / 同じく accept / 1 byte ずつ送る相手は偽の時刻の期限で切られる (10 s、読み取りごとに 3 s 進む時計で 3 byte) / `recv_before` は時計に従い、何も来なければ使い続けられ、途中で切れた message は channel を Poisoned にする Node (wasm32-unknown-unknown) と native の両方で走る 変異: 期限の計算で標準 library の時計を読むと Node で stream の 4 本が panic で落ち (native は通る)、init の時刻を標準 library の壁時計にすると Node と native の両方で 1 本が落ちる
  - `scripts/wasm_clock_required.py` (14 件の `cargo check`): wasm32-unknown-unknown で時計を取らない 5 つの呼び出しと既定の時計の型での `recv_before` は E0599 で compile できず、同じ code は host で compile でき、時計を取る constructor は両方で compile できる 小さな crate を target directory に書き、この repo の Cargo.lock を使う 走らせた件数が 14 未満 (0 を含む) なら失敗 wasm でも `SystemClock` を既定にする変異で 6 件が失敗 CI の `wasm-js` job と preflight
  - `scripts/law_boundary_table.toml` に `start_with_clock` の行
- WebAssembly (wasm32-unknown-unknown) の JavaScript の host (browser、Node、edge の runtime) で datagram の handshake が動くことを確かめる試験 `tests/wasm_handshake.rs` (2 本): 鍵は全て host の乱数 (alice-crypto 経由の `crypto.getRandomValues`) から作り、発信側と応答側を 1 つの process で handshake させ、両方向に data を送って開く (1 度だけ開く)、同じ 2 者の 2 回の handshake は transcript が違う この target の標準 library には system の時計が無いので、init の時刻は `Initiator::start_at` で渡す CI の `wasm-js` job が Node と `wasm-bindgen-test-runner` (Cargo.lock の wasm-bindgen と同じ版) で走らせ、通った試験が file の試験数より少なければ (0 を含む) 失敗する (`scripts/wasm_js_test.sh`、preflight も) 他の target では通常の試験として走る alice-crypto が wasm32-unknown-unknown で getrandom の `js` backend を使う前の版では、build の段階で失敗する (確かめた)
- 試験の依存: tokio (async の試験) を wasm32-unknown-unknown 以外の dev-dependency にした (tokio はこの target で multi-thread の runtime を build しない)、wasm32-unknown-unknown の dev-dependency に wasm-bindgen-test

### Changed
- 依存: alice-identity を 3.0 にする (失効は戻らない `DropsRevoked`、公開の error enum が non_exhaustive) branch main のまま、lock は 3.0 の commit code の変更は無し (利用している variant を網羅 match していない)
- 依存: alice-crypto 0.7 (機能ごとの feature に分かれた、既定の build は同じ API)
- `alice-identity` の要求を 2.0 にする (証明書の version 3、端末の id は subject と device key から導く) handshake は証明書を運ぶので、試験 `a_fixed_handshake_gives_fixed_packets` の init と response の digest を記録し直した (confirmation と data packet、`CHANNEL_SEMANTICS_ID` は変わらない) 試験の証明書は id の引数を取らず、失効の試験は証明書の `device_id()` を失効させる
- `alice-crypto` / `alice-identity` / `alice-sign` を git の commit 固定でなく `branch = "main"` で取る (Cargo.lock が固定する) 同じ crate を取る他の消費者と同じ source になり、一緒に build した時に 1 つずつだけ link される lock の解決: alice-crypto は ed065ad のまま、alice-identity は 55be137 から f09fc22、alice-sign は bb79209 から 8c8d1ee (試験 88 本は通る)
- `alice-crypto` を main の `ed065ad` に上げる (SHA-256 の逐次計算の追加と CI の変更のみ、wire の bytes と識別子は変わらない)
- CI (ALICE-Law G9 / G11): 識別子の移動の検査器 (`scripts/id_move_check.py` と試験) を共有の新しい bytes にし、新しく足した associated const を受けるようにした 他の共有の file も ALICE-Law 40973a8a の表が計画した bytes にし、shared-files と G11 の表の pin を上げた

- 依存: alice-identity の pin を 6cf9c0ff から 55be1372 (credential の署名と選択開示を alice-sign の `cred` に任せた版)、alice-sign の pin を 8a1b00d8 から bb79209e に上げ、依存の木の alice-sign を 1 版にした この crate の挙動の変更なし
- CI (ALICE-Law G11): `conformance/g11.toml` (ALICE-Law の `scripts/g11_table_gen.py` が `conformance/g11-own.toml` と共有の行から生成、14 行) を足し、`.github/g11-table-pin` の revision で ALICE-Law の検査器を取る `scripts/g11_table.sh` を CI の float-environment job と preflight で回す manifest の G11 を pass にした shared-files の pin を ALICE-Law 0e8c14e (この crate を写しの持ち主に載せた表) にし、`scripts/id_move_check.py` と試験をその表の計画の bytes (ALICE-Physics が owner) にした
- CI (ALICE-Law): `alice-law-conformance.toml` を足した (G1-G6 / G10 / G12-G14 は pass、G7-G9 は n/a、G11 は fail-known) 共有の file (ALICE-Law の表で ALICE-Crypto が持つ 81 行、pin は 0f545c2) を表の bytes で置き、`scripts/shared_files.sh` と `scripts/public_text.sh` が pin した revision の検査器で比べる
- CI: test を debug / release x x86_64 / aarch64 にし、記録した bit の golden (`tests/semantics_golden.rs`)、識別子 (`tests/channel_semantics_id.rs`)、Noise の vector を `scripts/run_tests.sh` で件数つきで走らせる float-environment job (ubuntu / macOS / Windows)、clippy の canary と外部 module の網羅、Law 境界の走査、識別子の移動の検査、g3-ir / semver-checks / security-audit / eol / public-text の workflow を足した
- clippy.toml: 浮動小数の超越関数と max / min / clamp、時計、OS 乱数、`HashMap` / `HashSet` / `RandomState` を禁止した 時計は `src/clock.rs` の 2 関数だけが読む
- 試験の `HashMap` を `BTreeMap` にした
- `.gitattributes`: text file を全 OS で LF で取り出す
- alice-identity を 6cf9c0f にした (claims と schema の map を `BTreeMap` にした rev、この crate の使い方は変わらない)

### 破壊的変更

- `ChannelError` に `StaleInit` を足した (網羅的な match は腕が要る)
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
- `SecureChannel::recv_before` / `AnonymousChannel::recv_before`: 次の message 全体を `deadline` まで待つ (byte が少しずつ届いても期限は延びない) message の最初の byte が来る前の `Timeout` では channel は使えるまま、途中まで読んだ後の `Timeout` では `Poisoned` 期限 0 は読まずに `Timeout`、stream の読み取り期限は呼ぶ前の値に戻す (戻せなかった時は `Poisoned`) 試験 `tests/recv_deadline.rs` `ChannelError::Timeout` の表示を「the peer did not send in time」にした
- `AnonymousChannel` (`Noise_NK_25519_ChaChaPoly_SHA256`、prologue `alice-channel anonymous v1`): responder だけを認証する channel initiator は ephemeral key と空の payload だけを送り、initiator の証明書・静的鍵・署名は wire に出ない 2 つの prologue は異なるので、一方の初手は他方として開かない 試験 `tests/noise_nk_vectors.rs` (cacophony の NK vector) / `tests/anonymous_channel.rs`
- CI: 他の crate の `PREVIOUS_*_SEMANTICS_IDS` は一覧全体としてだけ使える (`contains` / `len` / `is_empty`、全体を回す iterator や for、引数として丸ごと渡す) とし、添字・slice のパターン・`.first` / `next` / `take` などを拒む `scripts/upstream_previous_ids_check.py` と試験を足した (ALICE-Edge と同じ中身の共有 file) 上流は major で一覧を空にする 走査した .rs が 0 件なら失敗 (ci.yml と preflight)

- `semantics::CHANNEL_SEMANTICS_ID` (`7808060196ea5d8d…a76916d92`): 固定の鍵の handshake と transport、datagram の golden と alice-crypto の `CRYPTO_SEMANTICS_ID` の fold `CHANNEL_SEMANTICS_PINS` / `CHANNEL_SEMANTICS_CHECKED_AT`
- `datagram`: 失われ・並べ替わり・重なる datagram の上で、stream の channel と同じ Noise IK と証明書の束縛を張る (I/O を持たない、呼び出し側が packet を送り受けた packet を渡す) packet は種類 1 byte (`KIND_INIT` / `KIND_RESPONSE` / `KIND_DATA`) で始まり、data の packet は明示の 64 bit の counter (little-endian) を nonce に 1 つずつ封じる (associated data `alice-channel/datagram/v1`) 受け手は開いた最大の counter の下 `REPLAY_WINDOW` = 1024 の窓を持ち、各 counter を 1 回だけどの順でも開く (開いたものは `Replayed`、窓より下は `TooOld`、窓に記録するのは開いた後だけなので変えた・偽の packet は何も動かさない) handshake: `Initiator::start` (`start_at` で時刻を渡す) / `first` (届くまで繰り返す) / `finish`、`Responder::new().respond` → `Pending` (`is_first` で繰り返しを見分け `response` を送り直す、`confirm` は新しい鍵で開いた最初の data の packet で channel を返す: 空の確認でも、それが失われた時の次の data でも)、`DatagramChannel::answer_repeated_response` (応答が繰り返された時に新しい確認を返す) 空の payload は送らない (`Empty`、空の data の packet は確認) 発信側の暗号化した payload の先頭に TAI64N の時刻 (`InitTimestamp`、12 byte) を置き、`Responder` は同じ静的鍵から最後に受け入れた時刻より後の init だけに答える (古い init を後で再送されても何も始まらない、`ChannelError::StaleInit`) 試験用に固定の ephemeral の `Initiator::start_with_ephemeral` / `Responder::respond_with_ephemeral` と、その packet を byte で固定する試験
- noise 層: `Transport::into_datagram` → `DatagramTransport` (明示の counter で `seal` / `open`、transport を消費するので同じ鍵を 2 つの形で使わない)
- `check_cert`: 証明書を policy の今の状態 (master key、時刻、revocation list) で検査する
- `SecureChannel::accept_with_timeout` / `AsyncSecureChannel::accept_with_timeout`
- 試験 `tests/responder_hidden.rs` (鍵を持たない scanner は何も読めない)、`tests/noise_vectors.rs` は IK の公開 test vector (cacophony) に置き換えた

- feature `async`: `AsyncSecureChannel` (tokio の `AsyncRead + AsyncWrite` の上、同じ handshake・証明書への結び付け・鍵の確認) future を落とせる: handshake の途中で落とすと channel は得られず、送受信の途中で落とすと `Poisoned` 試験 `tests/async_channel.rs` (handshake の 4 か所での取り消し、送受信の frame の途中の取り消し、確認の期限)
- `AsyncSecureChannel::into_split`: 送る半分 (`AsyncSendHalf`) と受ける半分 (`AsyncRecvHalf`) に分け、両方向を別の task で同時に動かせる 半分ごとに stream の半分と nonce を持ち、`Poisoned` も半分ごと (送信を落としても受信側は使える、逆も同じ) 既に `Poisoned` の channel は分けない noise 層に `Transport::split` (`TransportSender` / `TransportReceiver`) を足した

### Changed

- Cargo.toml の description を実装に合わせた (handshake は Noise IK、「Noise XX」と書いていた)
- 依存: alice-identity の git rev を 68b8141 にする (did:key の変換と base58 を足しただけで、既存の API と bytes は変わらない)
- 試験: async の `accept_with_timeout` の試験 3 本は await を外側の `tokio::time::timeout` で包む accept が期限を守らなければ数秒で失敗する (以前は job の上限まで終わらなかった)
- README の licence の節を `LicenseRef-Proprietary` の一文と問い合わせ先にした
- alice-identity を path でなく git の rev (公開 repo の root) で取るようにした clone 1 つで build でき、CI は隣の checkout と deploy key を使わない

