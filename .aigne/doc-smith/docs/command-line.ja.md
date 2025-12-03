このドキュメントでは、`openssl cms` コマンドラインツールの詳細なリファレンスを提供し、その操作とフラグを基盤となる OpenSSL ライブラリ関数に対応付けます。これらの関連性を理解することで、コマンドラインの使用からプログラムによる API 実装への移行をより効果的に行うことができます。

# CLI ツール (`openssl cms`)

`openssl cms` コマンドは、Cryptographic Message Syntax (CMS) データを扱うためのコマンドラインインターフェースを提供します。これにより、ユーザーはデジタル署名の作成、署名の検証、メッセージ内容の暗号化または復号化など、S/MIME のようなセキュアな電子メールの標準に準拠した幅広い暗号操作を実行できます。

このツールは、OpenSSL の CMS ライブラリのコア機能に対する実用的なラッパーとして機能します。その使用法を理解することは、より複雑なワークフローのために API をプログラム的に応用する際の洞察を得るのに役立ちます。

以下の図は、`openssl cms` コマンドラインツール、その主要な操作、そしてそれらが利用するコア OpenSSL ライブラリ関数との関係を示しています。

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![このドキュメントでは、`openssl cms` コマンドラインツールの詳細なリファレンスを提供し、その操作とフラグを基盤となる OpenSSL ライブラリ関数に対応付けます。](./assets/diagram/command-line-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## 操作

`openssl cms` ツールの主要な機能は、単一の操作オプションによって決定されます。各操作は、入力データの読み取りから最終的な出力のフォーマットまで、いくつかのステップを組み合わせた高レベルのワークフローに対応します。以下の表は、最も一般的な操作と、それに対応する主要なライブラリ関数および CMS コンテンツタイプを示したものです。

| 操作オプション | CMS コンテンツタイプ | コア API 関数 | 説明 |
| :--- | :--- | :--- | :--- |
| `-sign` | `SignedData` | `CMS_sign()` | 入力データに対するデジタル署名を作成します。 |
| `-verify` | `SignedData` | `CMS_verify()` | 署名付きメッセージの完全性と真正性を検証します。 |
| `-encrypt` | `EnvelopedData` | `CMS_encrypt()` | 1 人以上の受信者宛にコンテンツを暗号化します。 |
| `-decrypt` | `EnvelopedData` | `CMS_decrypt()` | 受信者の秘密鍵を使用してコンテンツを復号化します。 |
| `-compress` | `CompressedData` | `CMS_compress()` | zlib を使用して入力データを圧縮します。 |
| `-uncompress` | `CompressedData` | `CMS_uncompress()` | `CompressedData` オブジェクトを解凍します。 |
| `-resign` | `SignedData` | `CMS_sign()` と `CMS_REUSE_DIGEST` | 既存の `SignedData` 構造体に新しい署名を追加します。 |
| `-digest_create`| `DigestedData` | `CMS_digest_create()` | メッセージダイジェストを含む構造体を作成します。 |
| `-EncryptedData_encrypt` | `EncryptedData` | `CMS_EncryptedData_encrypt()` | 受信者情報なしで対称鍵を使用してデータを暗号化します。 |

## オプションリファレンス

各操作の動作は、一連のフラグによって制御されます。これらのフラグは、多くの場合、基盤となる C API 関数のパラメータやフラグに直接対応しています。

### 一般および I/O オプション

これらのオプションは、入力と出力のソースおよびフォーマットを制御します。

| フラグ | パラメータ | 説明 |
| :--- | :--- | :--- |
| `-in` | `<filename>` | 入力ファイルを指定します。 |
| `-out` | `<filename>` | 出力ファイルを指定します。 |
| `-inform` | `SMIME` \| `PEM` \| `DER` | 入力フォーマットを設定します。デフォルトは `SMIME` です。 |
| `-outform`| `SMIME` \| `PEM` \| `DER` | 出力フォーマットを設定します。デフォルトは `SMIME` です。 |
| `-binary` | (なし) | 正規のテキスト変換 (CRLF 変換) を防ぎます。バイナリデータに使用します。`CMS_BINARY` フラグに対応します。 |
| `-stream`, `-indef` | (なし) | ストリーミング I/O を有効にします。これは BER の不定長エンコーディングを使用します。`CMS_STREAM` フラグに対応します。 |
| `-content`| `<filename>` | 検証用の分離されたコンテンツファイルを指定します。 |
| `-text` | (なし) | 署名/暗号化時に `text/plain` MIME ヘッダーを追加するか、検証/復号化時にそれらを削除します。`CMS_TEXT` フラグに対応します。 |

### 署名および検証オプション

これらのフラグは、`-sign` および `-verify` 操作の動作を変更します。

| フラグ | パラメータ | 操作 | 説明 |
| :--- | :--- | :--- | :--- |
| `-signer` | `<certfile>` | Sign, Verify | 署名者の証明書を指定します。複数署名者メッセージの場合、複数回使用できます。 |
| `-inkey` | `<keyfile>` | Sign, Decrypt | `-signer` または `-recip` 証明書に対応する秘密鍵を指定します。 |
| `-md` | `<digest>` | Sign | ダイジェストアルゴリズム (例: `sha256`) を設定します。 |
| `-nodetach`| (なし) | Sign | コンテンツが `SignedData` 構造体内に埋め込まれる不透明な署名を作成します。`CMS_DETACHED` フラグをクリアします。 |
| `-nocerts` | (なし) | Sign | `SignedData` 構造体から署名者の証明書を除外します。`CMS_NOCERTS` フラグに対応します。 |
| `-noattr` | (なし) | Sign | 署名時刻や S/MIME capabilities を含むすべての署名付き属性を除外します。`CMS_NOATTR` フラグに対応します。 |
| `-noverify`| (なし) | Verify | 署名者の証明書チェーンの検証をスキップします。`CMS_NO_SIGNER_CERT_VERIFY` フラグに対応します。 |
| `-nosigs` | (なし) | Verify | デジタル署名自体の検証をスキップします。`CMS_NOSIGS` フラグに対応します。 |
| `-certfile`| `<certs.pem>` | Sign, Verify | メッセージに含めるか、検証時のチェーン構築に使用する追加の証明書を提供します。 |
| `-CAfile` | `<ca.pem>` | Verify | チェーン検証のために信頼された CA 証明書のファイルを指定します。 |

### 暗号化および復号化オプション

これらのフラグは、`-encrypt` および `-decrypt` 操作の動作を変更します。

| フラグ | パラメータ | 操作 | 説明 |
| :--- | :--- | :--- | :--- |
| `-recip` | `<cert.pem>` | Encrypt, Decrypt | 暗号化または復号化のための受信者の証明書を指定します。 |
| `-<cipher>` | (なし) | Encrypt | コンテンツ暗号化アルゴリズム (例: `-aes256`, `-des3`) を指定します。 |
| `-keyid` | (なし) | Encrypt, Sign | 発行者とシリアル番号の代わりに、サブジェクトキー識別子によって受信者または署名者を識別します。`CMS_USE_KEYID` フラグに対応します。 |
| `-secretkey`| `<key>` | Encrypt, Decrypt | `KEKRecipientInfo` (暗号化) または `EncryptedData` 操作用の16進数エンコードされた対称鍵。 |
| `-secretkeyid`| `<id>` | Encrypt, Decrypt | KEK 受信者用の16進数エンコードされた鍵識別子。 |
| `-pwri_password`| `<password>` | Encrypt, Decrypt | `PasswordRecipientInfo` (PWRI) 用のパスワード。 |
| `-originator` | `<cert.pem>` | Decrypt | 鍵合意方式 (例: ECDH) のための発信者の証明書を指定します。 |

## 実用例

以下の例は、`openssl cms` ツールの一般的な使用例を示しています。

### 分離署名の作成

このコマンドはメッセージに署名し、署名を別のファイルに出力することで、元のコンテンツを変更せずに保持します。これはデフォルトの署名動作です。

```sh 分離署名の作成 icon=lucide:terminal
openssl cms -sign -in message.txt -text -out signature.pem \
  -signer signer_cert.pem -inkey signer_key.pem
```

### 分離署名の検証

署名を検証するには、元のコンテンツ、署名ファイル、および署名者の証明書を提供する必要があります。

```sh 分離署名の検証 icon=lucide:terminal
openssl cms -verify -in signature.pem -inform PEM \
  -content message.txt -CAfile trusted_ca.pem -out verified_message.txt
```

### 不透明 (添付) 署名の作成

不透明署名は、元のコンテンツを CMS 構造内に埋め込みます。結果のファイルは、解析しない限り人間が読むことはできません。

```sh 不透明署名の作成 icon=lucide:terminal
openssl cms -sign -in message.txt -text -nodetach \
  -out signed_opaque.pem -signer signer_cert.pem
```

### 複数受信者向けのメッセージ暗号化

このコマンドは、2人の異なる受信者のためにファイルを暗号化します。どちらの受信者も、対応する秘密鍵でメッセージを復号化できます。

```sh 複数受信者向けの暗号化 icon=lucide:terminal
openssl cms -encrypt -in confidential.txt -out encrypted.pem \
  -recip recip1_cert.pem -recip recip2_cert.pem
```

### メッセージの復号化

受信者は、自分の証明書と秘密鍵を使用してメッセージを復号化します。

```sh メッセージの復号化 icon=lucide:terminal
openssl cms -decrypt -in encrypted.pem -out confidential.txt \
  -recip recip1_cert.pem -inkey recip1_key.pem
```

### メッセージの署名と暗号化

署名と暗号化の両方が施されたメッセージを作成するには、操作を連結します。`-sign` コマンドの出力を `-encrypt` コマンドの入力にパイプします。

```sh メッセージの署名と暗号化 icon=lucide:terminal
openssl cms -sign -in message.txt -signer signer.pem -text \
  | openssl cms -encrypt -recip recipient.pem -out signed_and_encrypted.pem
```

## まとめ

`openssl cms` コマンドラインツールは、CMS 構造を管理するための多機能なユーティリティです。そのオプションと操作は、OpenSSL ライブラリで利用可能な関数に直接対応しています。開発者にとって、そのソースコードと動作を分析することは、これらの機能をプログラム的に実装する方法を学ぶ効果的な方法です。

基盤となる API の詳細については、以下のセクションを参照してください:
- [主要な関数](./api-main.md)
- [署名と検証](./guides-signing-verifying.md)
- [暗号化と復号化](./guides-encrypting-decrypting.md)