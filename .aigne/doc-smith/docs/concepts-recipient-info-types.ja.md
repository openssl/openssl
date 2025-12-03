# 受信者情報の種類

Cryptographic Message Syntax (CMS) において、`RecipientInfo` 構造は、コンテンツ暗号化キー (CEK) を各受信者に安全に配送するためのメカニズムです。このドキュメントでは、6 種類の `RecipientInfo` 構造について詳述し、それぞれがどのようにキーを保護し転送するかを説明します。これにより、アプリケーションのセキュリティ要件に適した方法を選択できるようになります。

CMS の `EnvelopedData` 構造では、メッセージコンテンツは、コンテンツ暗号化キー (CEK) として知られる単一のランダムに生成された共通鍵で暗号化されます。許可された受信者のみがコンテンツにアクセスできるようにするためには、CEK 自体を安全に配布する必要があります。これは、各受信者に対して `RecipientInfo` 構造を作成することによって実現されます。各構造には CEK のコピーが含まれており、その意図された受信者だけが復号できるように、その受信者に固有の方法で暗号化されています。

<!-- DIAGRAM_IMAGE_START:intro:16:9 -->
![Recipient Info Types](./assets/diagram/concepts-recipient-info-types-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

OpenSSL は、このキー管理のために 6 つの異なるメカニズムをサポートしており、それぞれが一意のタイプで識別されます。

## Key Transport Recipient Info (KTRI)

キー転送は、CEK を配布するための最も一般的な方法の 1 つです。非対称 (公開鍵) 暗号を使用して、CEK を受信者の公開鍵で直接暗号化します。

*   **タイプ識別子**: `CMS_RECIPINFO_TRANS`
*   **メカニズム**: 送信者は CEK を生成し、受信者の公開鍵 (通常は RSA) を使用して暗号化し、その結果を `KeyTransRecipientInfo` 構造に配置します。受信者は、対応する秘密鍵を使用して CEK を復号し、メッセージコンテンツにアクセスします。
*   **ユースケース**: 受信者が暗号化に適した RSA や同様の公開鍵を含む X.509 証明書を持っている、標準的な公開鍵基盤 (PKI) 環境に最適です。
*   **ASN.1 構造**: `KeyTransRecipientInfo`

このアプローチは直接的で、広くサポートされています。KTRI 受信者を追加するための主要な関数は `CMS_add1_recipient_cert()` です。

```c
CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
                                           X509 *recip, unsigned int flags);
```

## Key Agreement Recipient Info (KARI)

キー合意により、2 つ以上の当事者が安全でないチャネルを介して共有シークレットを生成できます。これは、CEK をラップするためのキー暗号化キー (KEK) を導出するために使用されます。

*   **タイプ識別子**: `CMS_RECIPINFO_AGREE`
*   **メカニズム**: 送信者は一時的なキーペア (例: Diffie-Hellman または Elliptic Curve Diffie-Hellman) を生成します。自身の秘密鍵と受信者の公開鍵を使用して、共有シークレットを導出します。このシークレットは、CEK を暗号化する KEK を導出するために使用されます。受信者は、自身の秘密鍵と送信者の一時的な公開鍵を使用して同じ導出を実行します。
*   **ユースケース**: Diffie-Hellman (DH) または Elliptic Curve Diffie-Hellman (ECDH) に基づくプロトコルに適しており、一時的なキーが使用される場合は Perfect Forward Secrecy (PFS) を提供します。
*   **ASN.1 構造**: `KeyAgreeRecipientInfo`

この方法は KTRI よりも複雑ですが、高度なセキュリティ特性を提供します。

## Key Encryption Key Recipient Info (KEKRI)

この方法では、キー暗号化キー (KEK) として知られる事前共有共通鍵を使用して CEK を暗号化します。

*   **タイプ識別子**: `CMS_RECIPINFO_KEK`
*   **メカニズム**: 送信者と受信者の両方が、事前に共有された共通鍵を持っている必要があります。送信者はこの KEK を使用して、通常は AES Key Wrap のようなキーラッピングアルゴリズムで CEK を暗号化します。受信者は同じ KEK を使用してそれをアンラップします。KEK は一意のキー識別子によって識別されます。
*   **ユースケース**: 共通鍵を帯域外で安全にプロビジョニングおよび管理できるクローズドシステムで役立ちます。公開鍵暗号のオーバーヘッドを回避できます。
*   **ASN.1 構造**: `KEKRecipientInfo`

KEKRI 受信者を追加するための主要な関数は `CMS_add0_recipient_key()` です。

```c
CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid,
                                          unsigned char *key, size_t keylen,
                                          unsigned char *id, size_t idlen,
                                          ASN1_GENERALIZEDTIME *date,
                                          ASN1_OBJECT *otherTypeId,
                                          ASN1_TYPE *otherType);
```

## Password Recipient Info (PWRI)

パスワードベースのキー管理は、共有パスワードまたはパスフレーズから KEK を導出します。

*   **タイプ識別子**: `CMS_RECIPINFO_PASS`
*   **メカニズム**: KEK は、PBKDF2 などの鍵導出関数 (KDF) を使用してパスワードから導出されます。この KEK は、CEK を暗号化するために使用されます。同じパスワードを知っている受信者は、同じ KDF を実行して KEK を再導出し、CEK を復号します。
*   **ユースケース**: セキュリティが証明書やプロビジョニングされたキーではなく、人間が記憶できる秘密に基づいているシナリオ。
*   **ASN.1 構造**: `PasswordRecipientInfo`

PWRI 受信者を追加するには、`CMS_add0_recipient_password()` 関数を使用します。

```c
CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms,
                                               int iter, int wrap_nid,

                                               int pbe_nid,
                                               unsigned char *pass,
                                               ossl_ssize_t passlen,
                                               const EVP_CIPHER *kekciph);
```

## Key Encapsulation Mechanism Recipient Info (KEMRI)

KEMRI は、安全な鍵確立のための現代的なアプローチであり、特に耐量子計算機暗号に関連しています。これはキー転送の一種です。

*   **タイプ識別子**: `CMS_RECIPINFO_KEM`
*   **メカニズム**: 鍵カプセル化メカニズム (KEM) は、共有シークレットをカプセル化および非カプセル化するための一連のアルゴリズムです。送信者は受信者の公開鍵を使用して、共有シークレットと暗号文 (カプセル化されたキー) を生成します。共有シークレットは KDF と共に使用され、CEK をラップする KEK を導出します。受信者は自身の秘密鍵を使用して暗号文を非カプセル化し、同じ共有シークレットを取得して、同じ KEK を導出します。
*   **ユースケース**: 新たな暗号アルゴリズム、特に量子コンピュータからの攻撃に耐性があるように設計されたアルゴリズムのための標準化されたフレームワークを提供します。
*   **ASN.1 構造**: `KEMRecipientInfo` (`OtherRecipientInfo` 内)

## Other Recipient Info (ORI)

このタイプは、標準セットでカバーされていない新しい受信者情報タイプを定義するための拡張ポイントとして機能します。

*   **タイプ識別子**: `CMS_RECIPINFO_OTHER`
*   **メカニズム**: 構造と処理ルールは、一意のオブジェクト識別子 (`oriType`) によって識別される特定の実装によって定義されます。KEMRI は、`OtherRecipientInfo` を使用して実装されたメカニズムの著名な例です。
*   **ユースケース**: 仕様の新しいバージョンを必要とせずに、新しいキー管理スキームの統合を可能にすることで、CMS 標準の将来性を保証します。
*   **ASN.1 構造**: `OtherRecipientInfo`

## 受信者タイプの概要

以下の表は、さまざまな `RecipientInfo` タイプの概要比較を提供します。

| タイプ | 識別子 | キー管理 | 主なキータイプ | 一般的なユースケース |
| :--- | :--- | :--- | :--- | :--- |
| **KTRI** | `CMS_RECIPINFO_TRANS` | 非対称キー転送 | RSA 公開鍵 | 標準的な証明書ベースの暗号化。 |
| **KARI** | `CMS_RECIPINFO_AGREE` | 非対称キー合意 | DH/ECDH 公開鍵 | キー導出のための共有シークレットの確立。 |
| **KEKRI** | `CMS_RECIPINFO_KEK` | 共通鍵キーラップ | 事前共有共通鍵 | 事前にプロビジョニングされた共通鍵を持つシステム。 |
| **PWRI** | `CMS_RECIPINFO_PASS` | 共通鍵パスワードベース | パスワード/パスフレーズ | 共有された秘密に基づくセキュリティ。 |
| **KEMRI**| `CMS_RECIPINFO_KEM` | 鍵カプセル化 | KEM 公開鍵 | 耐量子計算機暗号と現代的なスキーム。 |
| **ORI** | `CMS_RECIPINFO_OTHER` | カスタム | 可変 | 新しいキー管理メカニズムのための拡張性。 |

---

### 参考文献

-   `RecipientInfo` がメッセージ全体の構造にどのように適合するかを理解するには、[コンテンツタイプ](./concepts-content-types.md) を参照してください。
-   暗号化を実装するためのステップバイステップの手順については、[暗号化と復号](./guides-encrypting-decrypting.md) ガイドを参照してください。
-   詳細な API リファレンスについては、[RecipientInfo 関数](./api-recipientinfo.md) のドキュメントをご覧ください。