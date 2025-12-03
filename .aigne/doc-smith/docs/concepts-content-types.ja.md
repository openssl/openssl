このセクションでは、Cryptographic Message Syntax (CMS) の 6 つの基本的な構成要素について解説します。このガイドを最後まで読むことで、それぞれの主要な CMS コンテンツタイプを区別し、それぞれが果たすように設計された特定の暗号化の目的を理解できるようになります。

# コンテンツタイプ

Cryptographic Message Syntax の中核には `ContentInfo` 構造体があります。これは、保護されたすべてのデータを格納する汎用的なコンテナです。`ContentInfo` オブジェクトには、コンテンツタイプの識別子と、それに対応するコンテンツ自体が含まれます。CMS は 6 つの主要なコンテンツタイプを定義しており、それぞれが異なる暗号化機能を果たします。これらのタイプはネストして、署名してから暗号化するメッセージを作成するなど、操作を組み合わせることができます。

以下の図は、これらのコンテンツタイプが互いにどのように関連しているかを示しており、多くの場合 `Data` タイプが最も内側のコンテンツになります。

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![This section breaks down the six fundamental building blocks of the Cryptographic Message Syntax ...](./assets/diagram/content-types-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

これら 6 つのタイプを理解することは、OpenSSL CMS ライブラリを効果的に使用するために不可欠です。なぜなら、これらがすべての署名および暗号化操作の基盤を形成するためです。

| コンテンツタイプ | ASN.1 オブジェクト識別子 | 目的 |
| :--- | :--- | :--- |
| **Data** | `pkcs7-data` | 暗号化による保護なしで、任意のオクテット文字列データをカプセル化します。他のタイプの最も内側のコンテンツとして機能します。 |
| **SignedData** | `pkcs7-signedData` | コンテンツにデジタル署名を適用し、認証、完全性、否認防止を提供します。 |
| **EnvelopedData** | `pkcs7-envelopedData` | 1 人以上の受信者に対してコンテンツを暗号化し、機密性を提供します。 |
| **DigestedData** | `pkcs7-digestData` | コンテンツとそのコンテンツのメッセージダイジェストをカプセル化することで、コンテンツの完全性を提供します。 |
| **EncryptedData** | `pkcs7-encryptedData` | 対称鍵を使用してコンテンツを暗号化します。`EnvelopedData` とは異なり、鍵管理のための受信者情報を含みません。 |
| **AuthEnvelopedData** | `id-smime-ct-authEnvelopedData` | 関連データ付き認証付き暗号化 (AEAD) を提供し、機密性と完全性を単一の操作で組み合わせます。 |

---

## Data

`Data` コンテンツタイプは最も基本的なものです。これは単にデータのオクテット文字列を含み、暗号化による保護は提供しません。`SignedData` や `EnvelopedData` といった他の CMS タイプ内でカプセル化されたコンテンツとして最も頻繁に使用されます。

-   **目的**: 生のメッセージコンテンツを保持するため。
-   **構造**: 単一のフィールドである `OCTET STRING` で構成され、メッセージデータを含みます。

```sh ASN.1 定義
ContentInfo ::= SEQUENCE {
  contentType                OBJECT IDENTIFIER (pkcs7-data),
  content               [0]  EXPLICIT ANY DEFINED BY contentType OPTIONAL
                               -- OCTET STRING を含む
}
```

---

## SignedData

`SignedData` コンテンツタイプは、1 つ以上のデジタル署名をコンテンツに適用するために使用されます。データの完全性、署名者の認証、および否認防止を提供します。コンテンツ自体は、構造体から分離 (detached) することも、構造体内にカプセル化することもできます。

-   **目的**: デジタル署名の作成と検証を行うため。
-   **主な特徴**: 複数の署名者、分離署名、検証を支援するための証明書と CRL の包含をサポートします。

### 構造

`SignedData` 構造体は、署名者、ダイジェストアルゴリズム、および署名対象のコンテンツに関する情報の集合です。

| フィールド | 説明 |
| :--- | :--- |
| `version` | 構文のバージョン番号。使用されるコンポーネントに基づいて自動的に設定されます (例: `subjectKeyIdentifier` が使用される場合はバージョン 3)。 |
| `digestAlgorithms` | 署名者によって使用されるメッセージダイジェストアルゴリズム識別子のセット。 |
| `encapContentInfo` | カプセル化されたコンテンツ。そのタイプとコンテンツ自体を含みます (分離署名の場合は省略されることがあります)。 |
| `certificates` | 署名の検証に役立つ証明書のオプションのセット。 |
| `crls` | パス検証のための証明書失効リスト (CRL) のオプションのセット。 |
| `signerInfos` | 各署名者に対応する `SignerInfo` 構造体のセット。各 `SignerInfo` には、署名者の ID、ダイジェストおよび署名アルゴリズム、署名付き属性、および署名自体が含まれます。 |

署名者情報の管理に関する詳細は、[SignerInfo Functions](./api-signerinfo.md) API リファレンスを参照してください。

---

## EnvelopedData

`EnvelopedData` コンテンツタイプは、1 人以上の受信者のためにコンテンツを暗号化し、機密性を確保するために使用されます。これは、ランダムな対称コンテンツ暗号化キー (CEK) を生成し、CEK でデータを暗号化し、その後、各受信者の公開鍵を使用して CEK を暗号化することで機能します。

-   **目的**: 特定の受信者のためにデータを暗号化するため。
-   **主な特徴**: さまざまな鍵管理技術を使用して複数の受信者をサポートします。

### 構造

`EnvelopedData` 構造体には、暗号化されたコンテンツと、受信者がそれを復号するために必要なすべての情報が含まれます。

| フィールド | 説明 |
| :--- | :--- |
| `version` | 構文のバージョン番号。受信者情報のタイプや他のフィールドの有無によって決定されます。 |
| `originatorInfo` | 受信者が鍵合意キーを確立するのを助けるための証明書と CRL を含むオプションのフィールド。 |
| `recipientInfos` | 各受信者に対応する `RecipientInfo` 構造体のセット。各構造体には、受信者の識別子と暗号化された CEK が含まれます。 |
| `encryptedContentInfo` | 暗号化されたコンテンツ、コンテンツ暗号化アルゴリズム、および暗号化されたコンテンツ自体を含みます。 |
| `unprotectedAttrs` | 暗号的に保護されていない属性のオプションのセット。 |

さまざまな受信者の鍵がどのように管理されるかを理解するには、[Recipient Info Types](./concepts-recipient-info-types.md) のドキュメントを参照してください。

---

## DigestedData

`DigestedData` コンテンツタイプは、コンテンツの完全性を保証するための簡単な方法を提供します。これは、コンテンツと、指定されたアルゴリズムで計算されたそのコンテンツのメッセージダイジェスト (ハッシュ) で構成されます。認証や機密性は提供しません。

-   **目的**: コンテンツが転送中に変更されていないことを検証するため。
-   **主な特徴**: 完全性のみが必要な場合、`SignedData` よりもシンプルです。

### 構造

| フィールド | 説明 |
| :--- | :--- |
| `version` | 構文のバージョン番号。 |
| `digestAlgorithm` | 使用されたメッセージダイジェストアルゴリズムの識別子。 |
| `encapContentInfo` | ダイジェスト化されたカプセル化コンテンツ。 |
| `digest` | 計算されたコンテンツのメッセージダイジェスト。 |

---

## EncryptedData

`EncryptedData` コンテンツタイプは、対称鍵を使用してデータを暗号化するために使用されます。`EnvelopedData` とは異なり、対称鍵を受信者に安全に配布するためのメカニズムを提供しません。鍵は、外部の帯域外チャネルを通じて管理する必要があります。

-   **目的**: 鍵管理が別途処理される場合のコンテンツの対称暗号化。
-   **主な特徴**: 送信者と受信者が既に共有秘密鍵を持っているシナリオで役立ちます。

### 構造

| フィールド | 説明 |
| :--- | :--- |
| `version` | 構文のバージョン番号。 |
| `encryptedContentInfo` | 暗号化されたコンテンツ、コンテンツ暗号化アルゴリズム、および暗号化されたコンテンツ自体を含みます。 |
| `unprotectedAttrs` | 暗号的に保護されていない属性のオプションのセット。 |

---

## AuthEnvelopedData

`AuthEnvelopedData` コンテンツタイプは認証付き暗号化を提供します。これは、機密性と完全性を単一の暗号化操作に組み合わせたモードです。通常、AES-GCM のような AEAD (Authenticated Encryption with Associated Data) 暗号と共に使用されます。

-   **目的**: コンテンツを暗号化すると同時に、完全性と真正性の保護を提供するため。
-   **主な特徴**: 暗号化と MAC を別々に適用する (例: Encrypt-then-MAC) よりも効率的で安全です。

### 構造

| フィールド | 説明 |
| :--- | :--- |
| `version` | 構文のバージョン番号。 |
| `originatorInfo` | `EnvelopedData` と同様の、送信者に関するオプションの情報。 |
| `recipientInfos` | コンテンツ暗号化キーを管理するための `RecipientInfo` 構造体のセット。 |
| `authEncryptedContentInfo` | 暗号化されたコンテンツと暗号化アルゴリズムを含みます。 |
| `authAttrs` | MAC 計算に含まれる認証付き属性のオプションのセット。 |
| `mac` | データの完全性と真正性を保証するメッセージ認証コード (タグ)。 |
| `unauthAttrs` | 認証されていない属性のオプションのセット。 |

## まとめ

6 つの CMS コンテンツタイプは、データを保護するための柔軟なツールキットを提供します。`Data` は基本であり、`SignedData` と `EnvelopedData` はそれぞれ署名と暗号化の主力です。`DigestedData`、`EncryptedData`、および `AuthEnvelopedData` は、完全性、単純な対称暗号化、および認証付き暗号化のための特化したソリューションを提供します。

`EnvelopedData` および `AuthEnvelopedData` における受信者の鍵管理方法についてさらに深く理解するには、[Recipient Info Types](./concepts-recipient-info-types.md) のセクションに進んでください。