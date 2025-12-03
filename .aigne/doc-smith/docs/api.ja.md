# APIリファレンス

このセクションでは、OpenSSLのCryptographic Message Syntax (CMS) の全公開APIについて、完全かつ検索可能なリファレンスを提供します。これまで文書化されていなかった関数を含むすべての関数の詳細なドキュメントを提供し、このライブラリを使用する開発者にとって決定的なガイドとなります。

APIは論理的なグループに整理されており、必要な関数をすばやく見つけることができます。高レベルの操作を行う場合でも、CMS構造に対するきめ細かな制御が必要な場合でも、このリファレンスには必要な詳細情報が含まれています。

CMSの概念的な説明については、[コアコンセプト](./concepts.md)のセクションを参照してください。タスク指向のワークフローについては、[ハウツーガイド](./guides.md)を参照してください。

## 機能カテゴリ

OpenSSL CMS APIは、機能に基づいていくつかのカテゴリに分類されています。以下に各カテゴリの概要と、その詳細なドキュメントへのリンクを示します。

<x-cards data-columns="2">
  <x-card data-title="主要な関数" data-icon="lucide:function-square" data-href="/api/main">
    CMSメッセージの署名、検証、暗号化、復号化といった一般的な操作のための高レベル関数。これらは最も頻繁に使用される関数です。
  </x-card>
  <x-card data-title="SignerInfo関数" data-icon="lucide:pen-tool" data-href="/api/signerinfo">
    SignerInfo構造を管理するための関数。署名者の追加、署名付きおよび署名なし属性の管理、低レベルの署名検証の実行などが含まれます。
  </x-card>
  <x-card data-title="RecipientInfo関数" data-icon="lucide:users" data-href="/api/recipientinfo">
    RecipientInfo構造を管理するための関数。さまざまな鍵管理タイプ（KTRI、KARIなど）の受信者の追加や、復号化鍵の処理などが含まれます。
  </x-card>
  <x-card data-title="属性と証明書のAPI" data-icon="lucide:files" data-href="/api/attributes-certs">
    CMS構造内の証明書、証明書失効リスト（CRL）、および属性を管理するための関数のコレクションです。
  </x-card>
  <x-card data-title="I/Oおよびデータ関数" data-icon="lucide:binary" data-href="/api/io-data">
    データストリーミング、I/O操作、およびData、DigestedData、CompressedDataなどのコンテンツタイプの直接管理のための関数をカバーしています。
  </x-card>
</x-cards>

## 主要なデータ構造

CMSの全機能は、いくつかの中心的なデータ構造を中心に展開されています。これらを理解することが、APIを効果的に使用するための鍵となります。以下の図は、これらの主要な構造間の関係を示しています。

<!-- DIAGRAM_IMAGE_START:intro:1:1 -->
![API Reference](assets/diagram/api-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

*   **`CMS_ContentInfo`**: CMSの最上位構造です。コンテンツタイプとコンテンツ自体をカプセル化します。すべてのCMSメッセージは、この構造に解析されるか、この構造から生成されます。
*   **`CMS_SignerInfo`**: 一人の署名者に関連するすべての情報を含みます。これには、署名者の証明書識別子、署名アルゴリズム、署名値、および署名付きまたは署名なし属性が含まれます。
*   **`CMS_RecipientInfo`**: 一人の受信者がコンテンツ暗号化キーを復号化するために必要な情報を含みます。使用される鍵管理技術に応じて、さまざまなタイプの`RecipientInfo`構造があります。

## 一般的なフラグ

多くのCMS関数は、その動作を変更する`flags`引数を受け入れます。これらのフラグは、ビット単位のOR演算子（`|`）を使用して組み合わせることができます。以下の表は、最も一般的なフラグとその目的をリストしたものです。

| Flag | Value | Description |
| :--- | :--- | :--- |
| `CMS_TEXT` | `0x1` | `text/plain`コンテンツタイプのためのMIMEヘッダーを追加します。 |
| `CMS_NOCERTS` | `0x2` | 署名時、署名者の証明書をメッセージに含めません。 |
| `CMS_NO_CONTENT_VERIFY` | `0x4` | 検証時、コンテンツの署名を検証しません。 |
| `CMS_NO_ATTR_VERIFY` | `0x8` | 検証時、署名付き属性の署名を検証しません。 |
| `CMS_NOINTERN` | `0x10` | 検証時、メッセージ自体から署名者の証明書を検索しません。 |
| `CMS_NO_SIGNER_CERT_VERIFY` | `0x20` | 署名者の証明書チェーンを検証しません。 |
| `CMS_DETACHED` | `0x40` | コンテンツが`SignedData`構造に含まれない分離署名を作成します。 |
| `CMS_BINARY` | `0x80` | コンテンツに対してMIMEの正規化を行いません。バイナリデータに使用します。 |
| `CMS_NOATTR` | `0x100` | 署名付き属性を一切含めません。これにより、より単純な署名が作成されますが、署名時刻などのコンテキストが失われます。 |
| `CMS_NOSMIMECAP` | `0x200` | S/MIME capabilities署名付き属性を省略します。 |
| `CMS_CRLFEOL` | `0x800` | テキストベースのMIMEコンテンツの行末としてCRLFを使用します。 |
| `CMS_STREAM` | `0x1000` | データがストリーミングされていることを示し、ストリーミングI/O操作を有効にします。 |
| `CMS_NOCRL` | `0x2000` | `SignedData`構造にCRLsを一切含めません。 |
| `CMS_USE_KEYID` | `0x10000` | 発行者とシリアル番号の代わりに、サブジェクトキー識別子を使用して証明書を識別します。 |
| `CMS_DEBUG_DECRYPT` | `0x20000` | 復号化操作中にデバッグ出力を有効にし、エラーの診断を支援します。 |
| `CMS_CADES` | `0x100000` | 署名に対してCAdES（CMS Advanced Electronic Signatures）準拠を有効にします。 |

## まとめ

このAPIリファレンスは、OpenSSL CMSライブラリを使用する開発者のための包括的なリソースとなるように設計されています。各サブセクションでは、詳細な関数プロトタイプ、パラメータの説明、戻り値、および使用上の注意が提供されています。ナビゲーションを使用してさまざまな機能カテゴリを探索し、実装に必要な特定のツールを見つけてください。