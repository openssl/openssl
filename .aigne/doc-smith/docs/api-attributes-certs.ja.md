# 属性および証明書 API

このセクションでは、Cryptographic Message Syntax (CMS) 構造内の属性、証明書、および証明書失効リスト (CRL) を管理する関数の詳細なリファレンスを提供します。これらのコンポーネントは、署名者の証明書や失効ステータスなど、署名検証に必要なメタデータを保持するため、検証可能な信頼チェーンを構築する上で不可欠です。これらの要素を適切に管理することは、準拠した安全なメッセージを作成するために不可欠です。

次の図は、API 関数とそれらが管理する CMS 構造との関係を示しています。

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![Attribute & Cert API](./assets/diagram/api-attributes-certs-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## 属性管理

属性は、署名者または署名に関する追加情報を提供します。これらは署名付き属性と非署名属性に分類されます。署名付き属性はデジタル署名されるデータの一部であり、改ざんから保護されますが、非署名属性は保護されません。

### 署名付き属性関数

署名付き属性は `SignerInfo` 構造内に格納され、暗号学的に署名に結び付けられます。一般的な署名付き属性には、コンテンツタイプ、署名時刻、メッセージダイジェストなどがあります。

<x-field-group>
  <x-field data-name="CMS_signed_get_attr_count()" data-type="int">
    <x-field-desc markdown>`CMS_SignerInfo` 構造内の署名付き属性の総数を取得します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性の数。エラーの場合は -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr_by_NID()" data-type="int">
    <x-field-desc markdown>NID (例: `NID_pkcs9_signingTime`) を使用して署名付き属性の場所を検索します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="nid" data-type="int" data-required="true" data-desc="検索する属性の NID。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="検索を開始する位置。最初の呼び出しには -1 を使用します。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性の場所のインデックス。見つからない場合は -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr_by_OBJ()" data-type="int">
    <x-field-desc markdown>ASN.1 OBJECT 識別子を使用して署名付き属性の場所を検索します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="obj" data-type="const ASN1_OBJECT *" data-required="true" data-desc="属性の ASN.1 OBJECT。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="検索を開始する位置。最初の呼び出しには -1 を使用します。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性の場所のインデックス。見つからない場合は -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr()" data-type="X509_ATTRIBUTE *">
    <x-field-desc markdown>特定の場所のインデックスにある署名付き属性を取得します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="loc" data-type="int" data-required="true" data-desc="属性の場所のインデックス。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="X509_ATTRIBUTE *" data-desc="属性へのポインタ。エラーの場合は NULL。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_add1_attr()" data-type="int">
    <x-field-desc markdown>既存の `X509_ATTRIBUTE` 構造体を署名付き属性として追加します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="attr" data-type="X509_ATTRIBUTE *" data-required="true" data-desc="追加する属性。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功した場合は 1、失敗した場合は 0 を返します。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_add1_attr_by_txt()" data-type="int">
    <x-field-desc markdown>文字列表現 (例: "signingTime") を使用して署名付き属性を作成し、追加します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="attrname" data-type="const char *" data-required="true" data-desc="オブジェクト名。"></x-field>
      <x-field data-name="type" data-type="int" data-required="true" data-desc="データの ASN.1 型 (例: `V_ASN1_UTCTIME`)。"></x-field>
      <x-field data-name="bytes" data-type="const void *" data-required="true" data-desc="属性データへのポインタ。"></x-field>
      <x-field data-name="len" data-type="int" data-required="true" data-desc="属性データの長さ。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功した場合は 1、失敗した場合は 0 を返します。"></x-field>
  </x-field>
</x-field-group>

### 非署名属性関数

非署名属性は `SignerInfo` 構造体に関連付けられますが、署名計算の一部ではありません。署名を無効にすることなく追加または削除できます。一般的な例は副署です。

<x-field-group>
  <x-field data-name="CMS_unsigned_get_attr_count()" data-type="int">
    <x-field-desc markdown>`CMS_SignerInfo` 構造内の非署名属性の総数を取得します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性の数。エラーの場合は -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr_by_NID()" data-type="int">
    <x-field-desc markdown>NID を使用して非署名属性の場所を検索します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="nid" data-type="int" data-required="true" data-desc="検索する属性の NID。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="検索を開始する位置。最初の呼び出しには -1 を使用します。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性の場所のインデックス。見つからない場合は -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr_by_OBJ()" data-type="int">
    <x-field-desc markdown>ASN.1 OBJECT 識別子を使用して非署名属性の場所を検索します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体。"></x-field>
      <x-field data-name="obj" data-type="const ASN1_OBJECT *" data-required="true" data-desc="属性の ASN.1 OBJECT。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="検索を開始する位置。最初の呼び出しには -1 を使用します。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性の場所のインデックス。見つからない場合は -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr()" data-type="X509_ATTRIBUTE *">
    <x-field-desc markdown>特定の場所のインデックスにある非署名属性を取得します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="loc" data-type="int" data-required="true" data-desc="属性の場所のインデックス。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="X509_ATTRIBUTE *" data-desc="属性へのポインタ。エラーの場合は NULL。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_add1_attr()" data-type="int">
    <x-field-desc markdown>既存の `X509_ATTRIBUTE` 構造体を非署名属性として追加します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="attr" data-type="X509_ATTRIBUTE *" data-required="true" data-desc="追加する属性。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功した場合は 1、失敗した場合は 0 を返します。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_add1_attr_by_txt()" data-type="int">
    <x-field-desc markdown>文字列表現を使用して非署名属性を作成し、追加します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="attrname" data-type="const char *" data-required="true" data-desc="オブジェクト名。"></x-field>
      <x-field data-name="type" data-type="int" data-required="true" data-desc="データの ASN.1 型。"></x-field>
      <x-field data-name="bytes" data-type="const void *" data-required="true" data-desc="属性データへのポインタ。"></x-field>
      <x-field data-name="len" data-type="int" data-required="true" data-desc="属性データの長さ。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功した場合は 1、失敗した場合は 0 を返します。"></x-field>
  </x-field>
</x-field-group>

## 証明書管理

CMS メッセージには、その署名を検証するために必要な証明書を埋め込むことができます。これらの関数を使用すると、`SignedData` または `EnvelopedData` 構造体の `certificates` セットに証明書を追加できます。

<x-field-group>
  <x-field data-name="CMS_add0_cert()" data-type="int">
    <x-field-desc markdown>証明書を CMS 構造体に追加します。CMS 構造体が証明書ポインタの所有権を取得するため、別途解放しないでください。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="CMS_ContentInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="cert" data-type="X509 *" data-required="true" data-desc="追加する証明書。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功した場合は 1、失敗した場合は 0 を返します。"></x-field>
  </x-field>
  <x-field data-name="CMS_add1_cert()" data-type="int">
    <x-field-desc markdown>証明書を複製して CMS 構造体に追加します。呼び出し元は元の証明書ポインタの所有権を保持します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="CMS_ContentInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="cert" data-type="X509 *" data-required="true" data-desc="追加する証明書。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功した場合は 1、失敗した場合は 0 を返します。"></x-field>
  </x-field>
  <x-field data-name="CMS_get1_certs()" data-type="STACK_OF(X509) *">
    <x-field-desc markdown>CMS 構造体からすべての証明書のコピーを取得します。返されたスタックとその内容は、呼び出し元が解放する必要があります。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="CMS_ContentInfo 構造体へのポインタです。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="STACK_OF(X509) *" data-desc="証明書のスタック。エラーの場合は NULL。"></x-field>
  </x-field>
</x-field-group>

## 証明書失効リスト (CRL) 管理

証明書が失効していないことを確認するために、CRL を CMS メッセージに含めることができます。これらの関数は、`SignedData` 構造内の `crls` セットを管理します。

<x-field-group>
  <x-field data-name="CMS_add0_crl()" data-type="int">
    <x-field-desc markdown>CRL を CMS 構造体に追加します。CMS 構造体が CRL ポインタの所有権を取得するため、別途解放しないでください。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="CMS_ContentInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="crl" data-type="X509_CRL *" data-required="true" data-desc="追加する CRL。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功した場合は 1、失敗した場合は 0 を返します。"></x-field>
  </x-field>
  <x-field data-name="CMS_add1_crl()" data-type="int">
    <x-field-desc markdown>CRL を複製して CMS 構造体に追加します。呼び出し元は元の CRL ポインタの所有権を保持します。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="CMS_ContentInfo 構造体へのポインタです。"></x-field>
      <x-field data-name="crl" data-type="X509_CRL *" data-required="true" data-desc="追加する CRL。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功した場合は 1、失敗した場合は 0 を返します。"></x-field>
  </x-field>
  <x-field data-name="CMS_get1_crls()" data-type="STACK_OF(X509_CRL) *">
    <x-field-desc markdown>CMS 構造体からすべての CRL のコピーを取得します。返されたスタックとその内容は、呼び出し元が解放する必要があります。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="CMS_ContentInfo 構造体へのポインタです。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="STACK_OF(X509_CRL) *" data-desc="CRL のスタック。エラーの場合は NULL。"></x-field>
  </x-field>
</x-field-group>

## まとめ

このセクションで詳述した関数は、CMS メッセージに付随する補助情報を管理するための完全なツールキットを提供します。属性関数を使用して署名付きまたは非署名のメタデータを署名に追加し、証明書および CRL 関数を使用して必要な検証資料を CMS 構造内に直接埋め込みます。

署名者と署名の管理に関する関連情報については、[SignerInfo 関数](./api-signerinfo.md) のドキュメントを参照してください。より高レベルの操作については、[メイン関数](./api-main.md) ガイドを参照してください。