# 屬性與憑證 API

本節提供在加密訊息語法 (Cryptographic Message Syntax, CMS) 結構內管理屬性、憑證和憑證撤銷清冊 (Certificate Revocation Lists, CRLs) 的函式詳細參考。這些元件對於建立可驗證的信任鏈至關重要，因為它們攜帶了簽章驗證所需的元數據，包括簽署者憑證和撤銷狀態。妥善管理這些元素對於建立合規且安全的消息至關重要。

下圖說明了 API 函式與其所管理的 CMS 結構之間的關係：

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![Attribute & Cert API](./assets/diagram/api-attributes-certs-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## 屬性管理

屬性提供關於簽署者或簽章的額外資訊。它們分為已簽署和未簽署兩類。已簽署屬性是經過數位簽章的資料的一部分，可防止被修改，而未簽署屬性則不是。

### 已簽署屬性函式

已簽署屬性儲存在 `SignerInfo` 結構中，並透過密碼學方式與簽章綁定。常見的已簽署屬性包括內容類型、簽署時間和訊息摘要。

<x-field-group>
  <x-field data-name="CMS_signed_get_attr_count()" data-type="int">
    <x-field-desc markdown>擷取 `CMS_SignerInfo` 結構中已簽署屬性的總數。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="屬性數量，若發生錯誤則為 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr_by_NID()" data-type="int">
    <x-field-desc markdown>透過 NID（例如 `NID_pkcs9_signingTime`）尋找已簽署屬性的位置。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="nid" data-type="int" data-required="true" data-desc="要尋找的屬性的 NID。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="起始搜尋位置。首次呼叫請使用 -1。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="屬性位置索引，若未找到則為 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr_by_OBJ()" data-type="int">
    <x-field-desc markdown>透過其 ASN.1 OBJECT 識別碼尋找已簽署屬性的位置。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="obj" data-type="const ASN1_OBJECT *" data-required="true" data-desc="屬性的 ASN.1 OBJECT。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="起始搜尋位置。首次呼叫請使用 -1。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="屬性位置索引，若未找到則為 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr()" data-type="X509_ATTRIBUTE *">
    <x-field-desc markdown>擷取指定位置索引的已簽署屬性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="loc" data-type="int" data-required="true" data-desc="屬性的位置索引。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="X509_ATTRIBUTE *" data-desc="指向屬性的指標，若發生錯誤則為 NULL。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_add1_attr()" data-type="int">
    <x-field-desc markdown>將一個已存在的 `X509_ATTRIBUTE` 結構新增為已簽署屬性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="attr" data-type="X509_ATTRIBUTE *" data-required="true" data-desc="要新增的屬性。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失敗返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_add1_attr_by_txt()" data-type="int">
    <x-field-desc markdown>使用其字串表示（例如 "signingTime"）建立並新增一個已簽署屬性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="attrname" data-type="const char *" data-required="true" data-desc="物件名稱。"></x-field>
      <x-field data-name="type" data-type="int" data-required="true" data-desc="資料的 ASN.1 類型（例如 `V_ASN1_UTCTIME`）。"></x-field>
      <x-field data-name="bytes" data-type="const void *" data-required="true" data-desc="指向屬性資料的指標。"></x-field>
      <x-field data-name="len" data-type="int" data-required="true" data-desc="屬性資料的長度。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失敗返回 0。"></x-field>
  </x-field>
</x-field-group>

### 未簽署屬性函式

未簽署屬性與 `SignerInfo` 結構相關聯，但不是簽章計算的一部分。它們可以被新增或移除而不會使簽章失效。一個常見的例子是計數器簽章 (countersignature)。

<x-field-group>
  <x-field data-name="CMS_unsigned_get_attr_count()" data-type="int">
    <x-field-desc markdown>擷取 `CMS_SignerInfo` 結構中未簽署屬性的總數。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="屬性數量，若發生錯誤則為 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr_by_NID()" data-type="int">
    <x-field-desc markdown>透過其 NID 尋找未簽署屬性的位置。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="nid" data-type="int" data-required="true" data-desc="要尋找的屬性的 NID。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="起始搜尋位置。首次呼叫請使用 -1。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="屬性位置索引，若未找到則為 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr_by_OBJ()" data-type="int">
    <x-field-desc markdown>透過其 ASN.1 OBJECT 識別碼尋找未簽署屬性的位置。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 結構。"></x-field>
      <x-field data-name="obj" data-type="const ASN1_OBJECT *" data-required="true" data-desc="屬性的 ASN.1 OBJECT。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="起始搜尋位置。首次呼叫請使用 -1。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="屬性位置索引，若未找到則為 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr()" data-type="X509_ATTRIBUTE *">
    <x-field-desc markdown>擷取指定位置索引的未簽署屬性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="loc" data-type="int" data-required="true" data-desc="屬性的位置索引。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="X509_ATTRIBUTE *" data-desc="指向屬性的指標，若發生錯誤則為 NULL。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_add1_attr()" data-type="int">
    <x-field-desc markdown>將一個已存在的 `X509_ATTRIBUTE` 結構新增為未簽署屬性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="attr" data-type="X509_ATTRIBUTE *" data-required="true" data-desc="要新增的屬性。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失敗返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_add1_attr_by_txt()" data-type="int">
    <x-field-desc markdown>使用其字串表示建立並新增一個未簽署屬性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 結構的指標。"></x-field>
      <x-field data-name="attrname" data-type="const char *" data-required="true" data-desc="物件名稱。"></x-field>
      <x-field data-name="type" data-type="int" data-required="true" data-desc="資料的 ASN.1 類型。"></x-field>
      <x-field data-name="bytes" data-type="const void *" data-required="true" data-desc="指向屬性資料的指標。"></x-field>
      <x-field data-name="len" data-type="int" data-required="true" data-desc="屬性資料的長度。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失敗返回 0。"></x-field>
  </x-field>
</x-field-group>

## 憑證管理

CMS 訊息可以嵌入驗證其簽章所需的憑證。這些函式允許您將憑證新增到 `SignedData` 或 `EnvelopedData` 結構中的 `certificates` 集合。

<x-field-group>
  <x-field data-name="CMS_add0_cert()" data-type="int">
    <x-field-desc markdown>將一個憑證新增到 CMS 結構中。CMS 結構會取得該憑證指標的所有權，因此不應單獨釋放它。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 結構的指標。"></x-field>
      <x-field data-name="cert" data-type="X509 *" data-required="true" data-desc="要新增的憑證。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失敗返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_add1_cert()" data-type="int">
    <x-field-desc markdown>透過複製的方式將一個憑證新增到 CMS 結構中。呼叫者保留原始憑證指標的所有權。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 結構的指標。"></x-field>
      <x-field data-name="cert" data-type="X509 *" data-required="true" data-desc="要新增的憑證。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失敗返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_get1_certs()" data-type="STACK_OF(X509) *">
    <x-field-desc markdown>從 CMS 結構中擷取所有憑證的副本。返回的堆疊及其內容必須由呼叫者釋放。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 結構的指標。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="STACK_OF(X509) *" data-desc="一個憑證堆疊，若發生錯誤則為 NULL。"></x-field>
  </x-field>
</x-field-group>

## 憑證撤銷清冊 (CRL) 管理

為確保憑證未被撤銷，可以在 CMS 訊息中包含 CRL。這些函式管理 `SignedData` 結構中的 `crls` 集合。

<x-field-group>
  <x-field data-name="CMS_add0_crl()" data-type="int">
    <x-field-desc markdown>將一個 CRL 新增到 CMS 結構中。CMS 結構會取得該 CRL 指標的所有權，因此不應單獨釋放它。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 結構的指標。"></x-field>
      <x-field data-name="crl" data-type="X509_CRL *" data-required="true" data-desc="要新增的 CRL。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失敗返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_add1_crl()" data-type="int">
    <x-field-desc markdown>透過複製的方式將一個 CRL 新增到 CMS 結構中。呼叫者保留原始 CRL 指標的所有權。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 結構的指標。"></x-field>
      <x-field data-name="crl" data-type="X509_CRL *" data-required="true" data-desc="要新增的 CRL。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失敗返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_get1_crls()" data-type="STACK_OF(X509_CRL) *">
    <x-field-desc markdown>從 CMS 結構中擷取所有 CRL 的副本。返回的堆疊及其內容必須由呼叫者釋放。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 結構的指標。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="STACK_OF(X509_CRL) *" data-desc="一個 CRL 堆疊，若發生錯誤則為 NULL。"></x-field>
  </x-field>
</x-field-group>

## 總結

本節詳述的函式提供了一套完整的工具組，用於管理 CMS 訊息附帶的輔助資訊。使用屬性函式向簽章新增已簽署或未簽署的元數據，並利用憑證和 CRL 函式將必要的驗證材料直接嵌入 CMS 結構中。

有關管理簽署者和簽章的相關資訊，請參閱 [SignerInfo 函式](./api-signerinfo.md) 文件。有關更高層級的操作，請參閱 [主要函式](./api-main.md) 指南。