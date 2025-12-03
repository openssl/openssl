# Attribute & Cert API

本节详细介绍了在 Cryptographic Message Syntax (CMS) 结构中管理属性、证书和证书吊销列表 (CRL) 的函数。这些组件对于构建可验证的信任链至关重要，因为它们携带了签名验证所需的元数据，包括签名者证书和吊销状态。正确管理这些元素对于创建合规且安全的消息至关重要。

下图说明了 API 函数与其管理的 CMS 结构之间的关系：

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![Attribute & Cert API](./assets/diagram/api-attributes-certs-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## 属性管理

属性提供有关签名者或签名的附加信息。它们分为签名属性和未签名属性。签名属性是经过数字签名的数据的一部分，可防止其被修改，而未签名属性则不是。

### 签名属性函数

签名属性存储在 `SignerInfo` 结构中，并通过加密方式与签名绑定。常见的签名属性包括内容类型、签名时间和消息摘要。

<x-field-group>
  <x-field data-name="CMS_signed_get_attr_count()" data-type="int">
    <x-field-desc markdown>检索 `CMS_SignerInfo` 结构中签名属性的总数。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性数量，错误时返回 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr_by_NID()" data-type="int">
    <x-field-desc markdown>通过 NID（例如 `NID_pkcs9_signingTime`）查找签名属性的位置。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="nid" data-type="int" data-required="true" data-desc="要查找的属性的 NID。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="起始搜索位置。首次调用时使用 -1。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性的位置索引，如果未找到则返回 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr_by_OBJ()" data-type="int">
    <x-field-desc markdown>通过 ASN.1 OBJECT 标识符查找签名属性的位置。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="obj" data-type="const ASN1_OBJECT *" data-required="true" data-desc="属性的 ASN.1 OBJECT。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="起始搜索位置。首次调用时使用 -1。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性的位置索引，如果未找到则返回 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_get_attr()" data-type="X509_ATTRIBUTE *">
    <x-field-desc markdown>检索特定位置索引处的签名属性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="loc" data-type="int" data-required="true" data-desc="属性的位置索引。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="X509_ATTRIBUTE *" data-desc="指向属性的指针，错误时返回 NULL。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_add1_attr()" data-type="int">
    <x-field-desc markdown>将一个已存在的 `X509_ATTRIBUTE` 结构添加为签名属性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="attr" data-type="X509_ATTRIBUTE *" data-required="true" data-desc="要添加的属性。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失败返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_signed_add1_attr_by_txt()" data-type="int">
    <x-field-desc markdown>使用字符串表示（例如 "signingTime"）创建并添加一个签名属性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="attrname" data-type="const char *" data-required="true" data-desc="对象名称。"></x-field>
      <x-field data-name="type" data-type="int" data-required="true" data-desc="数据的 ASN.1 类型（例如 `V_ASN1_UTCTIME`）。"></x-field>
      <x-field data-name="bytes" data-type="const void *" data-required="true" data-desc="指向属性数据的指针。"></x-field>
      <x-field data-name="len" data-type="int" data-required="true" data-desc="属性数据的长度。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失败返回 0。"></x-field>
  </x-field>
</x-field-group>

### 未签名属性函数

未签名属性与 `SignerInfo` 结构相关联，但不是签名计算的一部分。它们可以被添加或移除而不会使签名失效。一个常见的例子是副署（countersignature）。

<x-field-group>
  <x-field data-name="CMS_unsigned_get_attr_count()" data-type="int">
    <x-field-desc markdown>检索 `CMS_SignerInfo` 结构中未签名属性的总数。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性数量，错误时返回 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr_by_NID()" data-type="int">
    <x-field-desc markdown>通过 NID 查找未签名属性的位置。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="nid" data-type="int" data-required="true" data-desc="要查找的属性的 NID。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="起始搜索位置。首次调用时使用 -1。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性的位置索引，如果未找到则返回 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr_by_OBJ()" data-type="int">
    <x-field-desc markdown>通过 ASN.1 OBJECT 标识符查找未签名属性的位置。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="SignerInfo 结构。"></x-field>
      <x-field data-name="obj" data-type="const ASN1_OBJECT *" data-required="true" data-desc="属性的 ASN.1 OBJECT。"></x-field>
      <x-field data-name="lastpos" data-type="int" data-required="true" data-desc="起始搜索位置。首次调用时使用 -1。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="属性的位置索引，如果未找到则返回 -1。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_get_attr()" data-type="X509_ATTRIBUTE *">
    <x-field-desc markdown>检索特定位置索引处的未签名属性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="const CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="loc" data-type="int" data-required="true" data-desc="属性的位置索引。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="X509_ATTRIBUTE *" data-desc="指向属性的指针，错误时返回 NULL。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_add1_attr()" data-type="int">
    <x-field-desc markdown>将一个已存在的 `X509_ATTRIBUTE` 结构添加为未签名属性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="attr" data-type="X509_ATTRIBUTE *" data-required="true" data-desc="要添加的属性。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失败返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_unsigned_add1_attr_by_txt()" data-type="int">
    <x-field-desc markdown>使用字符串表示创建并添加一个未签名属性。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="si" data-type="CMS_SignerInfo *" data-required="true" data-desc="指向 SignerInfo 结构的指针。"></x-field>
      <x-field data-name="attrname" data-type="const char *" data-required="true" data-desc="对象名称。"></x-field>
      <x-field data-name="type" data-type="int" data-required="true" data-desc="数据的 ASN.1 类型。"></x-field>
      <x-field data-name="bytes" data-type="const void *" data-required="true" data-desc="指向属性数据的指针。"></x-field>
      <x-field data-name="len" data-type="int" data-required="true" data-desc="属性数据的长度。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失败返回 0。"></x-field>
  </x-field>
</x-field-group>

## 证书管理

CMS 消息可以嵌入验证其签名所需的证书。这些函数允许您将证书添加到 `SignedData` 或 `EnvelopedData` 结构中的 `certificates` 集合。

<x-field-group>
  <x-field data-name="CMS_add0_cert()" data-type="int">
    <x-field-desc markdown>向 CMS 结构中添加一个证书。CMS 结构将获得证书指针的所有权，因此不应单独释放它。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 结构的指针。"></x-field>
      <x-field data-name="cert" data-type="X509 *" data-required="true" data-desc="要添加的证书。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失败返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_add1_cert()" data-type="int">
    <x-field-desc markdown>通过复制的方式向 CMS 结构中添加一个证书。调用者保留原始证书指针的所有权。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 结构的指针。"></x-field>
      <x-field data-name="cert" data-type="X509 *" data-required="true" data-desc="要添加的证书。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失败返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_get1_certs()" data-type="STACK_OF(X509) *">
    <x-field-desc markdown>从 CMS 结构中检索所有证书的副本。返回的堆栈及其内容必须由调用者释放。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 结构的指针。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="STACK_OF(X509) *" data-desc="一个证书堆栈，错误时返回 NULL。"></x-field>
  </x-field>
</x-field-group>

## 证书吊销列表 (CRL) 管理

为确保证书未被吊销，可以在 CMS 消息中包含 CRL。这些函数管理 `SignedData` 结构中的 `crls` 集合。

<x-field-group>
  <x-field data-name="CMS_add0_crl()" data-type="int">
    <x-field-desc markdown>向 CMS 结构中添加一个 CRL。CMS 结构将获得 CRL 指针的所有权，因此不应单独释放它。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 结构的指针。"></x-field>
      <x-field data-name="crl" data-type="X509_CRL *" data-required="true" data-desc="要添加的 CRL。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失败返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_add1_crl()" data-type="int">
    <x-field-desc markdown>通过复制的方式向 CMS 结构中添加一个 CRL。调用者保留原始 CRL 指针的所有权。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 结构的指针。"></x-field>
      <x-field data-name="crl" data-type="X509_CRL *" data-required="true" data-desc="要添加的 CRL。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="int" data-desc="成功返回 1，失败返回 0。"></x-field>
  </x-field>
  <x-field data-name="CMS_get1_crls()" data-type="STACK_OF(X509_CRL) *">
    <x-field-desc markdown>从 CMS 结构中检索所有 CRL 的副本。返回的堆栈及其内容必须由调用者释放。</x-field-desc>
    <x-field data-name="parameters" data-type="object">
      <x-field data-name="cms" data-type="CMS_ContentInfo *" data-required="true" data-desc="指向 CMS_ContentInfo 结构的指针。"></x-field>
    </x-field>
    <x-field data-name="returnValue" data-type="STACK_OF(X509_CRL) *" data-desc="一个 CRL 堆栈，错误时返回 NULL。"></x-field>
  </x-field>
</x-field-group>

## 总结

本节详述的函数提供了一个完整的工具集，用于管理 CMS 消息附带的辅助信息。使用属性函数向签名添加签名或未签名的元数据，并使用证书和 CRL 函数将必要的验证材料直接嵌入 CMS 结构中。

有关管理签名者和签名的相关信息，请参阅 [SignerInfo Functions](./api-signerinfo.md) 文档。有关更高级别的操作，请参阅 [Main Functions](./api-main.md) 指南。