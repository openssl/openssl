# 主要函数

本节为用于创建、解析、定版和管理核心加密消息语法（CMS）结构的高级函数提供了详细参考。这些函数是签名、验证、加密和解密数据等常见操作的主要入口点。

下图阐明了用于签名/验证和加密/解密数据流的主要 CMS 函数之间的关系。

<!-- DIAGRAM_IMAGE_START:flowchart:16:9 -->
![主要函数](./assets/diagram/api-main-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## 签名与验证

这些函数处理 CMS `SignedData` 结构的创建和验证，这对于确保数据完整性和真实性至关重要。

### CMS_sign

`CMS_sign()` 和 `CMS_sign_ex()` 函数创建一个 `SignedData` 类型的 `CMS_ContentInfo` 结构。此操作涉及使用私钥对数据进行签名，并包含相应的证书以及任何附加证书，以形成一个完整、可验证的消息。

#### 摘要

```c
#include <openssl/cms.h>

CMS_ContentInfo *CMS_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                          BIO *data, unsigned int flags);

CMS_ContentInfo *CMS_sign_ex(X509 *signcert, EVP_PKEY *pkey,
                             STACK_OF(X509) *certs, BIO *data,
                             unsigned int flags, OSSL_LIB_CTX *libctx,
                             const char *propq);
```

#### 参数

<x-field-group>
  <x-field data-name="signcert" data-type="X509*" data-required="false" data-desc="签名者的证书。对于纯证书结构，可以为 NULL。"></x-field>
  <x-field data-name="pkey" data-type="EVP_PKEY*" data-required="false" data-desc="与 signcert 对应的私钥。对于纯证书结构，可以为 NULL。"></x-field>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="false" data-desc="一个可选的附加证书栈，用于包含在结构中，例如中间 CA。"></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="true" data-desc="一个包含待签名数据的 BIO。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="用于控制签名操作的标志位掩码。"></x-field>
  <x-field data-name="libctx" data-type="OSSL_LIB_CTX*" data-required="false" data-desc="一个 OpenSSL 库上下文（用于 CMS_sign_ex）。如果为 NULL，则使用默认上下文。"></x-field>
  <x-field data-name="propq" data-type="const char*" data-required="false" data-desc="用于算法获取的属性查询字符串（用于 CMS_sign_ex）。"></x-field>
</x-field-group>

#### 标志

`flags` 参数用于修改签名操作的行为。可以使用按位或（OR）组合多个标志。

| 标志 | 说明 |
| --- | --- |
| `CMS_TEXT` | 在内容前添加标准的 `text/plain` MIME 头。 |
| `CMS_NOCERTS` | 从 `SignedData` 结构中排除签名者的证书。该证书在 `signcert` 参数中仍然是签名所必需的。 |
| `CMS_DETACHED` | 创建一个分离式签名，其中内容不包含在最终的 `CMS_ContentInfo` 结构中。 |
| `CMS_BINARY` | 防止对内容进行 MIME 规范化。这对于避免二进制数据损坏至关重要。 |
| `CMS_NOATTR` | 排除所有签名属性，包括签名时间和 SMIMECapabilities。 |
| `CMS_NOSMIMECAP` | 省略 `SMIMECapabilities` 签名属性。 |
| `CMS_NO_SIGNING_TIME` | 省略签名时间属性。 |
| `CMS_USE_KEYID` | 通过签名者证书的主题密钥标识符而不是默认的颁发者和序列号来识别签名者。 |
| `CMS_STREAM` | 为流式处理初始化 `CMS_ContentInfo` 结构，但推迟实际的签名操作。数据在定版期间被读取和处理。 |
| `CMS_PARTIAL` | 创建一个部分的 `CMS_ContentInfo` 结构，允许在调用 `CMS_final()` 之前添加更多签名者或属性。 |

#### 返回值

成功时返回一个有效的 `CMS_ContentInfo` 结构，失败时返回 `NULL`。可以从 OpenSSL 错误队列中检索错误。

### CMS_verify

`CMS_verify()` 函数验证一个 CMS `SignedData` 结构。它检查签名内容的完整性，验证签名者的签名，并可选择性地根据受信任的存储区验证签名者的证书链。

#### 摘要

```c
#include <openssl/cms.h>

int CMS_verify(CMS_ContentInfo *cms, STACK_OF(X509) *certs, X509_STORE *store,
               BIO *detached_data, BIO *out, unsigned int flags);
```

#### 参数

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="要验证的 CMS_ContentInfo 结构。"></x-field>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="false" data-desc="一个可选的非受信证书栈，用于搜索签名者证书并辅助证书链构建。"></x-field>
  <x-field data-name="store" data-type="X509_STORE*" data-required="false" data-desc="用于路径验证的受信任证书存储区。"></x-field>
  <x-field data-name="detached_data" data-type="BIO*" data-required="false" data-desc="如果签名是分离式的，则此 BIO 包含内容。对于内嵌式签名，应为 NULL。"></x-field>
  <x-field data-name="out" data-type="BIO*" data-required="false" data-desc="一个用于写入已验证内容的 BIO。如果为 NULL，内容将被读取和验证但不会被写入。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="用于控制验证操作的标志位掩码。"></x-field>
</x-field-group>

#### 标志

| 标志 | 说明 |
| --- | --- |
| `CMS_NOINTERN` | 阻止在 CMS 结构内部搜索签名者证书。证书必须在 `certs` 参数中提供。 |
| `CMS_TEXT` | 从内容中剥离 `text/plain` MIME 头。如果内容类型不是 `text/plain`，则会发生错误。 |
| `CMS_NO_SIGNER_CERT_VERIFY` | 跳过对签名者证书的证书链验证。 |
| `CMS_NO_ATTR_VERIFY` | 跳过对签名属性的签名验证。 |
| `CMS_NO_CONTENT_VERIFY` | 跳过对内容摘要的验证。这意味着会检查签名，但不会根据签名验证内容本身。 |
| `CMS_NOCRL` | 在证书验证期间忽略 CMS 结构中存在的任何 CRL。 |
| `CMS_CADES` | 启用 CAdES 特定的检查，例如验证 `signingCertificate` 或 `signingCertificateV2` 属性。 |

#### 返回值

验证成功返回 `1`，失败返回 `0`。可以从 OpenSSL 错误队列中检索详细的错误信息。

### CMS_get0_signers

这个实用函数从 `CMS_ContentInfo` 结构中检索所有签名者的证书。它只应在成功验证后调用，因为验证过程负责定位证书并将其与每个 `SignerInfo` 关联起来。

#### 摘要

```c
#include <openssl/cms.h>

STACK_OF(X509) *CMS_get0_signers(CMS_ContentInfo *cms);
```

#### 参数

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="成功验证的 CMS 结构。"></x-field>
</x-field-group>

#### 返回值

返回一个指向内部 `STACK_OF(X509)` 的指针，其中包含签名者的证书。应用程序不应释放此指针。如果发生错误或未找到签名者，则返回 `NULL`。

## 加密与解密

这些函数用于为单个或多个接收者创建和解析 `EnvelopedData` 结构，以加密和解密数据。

### CMS_encrypt

`CMS_encrypt()` 和 `CMS_encrypt_ex()` 函数创建一个 `EnvelopedData` 或 `AuthEnvelopedData` 类型的 `CMS_ContentInfo` 结构。内容使用一个随机生成的对称密钥进行加密，然后通过用每个接收者的公钥加密该对称密钥，将其安全地分发给每个接收者。

#### 摘要

```c
#include <openssl/cms.h>

CMS_ContentInfo *CMS_encrypt(STACK_OF(X509) *certs, BIO *in,
                             const EVP_CIPHER *cipher, unsigned int flags);

CMS_ContentInfo *CMS_encrypt_ex(STACK_OF(X509) *certs, BIO *in,
                                const EVP_CIPHER *cipher, unsigned int flags,
                                OSSL_LIB_CTX *libctx, const char *propq);
```

#### 参数

<x-field-group>
  <x-field data-name="certs" data-type="STACK_OF(X509)*" data-required="true" data-desc="一个接收者证书栈。"></x-field>
  <x-field data-name="in" data-type="BIO*" data-required="true" data-desc="一个包含待加密数据的 BIO。"></x-field>
  <x-field data-name="cipher" data-type="const EVP_CIPHER*" data-required="true" data-desc="用于内容加密的对称密码算法（例如，EVP_aes_256_cbc()）。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="用于控制加密操作的标志位掩码。"></x-field>
  <x-field data-name="libctx" data-type="OSSL_LIB_CTX*" data-required="false" data-desc="一个 OpenSSL 库上下文（用于 CMS_encrypt_ex）。如果为 NULL，则使用默认上下文。"></x-field>
  <x-field data-name="propq" data-type="const char*" data-required="false" data-desc="用于算法获取的属性查询字符串（用于 CMS_encrypt_ex）。"></x-field>
</x-field-group>

#### 标志

| 标志 | 说明 |
| --- | --- |
| `CMS_TEXT` | 在加密前，在内容前添加标准的 `text/plain` MIME 头。 |
| `CMS_BINARY` | 防止对内容进行 MIME 规范化，这对于二进制数据是必需的。 |
| `CMS_USE_KEYID` | 通过接收者的主题密钥标识符来识别他们。如果接收者证书缺少此扩展，则会发生错误。 |
| `CMS_STREAM` | 为流式 I/O 初始化 `CMS_ContentInfo` 结构，但推迟从输入 BIO 读取数据。 |
| `CMS_PARTIAL` | 创建一个部分的 `CMS_ContentInfo` 结构，允许在定版前添加更多接收者。 |
| `CMS_DETACHED` | 从最终结构中省略加密内容。此标志很少使用。 |

#### 返回值

成功时返回一个有效的 `CMS_ContentInfo` 结构，失败时返回 `NULL`。

### CMS_decrypt

`CMS_decrypt()` 函数解密一个 `EnvelopedData` 或 `AuthEnvelopedData` 类型的 `CMS_ContentInfo` 结构。它使用接收者的私钥来解密内容加密密钥，然后用该密钥解密实际内容。

#### 摘要

```c
#include <openssl/cms.h>

int CMS_decrypt(CMS_ContentInfo *cms, EVP_PKEY *pkey, X509 *cert,
                BIO *dcont, BIO *out, unsigned int flags);
```

#### 参数

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="要解密的 CMS 结构。"></x-field>
  <x-field data-name="pkey" data-type="EVP_PKEY*" data-required="true" data-desc="接收者的私钥。"></x-field>
  <x-field data-name="cert" data-type="X509*" data-required="false" data-desc="接收者的证书。虽然解密并非严格要求此证书，但强烈建议提供它以定位正确的 RecipientInfo 并防止潜在攻击。"></x-field>
  <x-field data-name="dcont" data-type="BIO*" data-required="false" data-desc="如果加密内容是分离式的，则此 BIO 包含该内容。通常为 NULL。"></x-field>
  <x-field data-name="out" data-type="BIO*" data-required="true" data-desc="一个用于写入解密内容的 BIO。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="用于控制解密的标志位掩码。"></x-field>
</x-field-group>

#### 标志

| 标志 | 说明 |
| --- | --- |
| `CMS_TEXT` | 从解密内容中剥离 `text/plain` MIME 头。如果内容类型不是 `text/plain`，则会发生错误。 |
| `CMS_DEBUG_DECRYPT` | 禁用 MMA（Bleichenbacher 攻击）对策。如果没有接收者密钥能成功解密，则立即返回错误，而不是用一个随机密钥进行解密。请极其谨慎使用。 |

#### 返回值

成功时返回 `1`，失败时返回 `0`。

### 辅助解密函数

为了实现更精细的控制，您可以使用以下函数预先设置解密密钥，然后在调用 `CMS_decrypt()` 时将 `pkey` 和 `cert` 设置为 `NULL`。

#### 摘要

```c
#include <openssl/cms.h>

int CMS_decrypt_set1_pkey(CMS_ContentInfo *cms, EVP_PKEY *pk, X509 *cert);

int CMS_decrypt_set1_pkey_and_peer(CMS_ContentInfo *cms, EVP_PKEY *pk,
                                   X509 *cert, X509 *peer);

int CMS_decrypt_set1_password(CMS_ContentInfo *cms,
                              unsigned char *pass, ossl_ssize_t passlen);
```

#### 说明

-   `CMS_decrypt_set1_pkey()` 和 `CMS_decrypt_set1_pkey_and_peer()` 使用私钥 `pk` 解密内容加密密钥。证书 `cert` 有助于识别正确的 `RecipientInfo`。`peer` 证书用于密钥协商方案。
-   `CMS_decrypt_set1_password()` 使用密码为 `PWRI` (Password Recipient Info) 类型进行解密。

这些函数成功时返回 `1`，失败时返回 `0`。

## 定版函数

当使用 `CMS_STREAM` 或 `CMS_PARTIAL` 标志创建 CMS 结构时，在所有数据处理完毕后，需要一个定版步骤来完成该结构。

### CMS_final

`CMS_final()` 函数定版一个 `CMS_ContentInfo` 结构。这通常涉及在所有内容通过流式 BIO 写入后，计算并编码摘要和签名。在使用 `CMS_PARTIAL` 标志且不使用流式 I/O 时，此函数至关重要。

#### 摘要

```c
#include <openssl/cms.h>

int CMS_final(CMS_ContentInfo *cms, BIO *data, BIO *dcont, unsigned int flags);
```

#### 参数

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="要定版的部分 CMS 结构。"></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="true" data-desc="一个包含待处理内容的 BIO。"></x-field>
  <x-field data-name="dcont" data-type="BIO*" data-required="false" data-desc="一个用于在处理后写入内容的 BIO（用于分离式签名）。通常为 NULL。"></x-field>
  <x-field data-name="flags" data-type="unsigned int" data-required="true" data-desc="用于控制处理的标志，例如 MIME 规范化。"></x-field>
</x-field-group>

#### 返回值

成功时返回 `1`，失败时返回 `0`。

### CMS_dataFinal

当启用流式处理时，`CMS_dataFinal()` 和 `CMS_dataFinal_ex()` 函数用于定版 CMS 结构。它们被诸如 `i2d_CMS_bio_stream()` 等函数内部调用，但也可以直接用于精细控制。对于像 EdDSA 这样的无哈希签名方案，需要使用 `CMS_dataFinal_ex`。

#### 摘要

```c
#include <openssl/cms.h>

int CMS_dataFinal(CMS_ContentInfo *cms, BIO *cmsbio);

int CMS_dataFinal_ex(CMS_ContentInfo *cms, BIO *cmsbio, BIO *data);
```

#### 参数

<x-field-group>
  <x-field data-name="cms" data-type="CMS_ContentInfo*" data-required="true" data-desc="要定版的流式 CMS 结构。"></x-field>
  <x-field data-name="cmsbio" data-type="BIO*" data-required="true" data-desc="从 CMS_dataInit() 返回的 BIO 链，数据通过此链写入。"></x-field>
  <x-field data-name="data" data-type="BIO*" data-required="false" data-desc="原始数据 BIO，对于需要重新读取原始数据的无哈希签名方案是必需的（用于 CMS_dataFinal_ex）。"></x-field>
</x-field-group>

#### 返回值

成功时返回 `1`，失败时返回 `0`。

## 总结

本节涵盖了创建和处理 CMS 消息的主要入口点。如需对消息组件进行更详细的控制，请参考 [SignerInfo 函数](./api-signerinfo.md) 和 [RecipientInfo 函数](./api-recipientinfo.md) 部分中的函数。 [签名与验证](./guides-signing-verifying.md) 和 [加密与解密](./guides-encrypting-decrypting.md) 的操作指南提供了使用这些函数的实际示例。