本节将详细介绍加密消息语法（CMS）的六个基本构建模块。阅读完本指南后，您将能够区分每种核心 CMS 内容类型，并理解其各自设计的特定加密目的。

# 内容类型

加密消息语法的核心是 `ContentInfo` 结构，它是一个用于所有受保护数据的通用容器。`ContentInfo` 对象包含一个内容类型标识符和相应的内容本身。CMS 定义了六种主要内容类型，每种都服务于独特的加密功能。这些类型可以嵌套以组合操作，例如创建先签名后加密的消息。

下图说明了这些内容类型如何相互关联，通常以 `Data` 类型作为最内层的内容。

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![本节将详细介绍加密消息语法（CMS）的六个基本构建模块。阅读完本指南后，您将能够区分每种核心 CMS 内容类型，并理解其各自设计的特定加密目的。](./assets/diagram/content-types-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

理解这六种类型对于有效使用 OpenSSL CMS 库至关重要，因为它们构成了所有签名和加密操作的基础。

| 内容类型 | ASN.1 对象标识符 | 用途 |
| :--- | :--- | :--- |
| **Data** | `pkcs7-data` | 封装任意的八位字节字符串数据，不提供加密保护。它作为其他类型的最内层内容。 |
| **SignedData** | `pkcs7-signedData` | 对内容应用数字签名，提供身份验证、完整性和不可否认性。 |
| **EnvelopedData** | `pkcs7-envelopedData` | 为一个或多个接收者加密内容，提供机密性。 |
| **DigestedData** | `pkcs7-digestData` | 通过封装内容和该内容的消息摘要来提供内容完整性。 |
| **EncryptedData** | `pkcs7-encryptedData` | 使用对称密钥加密内容。与 `EnvelopedData` 不同，它不包含用于密钥管理的接收者信息。 |
| **AuthEnvelopedData** | `id-smime-ct-authEnvelopedData` | 提供带有关联数据的认证加密（AEAD），在单个操作中结合了机密性和完整性。 |

---

## Data

`Data` 内容类型是最基本的。它仅包含一个八位字节字符串数据，不提供任何加密保护。它最常被用作其他 CMS 类型（如 `SignedData` 或 `EnvelopedData`）中封装的内容。

-   **用途**：持有原始消息内容。
-   **结构**：由单个字段 `OCTET STRING` 组成，其中包含消息数据。

```sh ASN.1 定义
ContentInfo ::= SEQUENCE {
  contentType                OBJECT IDENTIFIER (pkcs7-data),
  content               [0]  EXPLICIT ANY DEFINED BY contentType OPTIONAL
                               -- 包含一个八位字节字符串
}
```

---

## SignedData

`SignedData` 内容类型用于对内容应用一个或多个数字签名。它提供数据完整性、签名者身份验证和不可否认性。内容本身可以分离或封装在结构内。

-   **用途**：创建和验证数字签名。
-   **主要特性**：支持多个签名者、分离式签名，并可包含证书和 CRL 以辅助验证。

### 结构

`SignedData` 结构是关于签名者、摘要算法和被签名内容的集合信息。

| 字段 | 描述 |
| :--- | :--- |
| `version` | 语法版本号。它会根据所使用的组件自动设置（例如，如果使用了 `subjectKeyIdentifier`，则版本为 3）。 |
| `digestAlgorithms` | 签名者使用的一组消息摘要算法标识符。 |
| `encapContentInfo` | 封装的内容，包括其类型和内容本身（对于分离式签名，内容可能被省略）。 |
| `certificates` | 一组可选的证书，用于验证签名。 |
| `crls` | 一组可选的证书吊销列表（CRL），用于路径验证。 |
| `signerInfos` | 一组 `SignerInfo` 结构，每个签名者对应一个。每个 `SignerInfo` 包含签名者的身份、摘要和签名算法、已签名的属性以及签名本身。 |

有关管理签名者信息的更多详细信息，请参阅 [SignerInfo 函数](./api-signerinfo.md) API 参考。

---

## EnvelopedData

`EnvelopedData` 内容类型用于为一个或多个接收者加密内容，以确保机密性。其工作原理是生成一个随机的对称内容加密密钥（CEK），用 CEK 加密数据，然后使用每个接收者各自的公钥为他们加密 CEK。

-   **用途**：为特定接收者加密数据。
-   **主要特性**：支持使用各种密钥管理技术的多个接收者。

### 结构

`EnvelopedData` 结构包含加密后的内容以及接收者解密所需的所有必要信息。

| 字段 | 描述 |
| :--- | :--- |
| `version` | 语法版本号，由接收者信息的类型和其他字段决定。 |
| `originatorInfo` | 一个可选字段，包含证书和 CRL，以帮助接收者建立密钥协商密钥。 |
| `recipientInfos` | 一组 `RecipientInfo` 结构，每个接收者对应一个。每个结构包含接收者的标识符和加密后的 CEK。 |
| `encryptedContentInfo` | 包含加密后的内容、内容加密算法和加密内容本身。 |
| `unprotectedAttrs` | 一组可选的未受加密保护的属性。 |

要了解如何为不同接收者管理密钥，请参阅 [Recipient Info 类型](./concepts-recipient-info-types.md) 文档。

---

## DigestedData

`DigestedData` 内容类型提供了一种确保内容完整性的直接方法。它由内容和该内容的消息摘要（哈希）组成，该摘要使用指定的算法计算。它不提供身份验证或机密性。

-   **用途**：验证内容在传输过程中未被修改。
-   **主要特性**：当仅需完整性时，比 `SignedData` 更简单。

### 结构

| 字段 | 描述 |
| :--- | :--- |
| `version` | 语法版本号。 |
| `digestAlgorithm` | 所使用的消息摘要算法的标识符。 |
| `encapContentInfo` | 被摘要的封装内容。 |
| `digest` | 计算出的内容消息摘要。 |

---

## EncryptedData

`EncryptedData` 内容类型用于使用对称密钥加密数据。与 `EnvelopedData` 不同，它不提供向接收者安全分发对称密钥的机制。密钥必须通过外部的带外渠道进行管理。

-   **用途**：在密钥管理单独处理时，对内容进行对称加密。
-   **主要特性**：适用于发送方和接收方已共享密钥的场景。

### 结构

| 字段 | 描述 |
| :--- | :--- |
| `version` | 语法版本号。 |
| `encryptedContentInfo` | 包含加密后的内容、内容加密算法和加密内容本身。 |
| `unprotectedAttrs` | 一组可选的未受加密保护的属性。 |

---

## AuthEnvelopedData

`AuthEnvelopedData` 内容类型提供认证加密，这是一种将机密性和完整性结合到单个加密操作中的模式。它通常与 AEAD（带有关联数据的认证加密）密码（如 AES-GCM）一起使用。

-   **用途**：在加密内容的同时提供完整性和真实性保护。
-   **主要特性**：比分别应用加密和 MAC（例如，先加密后 MAC）更高效、更安全。

### 结构

| 字段 | 描述 |
| :--- | :--- |
| `version` | 语法版本号。 |
| `originatorInfo` | 可选的发起者信息，类似于 `EnvelopedData`。 |
| `recipientInfos` | 一组用于管理内容加密密钥的 `RecipientInfo` 结构。 |
| `authEncryptedContentInfo` | 包含加密后的内容和加密算法。 |
| `authAttrs` | 一组可选的认证属性，包含在 MAC 计算中。 |
| `mac` | 消息认证码（标签），确保数据完整性和真实性。 |
| `unauthAttrs` | 一组可选的未认证属性。 |

## 总结

六种 CMS 内容类型为保护数据提供了一个灵活的工具集。`Data` 是基础，而 `SignedData` 和 `EnvelopedData` 分别是签名和加密的主力。`DigestedData`、`EncryptedData` 和 `AuthEnvelopedData` 为完整性、简单对称加密和认证加密提供了专门的解决方案。

要更深入地了解如何在 `EnvelopedData` 和 `AuthEnvelopedData` 中为接收者管理密钥，请继续阅读 [Recipient Info 类型](./concepts-recipient-info-types.md) 部分。