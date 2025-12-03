# 核心概念

要有效使用 OpenSSL 加密消息语法 (CMS) 库，首先必须了解其架构蓝图。本文档对 CMS 消息的主要组件、它们如何交互以及各自在创建安全数字消息中的作用进行了基础性概述。这个概念框架将为您在后续指南中的实际应用做好准备。

## CMS 架构蓝图

加密消息语法 (Cryptographic Message Syntax, CMS) 在 [RFC 5652](https://tools.ietf.org/html/rfc5652) 中指定，是一种保护数据的标准。它为包括数字签名、消息摘要、身份验证和加密在内的多种加密操作提供了语法。其最著名的应用是在 **S/MIME** (Secure/Multipurpose Internet Mail Extensions) 协议中，用于保护电子邮件通信。

每个 CMS 消息的核心都是一个 `ContentInfo` 结构。该结构充当一个通用包装器，包含两个关键信息：

1.  **内容类型 (Content Type)**：一个对象标识符 (OID)，用于指定所包含的数据类型。
2.  **内容 (Content)**：根据指定内容类型组织的实际数据。

这种分层设计允许嵌套，即一个 CMS 结构可以被包裹在另一个结构中。例如，一个已签名的消息 (`SignedData`) 本身可以被加密，整个 `SignedData` 结构成为一个 `EnvelopedData` 结构的内容。下图说明了这种层次结构：

<!-- DIAGRAM_IMAGE_START:architecture:3:4 -->
![核心概念](assets/diagram/concepts-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## CMS 内容类型

OpenSSL CMS 实现支持多种标准内容类型，每种类型都为特定的加密目的而设计。理解这些类型是构建和解析 CMS 消息的第一步。

有关每种类型的深入细节，请参阅[内容类型](./concepts-content-types.md)文档。

<x-cards data-columns="3">
  <x-card data-title="Data" data-icon="lucide:file-text">
    最简单的类型，表示任意的八位字节字符串数据。它充当其他类型的明文内容。
  </x-card>
  <x-card data-title="SignedData" data-icon="lucide:pen-square">
    提供数字签名。它包含原始内容、签名者信息 (SignerInfo) 和数字签名。
  </x-card>
  <x-card data-title="EnvelopedData" data-icon="lucide:mail">
    通过加密提供机密性。它包含加密后的内容和解密所需的特定于接收者的信息 (RecipientInfo)。
  </x-card>
  <x-card data-title="DigestedData" data-icon="lucide:hash">
    通过存储内容的消息摘要（哈希值）来提供内容完整性。
  </x-card>
  <x-card data-title="EncryptedData" data-icon="lucide:lock">
    包含对称加密的内容，但与 EnvelopedData 不同，它不包含接收者密钥管理信息。密钥必须通过带外方式管理。
  </x-card>
  <x-card data-title="AuthEnvelopedData" data-icon="lucide:shield-check">
    提供带有关联数据的认证加密 (AEAD)，在单个操作中结合了机密性和完整性。
  </x-card>
</x-cards>

## 内容类型中的关键组件

`SignerInfo` 和 `RecipientInfo` 这两个关键结构分别是 `SignedData` 和 `EnvelopedData` 类型的操作核心。

### SignerInfo：签名块

`SignerInfo` 结构是 `SignedData` 内容类型的核心。消息的每个签名者都贡献一个 `SignerInfo` 块。该块包含验证签名所需的所有信息，包括：

*   **签名者标识符 (Signer Identifier)**：唯一标识签名者的证书，通常通过颁发者和序列号或主题密钥标识符来识别。
*   **摘要算法 (Digest Algorithm)**：在签名之前用于哈希消息内容的算法（例如 SHA-256）。
*   **签名算法 (Signature Algorithm)**：用于创建数字签名的算法（例如 RSA）。
*   **已签名属性 (Signed Attributes)**：一组与内容摘要一同被签名的已认证属性。这通常包括内容类型和签名时间。
*   **签名值 (Signature Value)**：实际的数字签名八位字节字符串。
*   **未签名属性 (Unsigned Attributes)**：不属于签名计算部分的可选属性，例如副署签名。

### RecipientInfo：解密之钥

`RecipientInfo` 结构是 `EnvelopedData` 和 `AuthEnvelopedData` 的核心。它为特定接收者提供了成功解密消息所需的信息。一条消息可以包含多个 `RecipientInfo` 结构，每个接收者对应一个。

CMS 定义了多种向接收者传递内容加密密钥 (CEK) 的方法，每种方法对应一种不同的 `RecipientInfo` 类型。类型的选择取决于接收者使用的凭证种类。

有关每种类型的完整解释，请参阅[接收者信息类型](./concepts-recipient-info-types.md)文档。

| 类型  | 常量                  | 描述                                                                                              | 常用凭证                  |
| :---- | :---------------------- | :------------------------------------------------------------------------------------------------ | :------------------------ |
| KTRI  | `CMS_RECIPINFO_TRANS`   | **密钥传输 (Key Transport)**：CEK 使用接收者的公钥（例如 RSA）进行加密。                          | X.509 证书 (RSA)          |
| KARI  | `CMS_RECIPINFO_AGREE`   | **密钥协商 (Key Agreement)**：使用接收者和发起者的密钥派生出共享密钥（例如 DH/ECDH）。            | X.509 证书 (DH/EC)        |
| KEKRI | `CMS_RECIPINFO_KEK`     | **密钥加密密钥 (Key Encryption Key)**：CEK 使用预共享的对称密钥进行包装。                         | 对称密钥                  |
| PWRI  | `CMS_RECIPINFO_PASS`    | **密码 (Password)**：CEK 从密码派生而来。                                                         | 密码 / 口令               |
| KEMRI | `CMS_RECIPINFO_KEM`     | **密钥封装机制 (Key Encapsulation Mechanism)**：用于密钥交换的抗量子机制。                        | 后量子密钥                |
| ORI   | `CMS_RECIPINFO_OTHER`   | **其他 (Other)**：为自定义或未来的接收者类型保留的占位符。                                        | 自定义                    |

## 与 `openssl cms` 命令的关系

`openssl cms` 命令行工具是 CMS 库函数的一个高级接口。它的每个主要操作都直接对应于特定 CMS 内容类型的创建或处理。理解这种映射关系有助于了解命令行操作如何转换为底层的 API 调用。

| `openssl cms` 命令          | 对应的 CMS 内容类型          | 核心 API 函数                                      |
| :---------------------------- | :----------------------------- | :------------------------------------------------- |
| `-sign`, `-verify`, `-resign` | `SignedData`                   | `CMS_sign()`, `CMS_verify()`                       |
| `-encrypt`, `-decrypt`        | `EnvelopedData`                | `CMS_encrypt()`, `CMS_decrypt()`                   |
| `-digest_create`, `-digest_verify` | `DigestedData`                 | `CMS_digest_create()`, `CMS_digest_verify()`       |
| `-EncryptedData_encrypt`, `-EncryptedData_decrypt` | `EncryptedData`                | `CMS_EncryptedData_encrypt()`, `CMS_EncryptedData_decrypt()` |
| `-compress`, `-uncompress`    | `CompressedData`               | `CMS_compress()`, `CMS_uncompress()`               |
| `-data_create`                | `Data`                         | `CMS_data_create()`                                |

## 总结

加密消息语法提供了一个结构化、分层的框架，用于对数据应用加密保护。其核心是 `ContentInfo` 结构，它包装了如 `SignedData` 和 `EnvelopedData` 等多种内容类型。这些类型又依赖于 `SignerInfo` 和 `RecipientInfo` 来管理签名和加密密钥。

有了这个概念基础，您现在可以探索更具体的主题：

<x-cards data-columns="2">
  <x-card data-title="快速入门" data-icon="lucide:rocket" data-href="/quick-start">
    一个以最少理论执行常见 CMS 操作的实践指南。
  </x-card>
  <x-card data-title="内容类型" data-icon="lucide:box" data-href="/concepts/content-types">
    对每种主要 CMS 内容类型的详细剖析。
  </x-card>
  <x-card data-title="接收者信息类型" data-icon="lucide:key-round" data-href="/concepts/recipient-info-types">
    深入了解接收者密钥管理的不同方法。
  </x-card>
  <x-card data-title="CLI 工具 (openssl cms)" data-icon="lucide:terminal" data-href="/command-line">
    命令行界面的综合参考。
  </x-card>
</x-cards>