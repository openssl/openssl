# API 参考

本节为整个 OpenSSL Cryptographic Message Syntax (CMS) 公共 API 提供了完整且可搜索的参考。它为所有函数（包括之前未文档化的函数）提供了详细的文档，是开发人员使用该库的权威指南。

该 API 按逻辑分组进行组织，以帮助您快速找到所需的函数。无论您是执行高级操作还是需要对 CMS 结构进行精细控制，本参考都包含了必要的详细信息。

有关 CMS 的概念性解释，请参阅 [核心概念](./concepts.md) 部分。有关面向任务的工作流程，请参阅 [操作指南](./guides.md)。

## 函数类别

OpenSSL CMS API 根据功能分为几个类别。以下是每个类别的概述及其详细文档的链接。

<x-cards data-columns="2">
  <x-card data-title="主要函数" data-icon="lucide:function-square" data-href="/api/main">
    用于执行签名、验证、加密和解密 CMS 消息等常见操作的高级函数。这些是使用最频繁的函数。
  </x-card>
  <x-card data-title="SignerInfo 函数" data-icon="lucide:pen-tool" data-href="/api/signerinfo">
    用于管理 SignerInfo 结构的函数，包括添加签名者、管理签名和未签名属性以及执行低级签名验证。
  </x-card>
  <x-card data-title="RecipientInfo 函数" data-icon="lucide:users" data-href="/api/recipientinfo">
    用于管理 RecipientInfo 结构的函数。这包括为各种密钥管理类型（KTRI、KARI 等）添加接收者以及处理解密密钥。
  </x-card>
  <x-card data-title="属性与证书 API" data-icon="lucide:files" data-href="/api/attributes-certs">
    用于管理 CMS 结构中的证书、证书吊销列表 (CRL) 和属性的函数集合。
  </x-card>
  <x-card data-title="I/O 与数据函数" data-icon="lucide:binary" data-href="/api/io-data">
    涵盖用于数据流、I/O 操作以及直接管理 Data、DigestedData 和 CompressedData 等内容类型的函数。
  </x-card>
</x-cards>

## 关键数据结构

整个 CMS 功能都围绕几个核心数据结构展开。理解这些结构是有效使用 API 的关键。下图说明了这些关键结构之间的关系。

<!-- DIAGRAM_IMAGE_START:intro:1:1 -->
![API 参考](assets/diagram/api-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

*   **`CMS_ContentInfo`**：CMS 中的顶层结构。它封装了内容类型和内容本身。所有 CMS 消息都会被解析到此结构中或由此结构生成。
*   **`CMS_SignerInfo`**：包含与单个签名者相关的所有信息，包括其证书标识符、签名算法、签名值以及任何签名或未签名属性。
*   **`CMS_RecipientInfo`**：包含单个接收者解密内容加密密钥所需的信息。根据所使用的密钥管理技术，有不同类型的 `RecipientInfo` 结构。

## 常用标志

许多 CMS 函数接受一个 `flags` 参数来修改其行为。这些标志可以使用按位或运算符（`|`）进行组合。下表列出了最常见的标志及其用途。

| 标志 | 值 | 描述 |
| :--- | :--- | :--- |
| `CMS_TEXT` | `0x1` | 为 `text/plain` 内容类型添加 MIME 头。 |
| `CMS_NOCERTS` | `0x2` | 签名时，不在消息中包含签名者的证书。 |
| `CMS_NO_CONTENT_VERIFY` | `0x4` | 验证时，不验证内容签名。 |
| `CMS_NO_ATTR_VERIFY` | `0x8` | 验证时，不验证签名属性上的签名。 |
| `CMS_NOINTERN` | `0x10` | 验证时，不在消息本身中搜索签名者的证书。 |
| `CMS_NO_SIGNER_CERT_VERIFY` | `0x20` | 不验证签名者的证书链。 |
| `CMS_DETACHED` | `0x40` | 创建一个分离式签名，其中内容不包含在 `SignedData` 结构中。 |
| `CMS_BINARY` | `0x80` | 不对内容执行 MIME 规范化。用于二进制数据。 |
| `CMS_NOATTR` | `0x100` | 不包含任何签名属性。这会创建一个更简单的签名，但缺少签名时间等上下文信息。 |
| `CMS_NOSMIMECAP` | `0x200` | 省略 S/MIME 功能签名属性。 |
| `CMS_CRLFEOL` | `0x800` | 对基于文本的 MIME 内容使用 CRLF 作为行尾符。 |
| `CMS_STREAM` | `0x1000` | 指示数据正在以流式传输，并启用流式 I/O 操作。 |
| `CMS_NOCRL` | `0x2000` | 不在 `SignedData` 结构中包含任何 CRL。 |
| `CMS_USE_KEYID` | `0x10000` | 使用主题密钥标识符来识别证书，而不是颁发者和序列号。 |
| `CMS_DEBUG_DECRYPT` | `0x20000` | 在解密操作期间启用调试输出，以帮助诊断错误。 |
| `CMS_CADES` | `0x100000` | 为签名启用 CAdES (CMS Advanced Electronic Signatures) 合规性。 |

## 总结

本 API 参考旨在为使用 OpenSSL CMS 库的开发人员提供全面的资源。每个子部分都提供了详细的函数原型、参数描述、返回值和使用说明。请使用导航来浏览不同的函数类别，并找到您实现所需功能的特定工具。