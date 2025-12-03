本文档解释了加密消息语法（Cryptographic Message Syntax，CMS）的用途、其在 S/MIME 等安全消息应用中的作用，以及 OpenSSL CMS 库的高层架构。读完本文后，您将理解 CMS 消息的基本组成部分以及它们如何协同工作。

# 概述

加密消息语法（CMS）在 [RFC 5652](https://tools.ietf.org/html/rfc5652) 中指定，是一种使用密码学保护数据的标准。它为各种密码学操作定义了一种语法，包括数字签名、消息摘要、身份验证和加密。CMS 是安全消息标准（如安全/多用途互联网邮件扩展 S/MIME）的基石，后者用于对电子邮件进行签名和加密。

OpenSSL CMS 模块提供了对该标准的全面而灵活的实现，可通过 C 语言 API 和强大的命令行界面（`openssl cms`）进行访问。

## CMS 的用途

CMS 提供了一种“包装器”格式，用于封装数据和相关的密码学信息。这使得创建自包含的安全消息成为可能，这些消息可以在不安全的网络上传输。CMS 的核心功能包括：

*   **数据完整性：** 确保数据在传输过程中未被修改，通常使用数字签名实现。
*   **身份验证：** 验证发件人的身份。
*   **机密性：** 加密数据，以便只有授权的接收者才能查看。
*   **不可否认性：** 提供特定发件人创建消息的证据，防止其事后否认。

## 高层架构

CMS 结构的核心是一个 `ContentInfo` 对象。该对象充当一个容器，包含两个关键信息：

1.  **内容类型（Content Type）：** 一个标识符，指定所应用的密码学保护类型（例如，签名数据、封装数据）。
2.  **内容（Content）：** 实际数据，根据指定的内容类型进行结构化。

CMS 的强大之处在于其模块化设计，可以将不同的内容类型进行嵌套以组合密码学操作，例如创建一条既被签名又被加密的消息。

下图说明了 `ContentInfo` 容器与其各种内容类型之间的关系：

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![This document explains the purpose of the Cryptographic Message Syntax (CMS), its role in secure ...](./assets/diagram/overview-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

### 核心内容类型

OpenSSL 的 CMS 实现支持多种标准内容类型，每种类型都有其独特的用途。理解这些类型是有效使用该库的基础。

| 内容类型 | 描述 | 常见用例 |
| :--- | :--- | :--- |
| **Data** | 任意数据的简单包装器，没有密码学保护。它通常用作嵌套结构中最内层的内容。 | 在签名或加密前封装原始消息。 |
| **SignedData** | 包含数据以及来自一个或多个签名者的数字签名。它提供身份验证、完整性和不可否认性。 | 验证文档或电子邮件的作者。 |
| **EnvelopedData** | 包含加密数据以及供一个或多个接收者解密该数据的信息。它提供机密性。 | 向多个接收者发送机密消息。 |
| **DigestedData** | 包含数据和该数据的消息摘要（哈希）。它提供了一种基本的完整性检查形式。 | 验证文件在下载过程中是否已损坏。 |
| **EncryptedData** | 包含用对称密钥加密的数据。与 `EnvelopedData` 不同，它不包含用于密钥管理的接收者信息。 | 在密钥分发单独处理的情况下进行简单的对称加密。 |
| **AuthEnvelopedData** | 提供认证加密（AEAD），在一次高效的操作中结合了机密性和完整性。 | 保护机密性和真实性都至关重要的数据。 |
| **CompressedData** | 包含压缩数据。此类型通常在加密前使用，以减小消息的大小。 | 在加密和发送大型附件之前对其进行压缩。 |

有关每种类型的更详细解释，请参阅[核心概念](./concepts-content-types.md)部分。

### 签名者和接收者

在主要内容类型中，另外两种结构扮演着关键角色：

*   `SignerInfo`：在 `SignedData` 结构中使用。每个 `SignerInfo` 对象包含单个签名者的签名及相关信息，包括其证书标识符和签名属性的哈希值。一条消息可以有多个签名者，每个签名者都由一个单独的 `SignerInfo` 结构表示。

*   `RecipientInfo`：在 `EnvelopedData` 结构中使用。每个 `RecipientInfo` 对象包含为单个接收者加密的内容加密密钥。这种设计允许一条消息只加密一次，但可以由多个接收者使用各自的私钥解密。CMS 支持多种密钥管理方法，详见[接收者信息类型](./concepts-recipient-info-types.md)。

## 库与命令行工具

OpenSSL 提供了两种与 CMS 模块交互的主要方式：

1.  **`openssl cms` 命令行工具：** 一个功能多样的实用程序，用于直接从 shell 执行常见的 CMS 操作，如签名、验证、加密和解密文件。它非常适合脚本编写和手动任务。

2.  **C 库（`libcrypto`）：** 一个丰富的 API，展现了 CMS 实现的全部功能。对于需要将安全消息功能直接集成到其 C/C++ 应用程序中的开发人员来说，这是必经之路，它提供了对 CMS 结构各个方面的精细控制。

命令行工具直接构建在 C 库之上，其选项通常直接映射到 API 函数和标志。例如，运行 `openssl cms -sign` 会调用底层的 `CMS_sign()` 函数。本文档旨在弥合两者之间的差距，让熟悉命令行的用户能够过渡到 API，反之亦然。

## 如何阅读本文档

本文档的结构旨在引导您从高层概念到实际的实现细节。

<x-cards data-columns="2">
  <x-card data-title="快速入门" data-icon="lucide:rocket" data-href="/quick-start">
    本指南为最常见的操作提供了直接、实用的示例，帮助您上手实践。
  </x-card>
  <x-card data-title="核心概念" data-icon="lucide:book-open" data-href="/concepts">
    本节详细介绍了 CMS 的架构组件，帮助您获得更深入的理论理解。
  </x-card>
  <x-card data-title="操作指南" data-icon="lucide:wrench" data-href="/guides">
    这些指南为特定用例提供了分步工作流程，旨在提供面向任务的说明。
  </x-card>
  <x-card data-title="API 参考" data-icon="lucide:library" data-href="/api">
    本节为 API 中的每个函数提供了全面的参考，旨在提供详细的技术信息。
  </x-card>
</x-cards>

---

### 总结

*   **CMS 是一项标准：** 它提供了一种通用的语法（RFC 5652），用于对数据应用签名和加密等密码学保护。
*   **它是一个包装系统：** 核心的 `ContentInfo` 结构使用不同的 `内容类型`（例如 `SignedData`、`EnvelopedData`）包装数据以确保其安全。
*   **OpenSSL 提供全面支持：** 功能可通过灵活的 `openssl cms` 命令行工具和全面的 C 库 API 使用。
*   **关键结构：** `SignerInfo` 和 `RecipientInfo` 分别实现了多签名者和多接收者功能。