# Recipient Info 类型

在加密消息语法（Cryptographic Message Syntax）中，`RecipientInfo` 结构是一种将内容加密密钥（CEK）安全地传递给每个接收者的机制。本文档详细介绍了六种 `RecipientInfo` 结构类型，解释了每种类型如何保护和传输密钥，使您能够根据应用程序的安全需求选择适当的方法。

在 CMS `EnvelopedData` 结构中，消息内容使用一个随机生成的对称密钥（称为内容加密密钥，即 CEK）进行加密。为确保只有授权的接收者才能访问内容，CEK 本身必须被安全地分发。这是通过为每个接收者创建一个 `RecipientInfo` 结构来实现的。每个结构都包含一份 CEK 的副本，该副本以一种独特且仅能由其预期接收者解密的方式进行加密。

<!-- DIAGRAM_IMAGE_START:intro:16:9 -->
![Recipient Info 类型](./assets/diagram/concepts-recipient-info-types-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

OpenSSL 支持六种不同的密钥管理机制，每种机制都由一个唯一的类型标识。

## 密钥传输接收者信息 (KTRI)

密钥传输是分发 CEK 最常用的方法之一。它使用非对称（公钥）加密技术，直接用接收者的公钥加密 CEK。

*   **类型标识符**：`CMS_RECIPINFO_TRANS`
*   **机制**：发送方生成一个 CEK，使用接收者的公钥（通常是 RSA）对其进行加密，并将结果放入一个 `KeyTransRecipientInfo` 结构中。接收者使用其对应的私钥解密 CEK，然后访问消息内容。
*   **用例**：非常适用于标准的公钥基础设施（PKI）环境，其中接收者拥有包含 RSA 或类似适用于加密的公钥的 X.509 证书。
*   **ASN.1 结构**：`KeyTransRecipientInfo`

这种方法简单明了且得到广泛支持。添加 KTRI 接收者的主要函数是 `CMS_add1_recipient_cert()`。

```c
CMS_RecipientInfo *CMS_add1_recipient_cert(CMS_ContentInfo *cms,
                                           X509 *recip, unsigned int flags);
```

## 密钥协商接收者信息 (KARI)

密钥协商允许两方或多方在不安全的信道上生成一个共享秘密，然后用该秘密派生出一个密钥加密密钥（KEK）来包装 CEK。

*   **类型标识符**：`CMS_RECIPINFO_AGREE`
*   **机制**：发送方生成一个临时的密钥对（例如，Diffie-Hellman 或 Elliptic Curve Diffie-Hellman）。利用自己的私钥和接收者的公钥，他们派生出一个共享秘密。这个秘密被用来派生一个 KEK，该 KEK 用于加密 CEK。接收者使用自己的私钥和发送方的临时公钥执行相同的派生过程。
*   **用例**：适用于基于 Diffie-Hellman (DH) 或 Elliptic Curve Diffie-Hellman (ECDH) 的协议，如果使用临时密钥，可提供完全正向保密性。
*   **ASN.1 结构**：`KeyAgreeRecipientInfo`

该方法比 KTRI 更复杂，但提供了更高级别的安全属性。

## 密钥加密密钥接收者信息 (KEKRI)

此方法使用一个预共享的对称密钥，称为密钥加密密钥（KEK），来加密 CEK。

*   **类型标识符**：`CMS_RECIPINFO_KEK`
*   **机制**：发送方和接收方都必须已拥有一个共享的对称密钥。发送方使用此 KEK 加密 CEK，通常采用像 AES Key Wrap 这样的密钥包装算法。接收方使用相同的 KEK 对其进行解包。KEK 通过一个唯一的密钥标识符来识别。
*   **用例**：适用于可以带外安全地配置和管理对称密钥的封闭系统。它避免了公钥加密的开销。
*   **ASN.1 结构**：`KEKRecipientInfo`

添加 KEKRI 接收者的主要函数是 `CMS_add0_recipient_key()`。

```c
CMS_RecipientInfo *CMS_add0_recipient_key(CMS_ContentInfo *cms, int nid,
                                          unsigned char *key, size_t keylen,
                                          unsigned char *id, size_t idlen,
                                          ASN1_GENERALIZEDTIME *date,
                                          ASN1_OBJECT *otherTypeId,
                                          ASN1_TYPE *otherType);
```

## 密码接收者信息 (PWRI)

基于密码的密钥管理从共享的密码或口令中派生出 KEK。

*   **类型标识符**：`CMS_RECIPINFO_PASS`
*   **机制**：使用密钥派生函数（KDF），如 PBKDF2，从密码中派生出 KEK。然后，这个 KEK 被用来加密 CEK。知道相同密码的接收者执行相同的 KDF 来重新派生 KEK 并解密 CEK。
*   **用例**：适用于安全性基于人类可记忆的秘密而非证书或预配密钥的场景。
*   **ASN.1 结构**：`PasswordRecipientInfo`

函数 `CMS_add0_recipient_password()` 用于添加 PWRI 接收者。

```c
CMS_RecipientInfo *CMS_add0_recipient_password(CMS_ContentInfo *cms,
                                               int iter, int wrap_nid,
                                               int pbe_nid,
                                               unsigned char *pass,
                                               ossl_ssize_t passlen,
                                               const EVP_CIPHER *kekciph);
```

## 密钥封装机制接收者信息 (KEMRI)

KEMRI 是一种用于安全密钥建立的现代方法，尤其与后量子密码学相关。它是密钥传输的一种变体。

*   **类型标识符**：`CMS_RECIPINFO_KEM`
*   **机制**：密钥封装机制（KEM）是一套用于封装和解封装共享秘密的算法。发送方使用接收者的公钥生成一个共享秘密和一个密文（封装后的密钥）。该共享秘密与 KDF 一起使用，派生出一个 KEK，该 KEK 包装 CEK。接收者使用其私钥解封装该密文，检索出相同的共享秘密，并派生出相同的 KEK。
*   **用例**：为新兴的密码算法提供了一个标准化框架，特别是那些设计用于抵抗量子计算机攻击的算法。
*   **ASN.1 结构**：`KEMRecipientInfo`（在 `OtherRecipientInfo` 内）

## 其他接收者信息 (ORI)

此类型作为一个扩展点，用于定义标准集合未涵盖的新接收者信息类型。

*   **类型标识符**：`CMS_RECIPINFO_OTHER`
*   **机制**：其结构和处理规则由具体实现定义，并通过一个唯一的对象标识符（`oriType`）来识别。KEMRI 是使用 `OtherRecipientInfo` 实现的一个突出机制示例。
*   **用例**：通过允许集成新颖的密钥管理方案，而无需更新规范版本，从而使 CMS 标准能够适应未来发展。
*   **ASN.1 结构**：`OtherRecipientInfo`

## 接收者类型摘要

下表对不同的 `RecipientInfo` 类型进行了概要比较。

| 类型 | 标识符 | 密钥管理 | 主要密钥类型 | 常用场景 |
| :--- | :--- | :--- | :--- | :--- |
| **KTRI** | `CMS_RECIPINFO_TRANS` | 非对称密钥传输 | RSA 公钥 | 标准的基于证书的加密。 |
| **KARI** | `CMS_RECIPINFO_AGREE` | 非对称密钥协商 | DH/ECDH 公钥 | 建立用于密钥派生的共享秘密。 |
| **KEKRI** | `CMS_RECIPINFO_KEK` | 对称密钥包装 | 预共享对称密钥 | 具有预配置对称密钥的系统。 |
| **PWRI** | `CMS_RECIPINFO_PASS` | 基于对称密码 | 密码/口令 | 基于共享秘密的安全性。 |
| **KEMRI**| `CMS_RECIPINFO_KEM` | 密钥封装 | KEM 公钥 | 后量子密码学和现代方案。 |
| **ORI** | `CMS_RECIPINFO_OTHER` | 自定义 | 不定 | 为新的密钥管理机制提供可扩展性。 |

---

### 深入阅读

-   要了解 `RecipientInfo` 如何融入整体消息结构，请参阅[内容类型](./concepts-content-types.md)。
-   有关实现加密的详细步骤，请参阅[加密与解密](./guides-encrypting-decrypting.md)指南。
-   有关详细的 API 参考，请访问 [RecipientInfo 函数](./api-recipientinfo.md)文档。