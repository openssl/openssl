本文档为 `openssl cms` 命令行工具提供了详细的参考，将其操作和标志映射到底层的 OpenSSL 库函数。通过理解这些关联，您可以更有效地从命令行使用过渡到程序化的 API 实现。

# CLI 工具 (`openssl cms`)

`openssl cms` 命令提供了一个用于处理加密消息语法 (CMS) 数据的命令行界面。它允许用户执行广泛的加密操作，例如创建数字签名、验证签名以及加密或解密消息内容，符合 S/MIME 等安全电子邮件标准。

该工具是 OpenSSL CMS 库核心功能的实用封装。理解其用法有助于深入了解如何以编程方式应用 API 以实现更复杂的工作流。

下图说明了 `openssl cms` 命令行工具、其主要操作以及它们所利用的核心 OpenSSL 库函数之间的关系。

<!-- DIAGRAM_IMAGE_START:architecture:16:9 -->
![本文档为 `openssl cms` 命令行工具提供了详细的参考，将其操作和标志映射到底层的 OpenSSL 库函数。](./assets/diagram/command-line-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

## 操作

`openssl cms` 工具的主要功能由单个操作选项决定。每个操作对应一个高级工作流，该工作流结合了从读取输入数据到格式化最终输出的多个步骤。下表将最常见的操作映射到其主要的库函数和 CMS 内容类型。

| 操作选项 | CMS 内容类型 | 核心 API 函数 | 描述 |
| :--- | :--- | :--- | :--- |
| `-sign` | `SignedData` | `CMS_sign()` | 对输入数据创建数字签名。 |
| `-verify` | `SignedData` | `CMS_verify()` | 验证签名消息的完整性和真实性。 |
| `-encrypt` | `EnvelopedData` | `CMS_encrypt()` | 为一个或多个接收者加密内容。 |
| `-decrypt` | `EnvelopedData` | `CMS_decrypt()` | 使用接收者的私钥解密内容。 |
| `-compress` | `CompressedData` | `CMS_compress()` | 使用 zlib 压缩输入数据。 |
| `-uncompress` | `CompressedData` | `CMS_uncompress()` | 解压缩一个 `CompressedData` 对象。 |
| `-resign` | `SignedData` | `CMS_sign()` 与 `CMS_REUSE_DIGEST` | 向现有的 `SignedData` 结构添加新签名。 |
| `-digest_create`| `DigestedData` | `CMS_digest_create()` | 创建一个包含消息摘要的结构。 |
| `-EncryptedData_encrypt` | `EncryptedData` | `CMS_EncryptedData_encrypt()` | 使用对称密钥加密数据，不包含接收者信息。 |

## 选项参考

每个操作的行为都由一组标志控制。这些标志通常直接对应于底层 C API 函数中的参数或标志。

### 通用和 I/O 选项

这些选项控制输入和输出的来源及格式。

| 标志 | 参数 | 描述 |
| :--- | :--- | :--- |
| `-in` | `<filename>` | 指定输入文件。 |
| `-out` | `<filename>` | 指定输出文件。 |
| `-inform` | `SMIME` \| `PEM` \| `DER` | 设置输入格式。默认为 `SMIME`。 |
| `-outform`| `SMIME` \| `PEM` \| `DER` | 设置输出格式。默认为 `SMIME`。 |
| `-binary` | (无) | 防止规范化文本转换（CRLF 转换）。用于二进制数据。对应于 `CMS_BINARY` 标志。 |
| `-stream`, `-indef` | (无) | 启用流式 I/O，它使用 BER 不定长编码。对应于 `CMS_STREAM` 标志。 |
| `-content`| `<filename>` | 指定用于验证的分离内容文件。 |
| `-text` | (无) | 签名/加密时添加 `text/plain` MIME 头，或在验证/解密时剥离它们。对应于 `CMS_TEXT` 标志。 |

### 签名和验证选项

这些标志修改 `-sign` 和 `-verify` 操作的行为。

| 标志 | 参数 | 操作 | 描述 |
| :--- | :--- | :--- | :--- |
| `-signer` | `<certfile>` | Sign, Verify | 指定签名者的证书。对于多签名者消息可多次使用。 |
| `-inkey` | `<keyfile>` | Sign, Decrypt | 指定与 `-signer` 或 `-recip` 证书对应的私钥。 |
| `-md` | `<digest>` | Sign | 设置摘要算法（例如，`sha256`）。 |
| `-nodetach`| (无) | Sign | 创建不透明签名，其中内容嵌入在 `SignedData` 结构内。清除 `CMS_DETACHED` 标志。 |
| `-nocerts` | (无) | Sign | 从 `SignedData` 结构中排除签名者的证书。对应于 `CMS_NOCERTS` 标志。 |
| `-noattr` | (无) | Sign | 排除所有已签名的属性，包括签名时间和 S/MIME 功能。对应于 `CMS_NOATTR` 标志。 |
| `-noverify`| (无) | Verify | 跳过对签名者证书链的验证。对应于 `CMS_NO_SIGNER_CERT_VERIFY` 标志。 |
| `-nosigs` | (无) | Verify | 跳过对数字签名本身的验证。对应于 `CMS_NOSIGS` 标志。 |
| `-certfile`| `<certs.pem>` | Sign, Verify | 提供额外的证书以包含在消息中，或在验证期间用于构建证书链。 |
| `-CAfile` | `<ca.pem>` | Verify | 指定一个包含受信任 CA 证书的文件，用于证书链验证。 |

### 加密和解密选项

这些标志修改 `-encrypt` 和 `-decrypt` 操作的行为。

| 标志 | 参数 | 操作 | 描述 |
| :--- | :--- | :--- | :--- |
| `-recip` | `<cert.pem>` | Encrypt, Decrypt | 指定用于加密或解密的接收者证书。 |
| `-<cipher>` | (无) | Encrypt | 指定内容加密算法（例如，`-aes256`、`-des3`）。 |
| `-keyid` | (无) | Encrypt, Sign | 通过主题密钥标识符而不是颁发者和序列号来识别接收者或签名者。对应于 `CMS_USE_KEYID` 标志。 |
| `-secretkey`| `<key>` | Encrypt, Decrypt | 用于 `KEKRecipientInfo`（加密）或 `EncryptedData` 操作的十六进制编码对称密钥。 |
| `-secretkeyid`| `<id>` | Encrypt, Decrypt | 用于 KEK 接收者的十六进制编码密钥标识符。 |
| `-pwri_password`| `<password>` | Encrypt, Decrypt | 用于 `PasswordRecipientInfo` (PWRI) 的密码。 |
| `-originator` | `<cert.pem>` | Decrypt | 为密钥协商方案（例如，ECDH）指定发起者的证书。 |

## 实践示例

以下示例演示了 `openssl cms` 工具的常见用例。

### 创建分离式签名

此命令对消息进行签名，并将签名输出到一个单独的文件中，同时保持原始内容不变。这是默认的签名行为。

```sh 创建分离式签名 icon=lucide:terminal
openssl cms -sign -in message.txt -text -out signature.pem \
  -signer signer_cert.pem -inkey signer_key.pem
```

### 验证分离式签名

要验证签名，您必须提供原始内容、签名文件和签名者的证书。

```sh 验证分离式签名 icon=lucide:terminal
openssl cms -verify -in signature.pem -inform PEM \
  -content message.txt -CAfile trusted_ca.pem -out verified_message.txt
```

### 创建不透明（附加式）签名

不透明签名将原始内容嵌入到 CMS 结构中。若不进行解析，生成的文件是人类不可读的。

```sh 创建不透明签名 icon=lucide:terminal
openssl cms -sign -in message.txt -text -nodetach \
  -out signed_opaque.pem -signer signer_cert.pem
```

### 为多个接收者加密消息

此命令为一个文件对两个不同的接收者进行加密。任何一个接收者都可以用其对应的私钥解密该消息。

```sh 为多个接收者加密 icon=lucide:terminal
openssl cms -encrypt -in confidential.txt -out encrypted.pem \
  -recip recip1_cert.pem -recip recip2_cert.pem
```

### 解密消息

接收者使用其证书和私钥来解密消息。

```sh 解密消息 icon=lucide:terminal
openssl cms -decrypt -in encrypted.pem -out confidential.txt \
  -recip recip1_cert.pem -inkey recip1_key.pem
```

### 先签名后加密消息

要创建既签名又加密的消息，需要将操作串联起来。`-sign` 命令的输出通过管道传递给 `-encrypt` 命令的输入。

```sh 先签名后加密消息 icon=lucide:terminal
openssl cms -sign -in message.txt -signer signer.pem -text \
  | openssl cms -encrypt -recip recipient.pem -out signed_and_encrypted.pem
```

## 总结

`openssl cms` 命令行工具是用于管理 CMS 结构的多功能实用程序。其选项和操作与 OpenSSL 库中可用的函数直接对应。对于开发者而言，分析其源代码和行为是学习如何以编程方式实现这些功能的有效途径。

有关底层 API 的更多详细信息，请参阅以下部分：
- [主要函数](./api-main.md)
- [签名与验证](./guides-signing-verifying.md)
- [加密与解密](./guides-encrypting-decrypting.md)