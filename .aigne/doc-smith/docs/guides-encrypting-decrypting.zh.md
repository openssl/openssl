# 加密与解密

安全传输敏感信息需要强大的加密技术，以确保只有授权的接收者才能访问内容。本指南提供了使用 OpenSSL 实现的 CMS `EnvelopedData` 内容类型进行数据加密和解密的系统化、分步工作流程。您将学习处理加密消息的标准流程以及处理分离式数据的不太常见的工作流程。

此处概述的流程主要涉及 `EnvelopedData` 内容类型，该类型封装了加密内容和一个或多个接收者标识符。每个接收者条目都包含一个内容加密密钥，该密钥已为该特定接收者单独加密，通常使用其公钥。下图说明了这一通用概念。

<!-- DIAGRAM_IMAGE_START:flowchart:4:3 -->
![加密与解密](./assets/diagram/guides-encrypting-decrypting-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

有关底层结构的更详细解释，请参阅[内容类型](./concepts-content-types.md)和[接收者信息类型](./concepts-recipient-info-types.md)文档。

## 标准工作流程：附加数据

最常见的用例是创建一个 S/MIME 消息，其中加密内容包含在 CMS 结构中。以下各节详细介绍了创建和解密这些消息的过程。

### 加密过程

加密工作流程会生成一个 `EnvelopedData` 类型的 `CMS_ContentInfo` 结构。该结构包含加密数据以及每个接收者解密所需的信息。

此操作的主要函数是 `CMS_encrypt()`。它负责协调整个过程：生成对称的内容加密密钥（CEK）、使用 CEK 加密数据、使用每个接收者的公钥为他们分别加密 CEK，并将这些组件组装成最终的结构。

逻辑步骤如下：
1.  初始化 OpenSSL 库。
2.  加载每个目标接收者的公钥证书。
3.  创建一个 `STACK_OF(X509)` 并将每个接收者的证书添加到其中。
4.  使用 `BIO` 打开要加密的输入数据。
5.  调用 `CMS_encrypt()`，提供接收者栈、输入 `BIO`、对称密码（例如 `EVP_des_ede3_cbc()`）以及任何必要的标志。
6.  打开一个输出 `BIO` 以写入结果。
7.  使用 `SMIME_write_CMS()` 写入完整的 S/MIME 消息。
8.  清理所有已分配的资源。

以下示例演示了一个完整的加密操作。

```c cms_enc.c
/* 简单的 S/MIME 加密示例 */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    /*
     * 仅在 OpenSSL 1.0.0 及更高版本中：
     * 对于流式处理，设置 CMS_STREAM
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* 读入接收者证书 */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!rcert)
        goto err;

    /* 创建接收者 STACK 并将接收者证书添加进去 */
    recips = sk_X509_new_null();
    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /* rcert 现在是 recips 的一部分，将随其一起释放 */
    rcert = NULL;

    /* 打开要加密的内容 */
    in = BIO_new_file("encr.txt", "r");
    if (!in)
        goto err;

    /* 加密内容 */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
    if (!cms)
        goto err;

    out = BIO_new_file("smencr.txt", "w");
    if (!out)
        goto err;

    /* 写出 S/MIME 消息 */
    if (!SMIME_write_CMS(out, cms, in, flags))
        goto err;

    printf("Encryption Successful\n");
    ret = EXIT_SUCCESS;

err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    OSSL_STACK_OF_X509_free(recips);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
```

### 解密过程

解密是反向操作。接收者使用其私钥从其对应的 `RecipientInfo` 结构中解密内容加密密钥（CEK）。一旦恢复了 CEK，就用它来解密消息内容。

`CMS_decrypt()` 函数处理此过程。它需要接收者的私钥及其匹配的证书来定位正确的 `RecipientInfo` 结构并执行解密。

逻辑步骤如下：
1.  初始化 OpenSSL 库。
2.  加载接收者的私钥（`EVP_PKEY`）和公钥证书（`X509`）。
3.  使用 `BIO` 打开加密的 S/MIME 消息。
4.  使用 `SMIME_read_CMS()` 将消息解析为 `CMS_ContentInfo` 结构。
5.  为解密后的明文打开一个输出 `BIO`。
6.  调用 `CMS_decrypt()`，提供 `CMS_ContentInfo` 结构、接收者的私钥、证书和输出 `BIO`。
7.  清理所有已分配的资源。

以下示例演示了一个完整的解密操作。

```c cms_dec.c
/* 简单的 S/MIME 解密示例 */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* 读入接收者证书和私钥 */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (BIO_reset(tbio) < 0)
        goto err;
    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!rcert || !rkey)
        goto err;

    /* 打开要解密的 S/MIME 消息 */
    in = BIO_new_file("smencr.txt", "r");
    if (!in)
        goto err;

    /* 解析消息 */
    cms = SMIME_read_CMS(in, NULL);
    if (!cms)
        goto err;

    out = BIO_new_file("decout.txt", "w");
    if (!out)
        goto err;

    /* 解密 S/MIME 消息 */
    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0))
        goto err;

    printf("Decryption Successful\n");
    ret = EXIT_SUCCESS;

err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
```

## 高级工作流程：分离式数据

在某些情况下，加密内容可能与 CMS 元数据结构分开处理。这称为分离式数据。加密时，使用 `CMS_DETACHED` 标志创建一个省略了加密内容的 `CMS_ContentInfo` 结构，该加密内容必须存储在其他地方。这是一个不常见的用例。

### 使用分离式数据进行加密

当 `CMS_DETACHED` 标志与 `CMS_encrypt()` 一起使用时，该函数仍然执行加密，但会将生成的密文写入一个单独的 `BIO`。返回的 `CMS_ContentInfo` 结构包含所有必要的接收者信息，但不包含数据本身。

该过程与标准加密类似，但有以下关键区别：
- 必须包含 `CMS_DETACHED` 标志。
- 需要一个单独的 `BIO`（示例中的 `dout`）来捕获加密输出。
- 使用 `CMS_final()` 函数来完成流式加密操作。
- 生成的 `CMS_ContentInfo` 结构（不含内容）被写入一个文件，而加密数据被写入另一个文件。

```c cms_denc.c
/* S/MIME 分离式数据加密示例 */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *dout = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    int flags = CMS_STREAM | CMS_DETACHED;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* 读入接收者证书 */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!rcert)
        goto err;

    /* 创建接收者 STACK */
    recips = sk_X509_new_null();
    if (!recips || !sk_X509_push(recips, rcert))
        goto err;
    rcert = NULL;

    /* 打开要加密的内容和分离式输出 */
    in = BIO_new_file("encr.txt", "r");
    dout = BIO_new_file("smencr.out", "wb");
    if (in == NULL || dout == NULL)
        goto err;

    /* 加密内容 */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
    if (!cms)
        goto err;

    out = BIO_new_file("smencr.pem", "w");
    if (!out)
        goto err;

    /* 完成流式加密，将密文写入 dout */
    if (!CMS_final(cms, in, dout, flags))
        goto err;

    /* 写出不含内容的 CMS 结构 */
    if (!PEM_write_bio_CMS(out, cms))
        goto err;

    ret = EXIT_SUCCESS;
err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    OSSL_STACK_OF_X509_free(recips);
    BIO_free(in);
    BIO_free(out);
    BIO_free(dout);
    BIO_free(tbio);
    return ret;
}
```

### 使用分离式数据进行解密

要解密带有分离式数据的消息，您必须同时提供 `CMS_ContentInfo` 结构和包含加密内容的单独文件。为此，`CMS_decrypt()` 函数接受一个额外的 `BIO` 参数 (`dcont`)。

与标准解密过程的主要区别在于：
- 从其文件（例如 `.pem` 文件）中读取 `CMS_ContentInfo` 结构。
- 为分离的加密内容打开一个单独的 `BIO`。
- 此内容 `BIO`作为 `dcont` 参数传递给 `CMS_decrypt()`。

```c cms_ddec.c
/* S/MIME 分离式数据解密示例 */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL, *dcont = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = EXIT_FAILURE;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* 读入接收者证书和私钥 */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (BIO_reset(tbio) < 0)
        goto err;
    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!rcert || !rkey)
        goto err;

    /* 打开包含 EnvelopedData 结构的 PEM 文件 */
    in = BIO_new_file("smencr.pem", "r");
    if (!in)
        goto err;

    /* 解析 PEM 内容 */
    cms = PEM_read_bio_CMS(in, NULL, 0, NULL);
    if (!cms)
        goto err;

    /* 打开包含分离式内容的文件 */
    dcont = BIO_new_file("smencr.out", "rb");
    if (dcont == NULL)
        goto err;

    out = BIO_new_file("encrout.txt", "w");
    if (!out)
        goto err;

    /* 使用分离式内容解密 S/MIME 消息 */
    if (!CMS_decrypt(cms, rkey, rcert, dcont, out, 0))
        goto err;

    ret = EXIT_SUCCESS;

err:
    if (ret != EXIT_SUCCESS) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    BIO_free(dcont);
    return ret;
}
```

## 总结

本指南全面、系统地概述了使用 OpenSSL CMS API 的加密和解密工作流程。您已经了解了如何处理标准的附加数据和不太常见的分离式数据场景。通过遵循这些结构化的示例，您可以在应用程序中可靠地实现安全的数据交换。

有关所用函数的更多详细信息，请查阅 [API 参考](./api.md) 部分中的相关条目。还提供了有关相关主题的其他指南：

<x-cards data-columns="2">
  <x-card data-title="签名与验证" data-icon="lucide:pen-square" data-href="/guides/signing-verifying">
    了解如何创建和验证 CMS 消息的数字签名。
  </x-card>
  <x-card data-title="API 参考" data-icon="lucide:book-text" data-href="/api">
    探索完整的 OpenSSL CMS API 以进行高级操作。
  </x-card>
</x-cards>