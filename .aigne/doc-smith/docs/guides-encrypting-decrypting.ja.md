# 暗号化と復号

機密情報を安全に送信するには、堅牢な暗号化が必要であり、認可された受信者のみがコンテンツにアクセスできるようにする必要があります。このガイドでは、OpenSSL の CMS `EnvelopedData` コンテンツタイプの実装を使用してデータを暗号化および復号するための体系的でステップバイステップのワークフローを提供します。暗号化されたメッセージを処理する標準的なプロセスと、あまり一般的ではない分離データ用のワークフローについて学びます。

ここで概説する手順は、主に `EnvelopedData` コンテンツタイプに関わるものです。これは、暗号化されたコンテンツと 1 つ以上の受信者識別子をカプセル化します。各受信者エントリには、通常はその受信者の公開鍵を使用して個別に暗号化されたコンテンツ暗号化キーが含まれています。次の図は、この一般的な概念を示しています。

<!-- DIAGRAM_IMAGE_START:flowchart:4:3 -->
![Encryption & Decryption](./assets/diagram/guides-encrypting-decrypting-diagram-0.jpg)
<!-- DIAGRAM_IMAGE_END -->

基盤となる構造の詳細については、[コンテンツタイプ](./concepts-content-types.md)および[受信者情報タイプ](./concepts-recipient-info-types.md)のドキュメントを参照してください。

## 標準ワークフロー: 添付データ

最も一般的なユースケースは、暗号化されたコンテンツが CMS 構造内に含まれる単一の S/MIME メッセージを作成することです。以下のセクションでは、これらのメッセージを作成および復号するプロセスについて詳しく説明します。

### 暗号化プロセス

暗号化ワークフローは、`EnvelopedData` タイプの `CMS_ContentInfo` 構造を生成します。この構造には、暗号化されたデータと、各受信者がそれを復号するために必要な情報が含まれています。

この操作の主要な関数は `CMS_encrypt()` です。これは、対称コンテンツ暗号化キー (CEK) の生成、CEK によるデータの暗号化、各受信者の公開鍵を使用した CEK の暗号化、およびこれらのコンポーネントを最終的な構造に組み立てるというプロセス全体を調整します。

論理的な手順は次のとおりです。
1.  OpenSSL ライブラリを初期化します。
2.  各対象受信者の公開証明書を読み込みます。
3.  `STACK_OF(X509)` を作成し、各受信者の証明書をそれに追加します。
4.  `BIO` を使用して、暗号化する入力データを開きます。
5.  受信者スタック、入力 `BIO`、対称暗号 (例: `EVP_des_ede3_cbc()`)、および必要なフラグを指定して `CMS_encrypt()` を呼び出します。
6.  結果を書き込むための出力 `BIO` を開きます。
7.  `SMIME_write_CMS()` を使用して、完全な S/MIME メッセージを書き込みます。
8.  割り当てられたすべてのリソースをクリーンアップします。

次の例は、完全な暗号化操作を示しています。

```c cms_enc.c
/* Simple S/MIME encrypt example */
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
     * On OpenSSL 1.0.0 and later only:
     * for streaming set CMS_STREAM
     */
    /*
     * OpenSSL 1.0.0 以降のみ:
     * ストリーミングには CMS_STREAM を設定
     */
    int flags = CMS_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    /* 受信者の証明書を読み込む */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    /* 受信者 STACK を作成し、それに受信者証明書を追加する */
    recips = sk_X509_new_null();
    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /* rcert is now part of recips and will be freed with it */
    /* rcert は現在 recips の一部であり、recips と共に解放される */
    rcert = NULL;

    /* Open content being encrypted */
    /* 暗号化されるコンテンツを開く */
    in = BIO_new_file("encr.txt", "r");
    if (!in)
        goto err;

    /* Encrypt content */
    /* コンテンツを暗号化する */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
    if (!cms)
        goto err;

    out = BIO_new_file("smencr.txt", "w");
    if (!out)
        goto err;

    /* Write out S/MIME message */
    /* S/MIME メッセージを書き出す */
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

### 復号プロセス

復号は逆の操作です。受信者は、自身の秘密鍵を使用して、対応する `RecipientInfo` 構造からコンテンツ暗号化キー (CEK) を復号します。CEK が回復されると、それを使用してメッセージコンテンツを復号します。

`CMS_decrypt()` 関数がこのプロセスを処理します。この関数は、正しい `RecipientInfo` 構造を見つけて復号を実行するために、受信者の秘密鍵とそれに対応する証明書を必要とします。

論理的な手順は次のとおりです。
1.  OpenSSL ライブラリを初期化します。
2.  受信者の秘密鍵 (`EVP_PKEY`) と公開証明書 (`X509`) を読み込みます。
3.  `BIO` を使用して、暗号化された S/MIME メッセージを開きます。
4.  `SMIME_read_CMS()` を使用して、メッセージを `CMS_ContentInfo` 構造に解析します。
5.  復号された平文用の出力 `BIO` を開きます。
6.  `CMS_ContentInfo` 構造、受信者の秘密鍵、証明書、および出力 `BIO` を指定して `CMS_decrypt()` を呼び出します。
7.  割り当てられたすべてのリソースをクリーンアップします。

次の例は、完全な復号操作を示しています。

```c cms_dec.c
/* Simple S/MIME decryption example */
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

    /* Read in recipient certificate and private key */
    /* 受信者の証明書と秘密鍵を読み込む */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (BIO_reset(tbio) < 0)
        goto err;
    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!rcert || !rkey)
        goto err;

    /* Open S/MIME message to decrypt */
    /* 復号する S/MIME メッセージを開く */
    in = BIO_new_file("smencr.txt", "r");
    if (!in)
        goto err;

    /* Parse message */
    /* メッセージを解析する */
    cms = SMIME_read_CMS(in, NULL);
    if (!cms)
        goto err;

    out = BIO_new_file("decout.txt", "w");
    if (!out)
        goto err;

    /* Decrypt S/MIME message */
    /* S/MIME メッセージを復号する */
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

## 高度なワークフロー: 分離データ

一部のシナリオでは、暗号化されたコンテンツが CMS メタデータ構造とは別に処理される場合があります。これは分離データとして知られています。暗号化する際、`CMS_DETACHED` フラグを使用して、暗号化されたコンテンツを省略した `CMS_ContentInfo` 構造を作成します。このコンテンツは他の場所に保存する必要があります。これはまれなユースケースです。

### 分離データによる暗号化

`CMS_encrypt()` で `CMS_DETACHED` フラグを使用すると、関数は暗号化を実行しますが、結果の暗号文を別の `BIO` に書き込みます。返される `CMS_ContentInfo` 構造には、必要なすべての受信者情報が含まれますが、データ自体は含まれません。

このプロセスは標準の暗号化と似ていますが、以下の重要な違いがあります。
-   `CMS_DETACHED` フラグを含める必要があります。
-   暗号化された出力をキャプチャするために、別の `BIO` (例では `dout`) が必要です。
-   ストリーミング暗号化操作を完了するために `CMS_final()` 関数が使用されます。
-   結果として得られる `CMS_ContentInfo` 構造 (コンテンツなし) は 1 つのファイルに書き込まれ、暗号化されたデータは別のファイルに書き込まれます。

```c cms_denc.c
/* S/MIME detached data encrypt example */
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

    /* Read in recipient certificate */
    /* 受信者の証明書を読み込む */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (!rcert)
        goto err;

    /* Create recipient STACK */
    /* 受信者 STACK を作成する */
    recips = sk_X509_new_null();
    if (!recips || !sk_X509_push(recips, rcert))
        goto err;
    rcert = NULL;

    /* Open content being encrypted and detached output */
    /* 暗号化されるコンテンツと分離された出力を開く */
    in = BIO_new_file("encr.txt", "r");
    dout = BIO_new_file("smencr.out", "wb");
    if (in == NULL || dout == NULL)
        goto err;

    /* Encrypt content */
    /* コンテンツを暗号化する */
    cms = CMS_encrypt(recips, in, EVP_des_ede3_cbc(), flags);
    if (!cms)
        goto err;

    out = BIO_new_file("smencr.pem", "w");
    if (!out)
        goto err;

    /* Finalize the streaming encryption, writing ciphertext to dout */
    /* ストリーミング暗号化を完了し、暗号文を dout に書き込む */
    if (!CMS_final(cms, in, dout, flags))
        goto err;

    /* Write out CMS structure without content */
    /* コンテンツなしで CMS 構造を書き出す */
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

### 分離データによる復号

分離データを持つメッセージを復号するには、`CMS_ContentInfo` 構造と、暗号化されたコンテンツを含む別のファイルの両方を提供する必要があります。`CMS_decrypt()` 関数は、この目的のために追加の `BIO` 引数 (`dcont`) を受け入れます。

標準的な復号プロセスとの主な違いは次のとおりです。
-   `CMS_ContentInfo` 構造は、そのファイル (例: `.pem` ファイル) から読み込まれます。
-   分離された暗号化コンテンツ用に別の `BIO` が開かれます。
-   このコンテンツ `BIO` は、`CMS_decrypt()` の `dcont` 引数として渡されます。

```c cms_ddec.c
/* S/MIME detached data decrypt example */
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

    /* Read in recipient certificate and private key */
    /* 受信者の証明書と秘密鍵を読み込む */
    tbio = BIO_new_file("signer.pem", "r");
    if (!tbio)
        goto err;
    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (BIO_reset(tbio) < 0)
        goto err;
    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (!rcert || !rkey)
        goto err;

    /* Open PEM file containing enveloped data structure */
    /* EnvelopedData 構造を含む PEM ファイルを開く */
    in = BIO_new_file("smencr.pem", "r");
    if (!in)
        goto err;

    /* Parse PEM content */
    /* PEM コンテンツを解析する */
    cms = PEM_read_bio_CMS(in, NULL, 0, NULL);
    if (!cms)
        goto err;

    /* Open file containing detached content */
    /* 分離されたコンテンツを含むファイルを開く */
    dcont = BIO_new_file("smencr.out", "rb");
    if (dcont == NULL)
        goto err;

    out = BIO_new_file("encrout.txt", "w");
    if (!out)
        goto err;

    /* Decrypt S/MIME message using detached content */
    /* 分離されたコンテンツを使用して S/MIME メッセージを復号する */
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

## まとめ

このガイドでは、OpenSSL CMS API を使用した暗号化および復号ワークフローの完全で体系的な概要を提供しました。標準的な添付データと、あまり一般的ではない分離データの両方のシナリオを処理する方法を見てきました。これらの構造化された例に従うことで、アプリケーションで安全なデータ交換を確実に実装できます。

使用されている関数の詳細については、[API リファレンス](./api.md)セクションの関連エントリを参照してください。関連トピックに関する追加のガイドも利用可能です。

<x-cards data-columns="2">
  <x-card data-title="署名と検証" data-icon="lucide:pen-square" data-href="/guides/signing-verifying">
    CMS メッセージに対するデジタル署名の作成と検証方法を学びます。
  </x-card>
  <x-card data-title="API リファレンス" data-icon="lucide:book-text" data-href="/api">
    高度な操作のために、完全な OpenSSL CMS API を探索します。
  </x-card>
</x-cards>